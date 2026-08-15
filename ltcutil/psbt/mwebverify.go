package psbt

// MWEB verification helpers: LIP-0007 requires signatures, range proofs, the
// kernel balance equation, and peg-in script commitments to be verified
// before a packet is extracted.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	ec "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/ltcutil"
	"github.com/ltcsuite/ltcd/ltcutil/mweb"
	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"lukechampine.com/blake3"
)

// validScalar reports whether the digest is a canonical non-zero scalar.
func validScalar(digest []byte) bool {
	var s ec.ModNScalar
	overflow := s.SetByteSlice(digest)
	return !overflow && !s.IsZero()
}

// scalarInRange reports whether the bytes are below the group order; zero is
// allowed (a blinding-factor sum can legitimately be zero).
func scalarInRange(b []byte) bool {
	var s ec.ModNScalar
	return !s.SetByteSlice(b)
}

// hashToScalar implements the MWEB hash-to-scalar rule: use the 32-byte
// digest directly when it is a valid non-zero scalar, otherwise rehash
// "MWEB hash-to-scalar" || digest || LE32 counter until one is found.
func hashToScalar(digest []byte) *mw.SecretKey {
	if validScalar(digest) {
		return (*mw.SecretKey)(digest)
	}

	for counter := uint32(0); ; counter++ {
		h := blake3.New(32, nil)
		h.Write([]byte("MWEB hash-to-scalar"))
		h.Write(digest)
		_ = binary.Write(h, binary.LittleEndian, counter)

		if candidate := h.Sum(nil); validScalar(candidate) {
			return (*mw.SecretKey)(candidate)
		}
	}
}

// keyAggScalar returns HS(a || b), the aggregation scalar for the stealth
// key constructions of inputs and kernels.
func keyAggScalar(a, b *mw.PublicKey) *mw.SecretKey {
	h := blake3.New(32, nil)
	h.Write(a[:])
	h.Write(b[:])
	return hashToScalar(h.Sum(nil))
}

// mwebVerify verifies an MWEB Schnorr signature, mirroring mw.Sign: the
// nonce point's X is sig[0:32] with a quadratic-residue Y, and the challenge
// is SHA256(R.x || pubkey || message).
func mwebVerify(pubKey *mw.PublicKey, message []byte, sig *mw.Signature) bool {
	var s ec.ModNScalar
	if overflow := s.SetByteSlice(sig[32:]); overflow {
		return false
	}

	h := sha256.New()
	h.Write(sig[:32])
	h.Write(pubKey[:])
	h.Write(message)
	// An over-order challenge hash reduces silently, as in libsecp's
	// verifier.
	var e ec.ModNScalar
	e.SetByteSlice(h.Sum(nil))

	parsed, err := ec.ParsePubKey(pubKey[:])
	if err != nil {
		return false
	}

	// R = s*G - e*P
	var p, sG, eP, r ec.JacobianPoint
	parsed.AsJacobian(&p)
	ec.ScalarBaseMultNonConst(&s, &sG)
	e.Negate()
	ec.ScalarMultNonConst(&e, &p, &eP)
	ec.AddNonConst(&sG, &eP, &r)
	if (r.X.IsZero() && r.Y.IsZero()) || r.Z.IsZero() {
		return false
	}
	r.ToAffine()

	var rx ec.FieldVal
	if overflow := rx.SetByteSlice(sig[:32]); overflow {
		return false
	}
	if !rx.Equals(&r.X) {
		return false
	}

	// The signer chose the nonce whose Y is a quadratic residue.
	var sqrt ec.FieldVal
	return sqrt.SquareRootVal(&r.Y)
}

// mwebInputMessageHash is the input signature preimage shared by signing and
// verification: H(features || output_id [|| extra_data]).
func mwebInputMessageHash(features wire.MwebInputFeatureBit,
	outputId *chainhash.Hash, extraData []byte) []byte {

	h := blake3.New(32, nil)
	_ = binary.Write(h, binary.LittleEndian, features)
	h.Write(outputId[:])
	if features&wire.MwebInputExtraDataFeatureBit > 0 {
		_ = wire.WriteVarBytes(h, 0, extraData)
	}
	return h.Sum(nil)
}

// mwebInputVerifyKey returns the input signature verification key: the spent
// output's pubkey Ko, or Ko*HS(Ki||Ko) + Ki when the stealth bit is set.
func mwebInputVerifyKey(pi *PInput) (*mw.PublicKey, error) {
	if *pi.MwebFeatures&wire.MwebInputStealthKeyFeatureBit == 0 {
		return pi.MwebOutputPubkey, nil
	}
	if pi.MwebInputPubkey == nil {
		return nil, errors.New("mweb input missing input pubkey")
	}

	aggScalar := keyAggScalar(pi.MwebInputPubkey, pi.MwebOutputPubkey)
	return pi.MwebOutputPubkey.Mul(aggScalar).Add(pi.MwebInputPubkey), nil
}

// mwebKernelVerifyKey returns the kernel signature verification key: the
// excess as a pubkey E, or E*HS(E||E') + E' when the stealth bit is set.
func mwebKernelVerifyKey(pk *PKernel) (*mw.PublicKey, error) {
	excess := pk.ExcessCommitment.PubKey()
	if *pk.Features&wire.MwebKernelStealthExcessFeatureBit == 0 {
		return excess, nil
	}
	if pk.StealthExcess == nil {
		return nil, errors.New("kernel missing stealth excess")
	}

	return excess.Mul(keyAggScalar(excess, pk.StealthExcess)).
		Add(pk.StealthExcess), nil
}

// peginScript builds the canonical main-chain side of a peg-in: a version-9
// witness program over the kernel ID.
func peginScript(kernelId *chainhash.Hash) []byte {
	return mweb.NewPegin(0, kernelId).PkScript
}

// isPeginScript reports whether script is a peg-in output script.
func isPeginScript(script []byte) bool {
	return txscript.GetScriptClass(script) == txscript.WitnessMwebPeginTy
}

// PeginPlaceholderScript returns the peg-in output script a Creator sets
// before the funding kernel is signed: a peg-in commitment to the all-zero
// hash, rewritten by the MWEB signer.
func PeginPlaceholderScript() []byte {
	return peginScript(&chainhash.Hash{})
}

// isPeginPlaceholder reports whether script is a peg-in script committing to
// the all-zero hash.
func isPeginPlaceholder(script []byte) bool {
	return isPeginScript(script) &&
		bytes.Equal(script, PeginPlaceholderScript())
}

// peginPairs collects the packet's peg-in outputs (classified purely by
// script shape, per LIP-0007 peg-in classification) and peg-in kernels, in
// packet order.
func peginPairs(p *Packet) ([]*POutput, []*PKernel) {
	var outputs []*POutput
	for i := range p.Outputs {
		if isPeginScript(p.Outputs[i].PKScript) {
			outputs = append(outputs, &p.Outputs[i])
		}
	}
	var kernels []*PKernel
	for i := range p.Kernels {
		if p.Kernels[i].PeginAmount != nil {
			kernels = append(kernels, &p.Kernels[i])
		}
	}
	return outputs, kernels
}

// validatePeginOutputs checks the peg-in associations LIP-0007 mandates over
// every pair that can be formed. Count equality is enforced when requireFinal
// or once any peg-in script is finalized; a partial packet under construction
// may still be missing one side.
func validatePeginOutputs(p *Packet, requireFinal bool) error {
	outputs, kernels := peginPairs(p)

	hasFinal := false
	for _, po := range outputs {
		if !isPeginPlaceholder(po.PKScript) {
			hasFinal = true
		}
	}
	if (requireFinal || hasFinal) && len(outputs) != len(kernels) {
		return errors.New("peg-in output and kernel counts differ")
	}

	pairs := len(outputs)
	if len(kernels) < pairs {
		pairs = len(kernels)
	}
	for i := 0; i < pairs; i++ {
		po, pk := outputs[i], kernels[i]
		if po.Amount != *pk.PeginAmount {
			return errors.New("peg-in output amount does not match kernel")
		}

		if isPeginPlaceholder(po.PKScript) {
			if requireFinal {
				return errors.New("peg-in script is still a placeholder")
			}
			continue
		}

		// A non-placeholder script must commit to the kernel's ID.
		if !pk.isFinalized() {
			return errors.New("peg-in script set before kernel was signed")
		}
		kernel, err := extractKernel(pk)
		if err != nil {
			return err
		}
		if !bytes.Equal(po.PKScript, peginScript(kernel.Hash())) {
			return errors.New("peg-in script does not commit to its kernel")
		}
	}

	return nil
}

// hasCanonicalSigData reports whether the input carries any canonical
// signature material, which commits to the peg-in scripts.
func hasCanonicalSigData(pi *PInput) bool {
	return len(pi.PartialSigs) > 0 || pi.FinalScriptSig != nil ||
		pi.FinalScriptWitness != nil || pi.TaprootKeySpendSig != nil ||
		len(pi.TaprootScriptSpendSig) > 0
}

// mwebComponentsFinal reports whether every MWEB component is finalized and
// both offsets are set, i.e. the monolithic MWEB signing step has run.
func mwebComponentsFinal(p *Packet) bool {
	// A peg-in script must commit to a signed kernel (LIP-0007 peg-in kernel
	// commitment) even when the packet carries no MWEB component maps at all.
	if validatePeginOutputs(p, true) != nil {
		return false
	}
	if !p.HasMwebComponents() {
		return true
	}
	// MWEB components require at least one kernel; without it the packet
	// can never complete and its offsets are not settled.
	if len(p.Kernels) == 0 {
		return false
	}
	if p.MwebTxOffset == nil || p.MwebStealthOffset == nil {
		return false
	}
	for i := range p.Inputs {
		if p.Inputs[i].isMWEB() && !p.Inputs[i].isFinalized() {
			return false
		}
	}
	for i := range p.Outputs {
		if p.Outputs[i].isMWEB() && !p.Outputs[i].isFinalized() {
			return false
		}
	}
	for i := range p.Kernels {
		if !p.Kernels[i].isFinalized() {
			return false
		}
	}
	return true
}

// addAmount accumulates an amount, rejecting values or running totals
// outside the money range.
func addAmount(sum *uint64, amount int64) error {
	if amount < 0 || amount > ltcutil.MaxSatoshi {
		return errors.New("mweb amount outside money range")
	}
	next, err := addChecked(*sum, uint64(amount))
	if err != nil {
		return err
	}
	*sum = next
	return nil
}

// addChecked returns a + b, rejecting a total outside the money range. Each
// combined category (input+pegin, output+pegout+fee) is money-range-checked,
// not just the per-item amounts.
func addChecked(a, b uint64) (uint64, error) {
	sum := a + b
	if sum < a || sum > uint64(ltcutil.MaxSatoshi) {
		return 0, errors.New("mweb amount sum outside money range")
	}
	return sum, nil
}

// kernelTotals sums the value terms carried by the packet's kernels.
func kernelTotals(p *Packet) (fees, pegins, pegouts uint64, err error) {
	for i := range p.Kernels {
		pk := &p.Kernels[i]
		if pk.Fee != nil {
			if err := addAmount(&fees, int64(*pk.Fee)); err != nil {
				return 0, 0, 0, err
			}
		}
		if pk.PeginAmount != nil {
			if err := addAmount(&pegins, int64(*pk.PeginAmount)); err != nil {
				return 0, 0, 0, err
			}
		}
		for _, pegout := range pk.PegOuts {
			if err := addAmount(&pegouts, pegout.Value); err != nil {
				return 0, 0, 0, err
			}
		}
	}
	return fees, pegins, pegouts, nil
}

// checkMwebBalance verifies the explicit amounts balance: sum(mweb inputs) +
// sum(pegins) must equal sum(mweb outputs) + sum(pegouts) + sum(fees). The
// explicit input amount is required for signing but is optional metadata at
// extraction (LIP-0007); when requireAmounts is false a missing amount skips
// the cross-check, leaving the commitment balance authoritative — the
// strictness-flag shape of validatePeginOutputs.
func checkMwebBalance(p *Packet, requireAmounts bool) error {
	var inputs, outputs uint64
	for i := range p.Inputs {
		pi := &p.Inputs[i]
		if !pi.isMWEB() {
			continue
		}
		if pi.MwebAmount == nil {
			if requireAmounts {
				return errors.New("mweb input amount missing")
			}
			return nil
		}
		if err := addAmount(&inputs, int64(*pi.MwebAmount)); err != nil {
			return err
		}
	}
	for i := range p.Outputs {
		if p.Outputs[i].isMWEB() {
			if err := addAmount(&outputs, int64(p.Outputs[i].Amount)); err != nil {
				return err
			}
		}
	}
	fees, pegins, pegouts, err := kernelTotals(p)
	if err != nil {
		return err
	}

	lhs, err := addChecked(inputs, pegins)
	if err != nil {
		return err
	}
	rhs, err := addChecked(outputs, pegouts)
	if err != nil {
		return err
	}
	rhs, err = addChecked(rhs, fees)
	if err != nil {
		return err
	}
	if lhs != rhs {
		return ErrMwebAmountsUnbalanced
	}
	return nil
}

// addPointTo accumulates a parsed 33-byte point into sum.
func addPointTo(sum *ec.JacobianPoint, serialized []byte) error {
	parsed, err := ec.ParsePubKey(serialized)
	if err != nil {
		return err
	}
	var point ec.JacobianPoint
	parsed.AsJacobian(&point)
	ec.AddNonConst(sum, &point, sum)
	return nil
}

// addValueTo accumulates value*H into sum, encoding the value exactly as mw
// does (a commitment to value with a zero blind is value*H).
func addValueTo(sum *ec.JacobianPoint, value uint64) error {
	if value == 0 {
		return nil
	}
	commit := mw.NewCommitment(&mw.BlindingFactor{}, value)
	return addPointTo(sum, commit.PubKey()[:])
}

// verifyMwebBalance checks the kernel sums equation over the packet fields:
// sum(output commitments) + (fees + pegouts)*H ==
// sum(input commitments) + pegins*H + sum(kernel excesses) + offset*G.
func verifyMwebBalance(p *Packet) error {
	var lhs, rhs ec.JacobianPoint

	for i := range p.Kernels {
		if err := addPointTo(&rhs, p.Kernels[i].ExcessCommitment.PubKey()[:]); err != nil {
			return err
		}
	}
	for i := range p.Outputs {
		if p.Outputs[i].isMWEB() {
			if err := addPointTo(&lhs, p.Outputs[i].OutputCommit.PubKey()[:]); err != nil {
				return err
			}
		}
	}
	for i := range p.Inputs {
		if p.Inputs[i].isMWEB() {
			if err := addPointTo(&rhs, p.Inputs[i].MwebCommit.PubKey()[:]); err != nil {
				return err
			}
		}
	}

	fees, pegins, pegouts, err := kernelTotals(p)
	if err != nil {
		return err
	}
	feePegout, err := addChecked(fees, pegouts)
	if err != nil {
		return err
	}
	if err := addValueTo(&lhs, feePegout); err != nil {
		return err
	}
	if err := addValueTo(&rhs, pegins); err != nil {
		return err
	}
	// A zero offset contributes the identity; mw cannot represent it.
	if *p.MwebTxOffset != (mw.BlindingFactor{}) {
		if !validScalar(p.MwebTxOffset[:]) {
			return errors.New("invalid mweb kernel offset")
		}
		if err := addPointTo(&rhs, (*mw.SecretKey)(p.MwebTxOffset).PubKey()[:]); err != nil {
			return err
		}
	}

	// lhs - rhs must be the point at infinity.
	if !pointsEqual(&lhs, &rhs) {
		return errors.New("mweb kernel sums do not balance")
	}
	return nil
}

// pointsEqual reports whether two Jacobian sums are the same point.
func pointsEqual(lhs, rhs *ec.JacobianPoint) bool {
	rhs.Y.Normalize().Negate(1).Normalize()
	var diff ec.JacobianPoint
	ec.AddNonConst(lhs, rhs, &diff)
	return diff.X.IsZero() && diff.Y.IsZero()
}

// verifyStealthBalance checks the consensus stealth sums equation:
// sum(K_s) + sum(K_i) == sum(E') + offset*G + sum(K_o).
func verifyStealthBalance(p *Packet) error {
	var lhs, rhs ec.JacobianPoint

	for i := range p.Outputs {
		if p.Outputs[i].isMWEB() {
			if err := addPointTo(&lhs, p.Outputs[i].SenderPubkey[:]); err != nil {
				return err
			}
		}
	}
	for i := range p.Inputs {
		pi := &p.Inputs[i]
		if !pi.isMWEB() {
			continue
		}
		// The input pubkey enters the stealth sum only when the stealth-key
		// feature bit is set (that bit gates its serialization, verify key,
		// and signed message); isFinalized enforces the presence⇔bit agreement.
		if *pi.MwebFeatures&wire.MwebInputStealthKeyFeatureBit > 0 {
			if err := addPointTo(&lhs, pi.MwebInputPubkey[:]); err != nil {
				return err
			}
		}
		if err := addPointTo(&rhs, pi.MwebOutputPubkey[:]); err != nil {
			return err
		}
	}
	for i := range p.Kernels {
		if p.Kernels[i].StealthExcess != nil {
			if err := addPointTo(&rhs, p.Kernels[i].StealthExcess[:]); err != nil {
				return err
			}
		}
	}
	if *p.MwebStealthOffset != (mw.BlindingFactor{}) {
		if !validScalar(p.MwebStealthOffset[:]) {
			return errors.New("invalid mweb stealth offset")
		}
		if err := addPointTo(&rhs, (*mw.SecretKey)(p.MwebStealthOffset).PubKey()[:]); err != nil {
			return err
		}
	}

	if !pointsEqual(&lhs, &rhs) {
		return errors.New("mweb stealth sums do not balance")
	}
	return nil
}

// verifyMwebComponents runs the pre-extraction checks LIP-0007 mandates for
// the MWEB side: component signatures, range proofs, the balance equation,
// and the peg-in script commitments. It returns the extracted kernels so the
// extractor does not rebuild them.
func verifyMwebComponents(p *Packet) ([]*wire.MwebKernel, error) {
	// Duplicate detection is per category: spent-input IDs, output IDs, and
	// kernel IDs are checked independently, so an input that spends an output
	// created in the same body is permitted and must not collide across
	// categories.
	newSeen := func() func(*chainhash.Hash) bool {
		ids := make(map[chainhash.Hash]struct{})
		return func(id *chainhash.Hash) bool {
			if _, dup := ids[*id]; dup {
				return true
			}
			ids[*id] = struct{}{}
			return false
		}
	}
	seenInput, seenOutput, seenKernel := newSeen(), newSeen(), newSeen()

	var weight, inputCount int
	for i := range p.Inputs {
		pi := &p.Inputs[i]
		if !pi.isMWEB() {
			continue
		}
		key, err := mwebInputVerifyKey(pi)
		if err != nil {
			return nil, err
		}
		message := mwebInputMessageHash(
			*pi.MwebFeatures, pi.MwebOutputId, pi.MwebExtraData,
		)
		if !mwebVerify(key, message, pi.MwebInputSig) {
			return nil, errors.New("invalid mweb input signature")
		}
		if seenInput(pi.MwebOutputId) {
			return nil, errors.New("duplicate mweb input spend")
		}
		inputCount++
		weight += extraBytesWeight(len(pi.MwebExtraData))
	}

	for i := range p.Outputs {
		po := &p.Outputs[i]
		if !po.isMWEB() {
			continue
		}

		// Reuse the extraction mapping so verification commits to the
		// exact output the extractor will emit.
		out, err := extractMwebOutput(po)
		if err != nil {
			return nil, err
		}

		h := blake3.New(32, nil)
		h.Write(out.Commitment[:])
		h.Write(out.SenderPubKey[:])
		h.Write(out.ReceiverPubKey[:])
		h.Write(out.Message.Hash()[:])
		h.Write(out.RangeProofHash[:])
		if !mwebVerify(&out.SenderPubKey, h.Sum(nil), &out.Signature) {
			return nil, errors.New("invalid mweb output signature")
		}

		var messageBuf bytes.Buffer
		if err := out.Message.Serialize(&messageBuf); err != nil {
			return nil, err
		}
		if !out.RangeProof.Verify(out.Commitment, messageBuf.Bytes()) {
			return nil, errors.New("invalid mweb output range proof")
		}
		if seenOutput(out.Hash()) {
			return nil, errors.New("duplicate mweb output")
		}
		weight += outputWeight(po)
	}

	kernels := make([]*wire.MwebKernel, len(p.Kernels))
	for i := range p.Kernels {
		pk := &p.Kernels[i]
		key, err := mwebKernelVerifyKey(pk)
		if err != nil {
			return nil, err
		}
		kernel, err := extractKernel(pk)
		if err != nil {
			return nil, err
		}
		if !mwebVerify(key, kernel.MessageHash()[:], pk.Signature) {
			return nil, errors.New("invalid mweb kernel signature")
		}
		if seenKernel(kernel.Hash()) {
			return nil, errors.New("duplicate mweb kernel")
		}
		weight += kernelWeight(pk)
		kernels[i] = kernel
	}

	// The MWEB consensus body limits.
	if err := checkMwebBodyLimits(inputCount, weight); err != nil {
		return nil, err
	}

	if err := verifyMwebBalance(p); err != nil {
		return nil, err
	}
	if err := verifyStealthBalance(p); err != nil {
		return nil, err
	}
	// Cross-check the explicit amounts only when present; the commitment
	// balance verified above is authoritative.
	if err := checkMwebBalance(p, false); err != nil {
		return nil, err
	}

	if err := validatePeginOutputs(p, true); err != nil {
		return nil, err
	}
	return kernels, nil
}

// MWEB consensus weight rules.
const (
	mwebBytesPerWeight  = 42
	maxMwebInputs       = 50000
	maxMwebBlockWeight  = 200000
	baseKernelWeight    = 2
	stealthKernelWeight = 3
	baseOutputWeight    = 17
	stdOutputWeight     = 18
)

// checkMwebBodyLimits enforces the MWEB consensus body bounds: at most
// maxMwebInputs MWEB inputs and maxMwebBlockWeight total weight.
func checkMwebBodyLimits(inputCount, weight int) error {
	if inputCount > maxMwebInputs || weight > maxMwebBlockWeight {
		return errors.New("mweb body exceeds consensus limits")
	}
	return nil
}

func extraBytesWeight(n int) int {
	return (n + mwebBytesPerWeight - 1) / mwebBytesPerWeight
}

func outputWeight(po *POutput) int {
	weight := baseOutputWeight
	if *po.MwebFeatures&wire.MwebOutputMessageStandardFieldsFeatureBit > 0 {
		weight = stdOutputWeight
	}
	return weight + extraBytesWeight(len(po.MwebExtraData))
}

func kernelWeight(pk *PKernel) int {
	weight := baseKernelWeight
	if *pk.Features&wire.MwebKernelStealthExcessFeatureBit > 0 {
		weight = stealthKernelWeight
	}
	for _, pegout := range pk.PegOuts {
		weight += extraBytesWeight(len(pegout.PkScript))
	}
	return weight + extraBytesWeight(len(pk.ExtraData))
}

// effectiveLockTime determines the transaction lock time per BIP-0370 and
// LIP-0007 locktime resolution: an input carrying only one lock type vetoes
// the other; the surviving maximum wins with height preferred; a zero result
// falls back to the packet's fallback lock time.
func effectiveLockTime(p *Packet) (uint32, error) {
	heightOK, timeOK := true, true
	var maxHeight, maxTime uint32

	for i := range p.Inputs {
		pi := &p.Inputs[i]
		height, time := pi.RequiredHeightLockTime, pi.RequiredTimeLockTime
		if time != nil && height == nil {
			heightOK = false
			if !timeOK {
				return 0, errors.New("irreconcilable input lock time requirements")
			}
		} else if time == nil && height != nil {
			timeOK = false
			if !heightOK {
				return 0, errors.New("irreconcilable input lock time requirements")
			}
		}
		if time != nil && timeOK && *time > maxTime {
			maxTime = *time
		}
		if height != nil && heightOK && *height > maxHeight {
			maxHeight = *height
		}
	}

	if heightOK && maxHeight > 0 {
		return maxHeight, nil
	}
	if timeOK && maxTime > 0 {
		return maxTime, nil
	}
	if p.FallbackLocktime != nil {
		return *p.FallbackLocktime, nil
	}
	return 0, nil
}
