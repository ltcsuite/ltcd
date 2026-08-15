package psbt

// The BIP-0174 Combiner role plus the LIP-0007 MWEB combine rules:
// packets containing MWEB components are identified by structural
// compatibility rather than txid, every MWEB field merges strictly (present
// on both sides means equal, or the combine fails), canonical BIP-174 fields
// keep their union semantics, and a failed combine leaves the destination
// untouched.

import (
	"bytes"
	"errors"

	"github.com/ltcsuite/ltcd/ltcutil/mweb/mw"
	"github.com/ltcsuite/ltcd/wire"
)

// mergeStealthAddress merges the one optional field whose struct holds
// pointers: comparison must be by key bytes, not pointer identity.
func mergeStealthAddress(dst **mw.StealthAddress, src *mw.StealthAddress) bool {
	if src == nil {
		return true
	}
	if *dst == nil {
		address := mw.StealthAddress{Scan: src.Scan, Spend: src.Spend}
		*dst = &address
		return true
	}
	d := *dst
	if d.Scan == nil || d.Spend == nil || src.Scan == nil || src.Spend == nil {
		return d.Scan == src.Scan && d.Spend == src.Spend
	}
	return *d.Scan == *src.Scan && *d.Spend == *src.Spend
}

// ErrCombineMismatch indicates that two packets carry conflicting values for
// the same field, or are not structurally compatible, and cannot be merged.
var ErrCombineMismatch = errors.New("psbt packets are not compatible")

// Combine merges src into p following the LIP-0007 combining rules. On any
// mismatch p is left unmodified and ErrCombineMismatch is returned.
func (p *Packet) Combine(src *Packet) error {
	if p.PsbtVersion != src.PsbtVersion || p.TxVersion != src.TxVersion {
		return ErrCombineMismatch
	}
	if len(p.Inputs) != len(src.Inputs) ||
		len(p.Outputs) != len(src.Outputs) ||
		len(p.Kernels) != len(src.Kernels) {

		return ErrCombineMismatch
	}

	containsMweb := p.HasMwebComponents() || src.HasMwebComponents()

	// Identity: a v0 pair merges over the same unsigned transaction; a v2
	// pair must agree on the effective lock time (per-index identity is
	// checked during the field merges), replacing the txid identity that
	// neither commits to MWEB data nor survives peg-in finalization.
	if p.PsbtVersion == 0 {
		if p.UnsignedTx == nil || src.UnsignedTx == nil ||
			p.UnsignedTx.TxHash() != src.UnsignedTx.TxHash() {

			return ErrCombineMismatch
		}
	} else {
		dstLock, err1 := effectiveLockTime(p)
		srcLock, err2 := effectiveLockTime(src)
		if err1 != nil || err2 != nil || dstLock != srcLock {
			return ErrCombineMismatch
		}
	}

	// Merge into a copy so a mismatch leaves p untouched.
	merged := copyPacket(p)
	dstHasBaseSigs := hasBaseSignatureData(merged)
	srcHasBaseSigs := hasBaseSignatureData(src)

	for i := range merged.Inputs {
		if !mergeInput(&merged.Inputs[i], &src.Inputs[i], containsMweb) {
			return ErrCombineMismatch
		}
	}
	for i := range merged.Outputs {
		if !mergeOutput(&merged.Outputs[i], &src.Outputs[i],
			dstHasBaseSigs, srcHasBaseSigs, containsMweb) {

			return ErrCombineMismatch
		}
	}
	for i := range merged.Kernels {
		if !mergeKernel(&merged.Kernels[i], &src.Kernels[i]) {
			return ErrCombineMismatch
		}
	}

	if !mergeOpt(&merged.MwebTxOffset, src.MwebTxOffset) ||
		!mergeOpt(&merged.MwebStealthOffset, src.MwebStealthOffset) {

		return ErrCombineMismatch
	}
	if validatePeginOutputs(merged, false) != nil {
		return ErrCombineMismatch
	}

	mergedUnknowns, ok := mergeUnknowns(merged.Unknowns, src.Unknowns, containsMweb)
	if !ok {
		return ErrCombineMismatch
	}
	merged.Unknowns = mergedUnknowns

	merged.ExtPubKeys = mergeXpubs(merged.ExtPubKeys, src.ExtPubKeys)

	if merged.FallbackLocktime == nil && src.FallbackLocktime != nil {
		fallback := *src.FallbackLocktime
		merged.FallbackLocktime = &fallback
	}
	switch {
	case merged.TxModifiableFlag != nil && src.TxModifiableFlag != nil:
		modifiable := *merged.TxModifiableFlag | *src.TxModifiableFlag
		merged.TxModifiableFlag = &modifiable
	case merged.TxModifiableFlag == nil && src.TxModifiableFlag != nil:
		modifiable := *src.TxModifiableFlag
		merged.TxModifiableFlag = &modifiable
	}
	if containsMweb && hasMwebSignatureOrProof(merged) &&
		merged.TxModifiableFlag != nil {

		modifiable := TxModifiableFlag(0)
		merged.TxModifiableFlag = &modifiable
	}

	*p = *merged
	return nil
}

// mergeOpt strictly merges an optional comparable field: present on both
// sides means equal, one-sided values are copied.
func mergeOpt[T comparable](dst **T, src *T) bool {
	if src == nil {
		return true
	}
	if *dst == nil {
		value := *src
		*dst = &value
		return true
	}
	return **dst == *src
}

// mergeBytesStrict strictly merges an optional byte-slice field.
func mergeBytesStrict(dst *[]byte, src []byte) bool {
	if len(src) == 0 {
		return true
	}
	if len(*dst) == 0 {
		*dst = append([]byte{}, src...)
		return true
	}
	return bytes.Equal(*dst, src)
}

// fillBytes copies a one-sided byte-slice field without conflict checking
// (BIP-174 union semantics for canonical script fields).
func fillBytes(dst *[]byte, src []byte) {
	if len(*dst) == 0 && len(src) > 0 {
		*dst = append([]byte{}, src...)
	}
}

func mergeInput(dst, src *PInput, strictMetadata bool) bool {
	if dst.isMWEB() != src.isMWEB() {
		return false
	}

	mergedUnknowns, ok := mergeUnknowns(dst.Unknowns, src.Unknowns, strictMetadata || dst.isMWEB())
	if !ok {
		return false
	}

	if !dst.isMWEB() {
		if !equalOpt(dst.PrevoutHash, src.PrevoutHash) ||
			!equalOpt(dst.PrevoutIndex, src.PrevoutIndex) {

			return false
		}

		dst.Unknowns = mergedUnknowns
		mergeCanonicalInput(dst, src)
		return true
	}

	if *dst.MwebOutputId != *src.MwebOutputId {
		return false
	}

	if !mergeOpt(&dst.MwebCommit, src.MwebCommit) ||
		!mergeOpt(&dst.MwebOutputPubkey, src.MwebOutputPubkey) ||
		!mergeOpt(&dst.MwebInputPubkey, src.MwebInputPubkey) ||
		!mergeOpt(&dst.MwebFeatures, src.MwebFeatures) ||
		!mergeOpt(&dst.MwebInputSig, src.MwebInputSig) ||
		!mergeOpt(&dst.MwebAmount, src.MwebAmount) ||
		!mergeOpt(&dst.MwebSharedSecret, src.MwebSharedSecret) ||
		!mergeOpt(&dst.MwebKeyExchangePubkey, src.MwebKeyExchangePubkey) ||
		!mergeBytesStrict(&dst.MwebAddrDescriptor, src.MwebAddrDescriptor) ||
		!mergeBytesStrict(&dst.MwebExtraData, src.MwebExtraData) {

		return false
	}

	dst.Unknowns = mergedUnknowns
	return true
}

// mergeCanonicalInput applies the BIP-174 union to a canonical input pair
// whose identity has already been checked.
func mergeCanonicalInput(dst, src *PInput) {
	if dst.NonWitnessUtxo == nil {
		dst.NonWitnessUtxo = src.NonWitnessUtxo
	}
	if dst.WitnessUtxo == nil {
		dst.WitnessUtxo = src.WitnessUtxo
	}

	dst.PartialSigs = unionPartialSigs(dst.PartialSigs, src.PartialSigs)
	dst.Bip32Derivation = unionBip32(dst.Bip32Derivation, src.Bip32Derivation)
	dst.TaprootScriptSpendSig = unionTaprootScriptSpendSigs(
		dst.TaprootScriptSpendSig, src.TaprootScriptSpendSig,
	)
	dst.TaprootLeafScript = unionTaprootLeafScripts(
		dst.TaprootLeafScript, src.TaprootLeafScript,
	)
	dst.TaprootBip32Derivation = unionTaprootBip32(
		dst.TaprootBip32Derivation, src.TaprootBip32Derivation,
	)

	fillBytes(&dst.RedeemScript, src.RedeemScript)
	fillBytes(&dst.WitnessScript, src.WitnessScript)
	fillBytes(&dst.FinalScriptSig, src.FinalScriptSig)
	fillBytes(&dst.FinalScriptWitness, src.FinalScriptWitness)
	fillBytes(&dst.TaprootKeySpendSig, src.TaprootKeySpendSig)
	fillBytes(&dst.TaprootInternalKey, src.TaprootInternalKey)
	fillBytes(&dst.TaprootMerkleRoot, src.TaprootMerkleRoot)

	if dst.Sequence == nil && src.Sequence != nil {
		sequence := *src.Sequence
		dst.Sequence = &sequence
	}
	if dst.RequiredTimeLockTime == nil && src.RequiredTimeLockTime != nil {
		lock := *src.RequiredTimeLockTime
		dst.RequiredTimeLockTime = &lock
	}
	if dst.RequiredHeightLockTime == nil && src.RequiredHeightLockTime != nil {
		lock := *src.RequiredHeightLockTime
		dst.RequiredHeightLockTime = &lock
	}

	// Fill an absent sighash instruction from src (destination wins).
	// Carrying a one-sided instruction preserves more data and cannot produce
	// a duplicate key. sighashZero distinguishes an explicit SIGHASH_DEFAULT
	// (0) from an absent field.
	if dst.SighashType == 0 && !dst.sighashZero &&
		(src.SighashType != 0 || src.sighashZero) {

		dst.SighashType = src.SighashType
		dst.sighashZero = src.sighashZero
	}
}

func mergeOutput(dst, src *POutput, dstHasBaseSigs, srcHasBaseSigs, strictMetadata bool) bool {
	if dst.isMWEB() != src.isMWEB() {
		return false
	}

	if dst.Amount != src.Amount {
		return false
	}
	if !mergeScriptStrict(&dst.PKScript, src.PKScript, dstHasBaseSigs, srcHasBaseSigs) {
		return false
	}

	mergedUnknowns, ok := mergeUnknowns(dst.Unknowns, src.Unknowns, strictMetadata || dst.isMWEB())
	if !ok {
		return false
	}

	dst.Bip32Derivation = unionBip32(dst.Bip32Derivation, src.Bip32Derivation)
	dst.TaprootBip32Derivation = unionTaprootBip32(
		dst.TaprootBip32Derivation, src.TaprootBip32Derivation,
	)
	fillBytes(&dst.RedeemScript, src.RedeemScript)
	fillBytes(&dst.WitnessScript, src.WitnessScript)
	fillBytes(&dst.TaprootInternalKey, src.TaprootInternalKey)
	fillBytes(&dst.TaprootTapTree, src.TaprootTapTree)

	if !dst.isMWEB() {
		dst.Unknowns = mergedUnknowns
		return true
	}

	if !mergeStealthAddress(&dst.StealthAddress, src.StealthAddress) ||
		!mergeOpt(&dst.OutputCommit, src.OutputCommit) ||
		!mergeOpt(&dst.MwebFeatures, src.MwebFeatures) ||
		!mergeOpt(&dst.SenderPubkey, src.SenderPubkey) ||
		!mergeOpt(&dst.OutputPubkey, src.OutputPubkey) ||
		!mergeOpt(&dst.MwebStandardFields, src.MwebStandardFields) ||
		!mergeOpt(&dst.RangeProof, src.RangeProof) ||
		!mergeOpt(&dst.MwebSignature, src.MwebSignature) ||
		!mergeBytesStrict(&dst.MwebExtraData, src.MwebExtraData) {

		return false
	}

	dst.Unknowns = mergedUnknowns
	return true
}

func mergeKernel(dst, src *PKernel) bool {
	// A features byte inconsistent with its own map invalidates the
	// combine; consistent bytes are recomputed to the merged fields.
	if !kernelFeaturesConsistent(dst) || !kernelFeaturesConsistent(src) {
		return false
	}
	hadFeatures := dst.Features != nil || src.Features != nil

	if !mergeOpt(&dst.ExcessCommitment, src.ExcessCommitment) ||
		!mergeOpt(&dst.StealthExcess, src.StealthExcess) ||
		!mergeOpt(&dst.Fee, src.Fee) ||
		!mergeOpt(&dst.PeginAmount, src.PeginAmount) ||
		!mergePegOuts(&dst.PegOuts, src.PegOuts) ||
		!mergeOpt(&dst.LockHeight, src.LockHeight) ||
		!mergeBytesStrict(&dst.ExtraData, src.ExtraData) ||
		!mergeOpt(&dst.Signature, src.Signature) {

		return false
	}

	mergedUnknowns, ok := mergeUnknowns(dst.Unknowns, src.Unknowns, true)
	if !ok {
		return false
	}
	dst.Unknowns = mergedUnknowns

	if hadFeatures {
		features := dst.featuresFromFields()
		dst.Features = &features
	}
	return true
}

func kernelFeaturesConsistent(pk *PKernel) bool {
	return pk.Features == nil || *pk.Features == pk.featuresFromFields()
}

// mergeScriptStrict merges an output script with the peg-in placeholder
// rules: a placeholder may be replaced by a finalized peg-in script unless
// the placeholder's side already carries canonical signature data.
func mergeScriptStrict(dst *[]byte, src []byte, dstHasBaseSigs, srcHasBaseSigs bool) bool {
	if len(src) == 0 {
		return true
	}
	if len(*dst) == 0 {
		*dst = append([]byte{}, src...)
		return true
	}
	if bytes.Equal(*dst, src) {
		return true
	}

	if isPeginPlaceholder(*dst) && isFinalPeginScript(src) {
		if dstHasBaseSigs {
			return false
		}
		*dst = append([]byte{}, src...)
		return true
	}
	if isFinalPeginScript(*dst) && isPeginPlaceholder(src) {
		return !srcHasBaseSigs
	}

	return false
}

func isFinalPeginScript(script []byte) bool {
	return isPeginScript(script) && !isPeginPlaceholder(script)
}

func mergePegOuts(dst *[]*wire.TxOut, src []*wire.TxOut) bool {
	if len(src) == 0 {
		return true
	}
	if len(*dst) == 0 {
		result := make([]*wire.TxOut, len(src))
		for i, pegout := range src {
			result[i] = &wire.TxOut{
				Value:    pegout.Value,
				PkScript: append([]byte{}, pegout.PkScript...),
			}
		}
		*dst = result
		return true
	}
	if len(*dst) != len(src) {
		return false
	}
	for i, pegout := range src {
		if (*dst)[i].Value != pegout.Value ||
			!bytes.Equal((*dst)[i].PkScript, pegout.PkScript) {

			return false
		}
	}
	return true
}

// mergeUnknowns merges unknown/proprietary keys: strictly (equal-or-fail)
// within MWEB packets, keep-first union otherwise.
func mergeUnknowns(dst, src []*Unknown, strict bool) ([]*Unknown, bool) {
	merged := append([]*Unknown{}, dst...)
	seen := make(map[string][]byte, len(dst))
	for _, unknown := range dst {
		seen[string(unknown.Key)] = unknown.Value
	}
	for _, unknown := range src {
		if existing, present := seen[string(unknown.Key)]; present {
			if strict && !bytes.Equal(existing, unknown.Value) {
				return nil, false
			}
			continue
		}
		seen[string(unknown.Key)] = unknown.Value
		merged = append(merged, unknown)
	}
	return merged, true
}

// unionKeepFirst returns dst followed by the src elements whose key is not
// already present (by sameKey). It always returns a fresh slice, and every
// collection dedups on its serialized keydata, so re-serialization never emits
// a duplicate key.
func unionKeepFirst[T any](dst, src []T, sameKey func(a, b T) bool) []T {
	merged := append([]T{}, dst...)
	for _, s := range src {
		found := false
		for _, existing := range merged {
			if sameKey(existing, s) {
				found = true
				break
			}
		}
		if !found {
			merged = append(merged, s)
		}
	}
	return merged
}

// mergeXpubs unions global xpubs keyed by the extended key alone (its serialized
// PSBT key), so entries sharing an xpub but differing in fingerprint/path cannot
// emit a duplicate key, matching BIP-0174 global-xpub deduplication (one per xpub).
func mergeXpubs(dst, src []*GlobalExtPubKey) []*GlobalExtPubKey {
	return unionKeepFirst(dst, src, func(a, b *GlobalExtPubKey) bool {
		return a.ExtKey.String() == b.ExtKey.String()
	})
}

func equalOpt[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func unionPartialSigs(dst, src []*PartialSig) []*PartialSig {
	return unionKeepFirst(dst, src, func(a, b *PartialSig) bool {
		return bytes.Equal(a.PubKey, b.PubKey)
	})
}

func unionBip32(dst, src []*Bip32Derivation) []*Bip32Derivation {
	return unionKeepFirst(dst, src, func(a, b *Bip32Derivation) bool {
		return bytes.Equal(a.PubKey, b.PubKey)
	})
}

// The taproot collections each serialize one record per element keyed by its
// keydata: (x-only pubkey, leaf hash) for script-spend sigs, the control block
// for leaf scripts, and the x-only pubkey for bip32 derivations.
func unionTaprootScriptSpendSigs(dst, src []*TaprootScriptSpendSig) []*TaprootScriptSpendSig {
	return unionKeepFirst(dst, src, func(a, b *TaprootScriptSpendSig) bool {
		return a.EqualKey(b)
	})
}

func unionTaprootLeafScripts(dst, src []*TaprootTapLeafScript) []*TaprootTapLeafScript {
	return unionKeepFirst(dst, src, func(a, b *TaprootTapLeafScript) bool {
		return bytes.Equal(a.ControlBlock, b.ControlBlock)
	})
}

func unionTaprootBip32(dst, src []*TaprootBip32Derivation) []*TaprootBip32Derivation {
	return unionKeepFirst(dst, src, func(a, b *TaprootBip32Derivation) bool {
		return bytes.Equal(a.XOnlyPubKey, b.XOnlyPubKey)
	})
}

// hasBaseSignatureData reports whether any input carries canonical signature
// material (which commits to the peg-in scripts).
func hasBaseSignatureData(p *Packet) bool {
	for i := range p.Inputs {
		// MWEB inputs never carry canonical signatures, and their fields
		// must not veto a peg-in placeholder replacement.
		if p.Inputs[i].isMWEB() {
			continue
		}
		if hasCanonicalSigData(&p.Inputs[i]) {
			return true
		}
	}
	return false
}

// hasMwebSignatureOrProof reports whether any MWEB signature or range proof
// is present, after which the packet is no longer modifiable.
func hasMwebSignatureOrProof(p *Packet) bool {
	for i := range p.Inputs {
		if p.Inputs[i].MwebInputSig != nil {
			return true
		}
	}
	for i := range p.Outputs {
		if p.Outputs[i].MwebSignature != nil || p.Outputs[i].RangeProof != nil {
			return true
		}
	}
	for i := range p.Kernels {
		if p.Kernels[i].Signature != nil {
			return true
		}
	}
	return false
}

// copyPacket returns a copy of p whose maps can be merged into without
// touching the original: the three map slices hold fresh element copies, and
// every merge helper replaces fields rather than writing through shared
// backing arrays.
func copyPacket(p *Packet) *Packet {
	copied := *p
	copied.Inputs = append([]PInput{}, p.Inputs...)
	copied.Outputs = append([]POutput{}, p.Outputs...)
	copied.Kernels = append([]PKernel{}, p.Kernels...)
	if p.MwebTxOffset != nil {
		offset := *p.MwebTxOffset
		copied.MwebTxOffset = &offset
	}
	if p.MwebStealthOffset != nil {
		offset := *p.MwebStealthOffset
		copied.MwebStealthOffset = &offset
	}
	if p.TxModifiableFlag != nil {
		modifiable := *p.TxModifiableFlag
		copied.TxModifiableFlag = &modifiable
	}
	return &copied
}
