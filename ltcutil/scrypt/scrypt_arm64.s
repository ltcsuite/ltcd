#include "textflag.h"

#define EORP(n, Ra1, Ra2, Rb1, Rb2, Rc1, Rc2) \
	LDP	n(Ra1), (Rb1, Rb2) \
	LDP	n(Ra2), (Rc1, Rc2) \
	EOR	Rb1, Rc1, Rc1      \
	EOR	Rb2, Rc2, Rc2      \
	STP	(Rc1, Rc2), n(Ra1)

#define ADDPW(n, Ra, _, Rb1, Rb2, Rc1, Rc2) \
	LDPW	n(Ra), (Rb1, Rb2)  \
	ADDW	Rb1, Rc1, Rc1      \
	ADDW	Rb2, Rc2, Rc2      \
	STPW	(Rc1, Rc2), n(Ra)

#define BLK(OP, w, n, Ra, Rb, Rc, Rd, Re, Rf, Rg, Rh) \
	OP(0*w+n, R16, R17, R19, R20, Ra, Rb) \
	OP(1*w+n, R16, R17, R21, R22, Rc, Rd) \
	OP(2*w+n, R16, R17, R23, R24, Re, Rf) \
	OP(3*w+n, R16, R17, R25, R26, Rg, Rh)

#define ADDEORW(Ra, Rb, Rc, n, Rd) \
	ADDW	Ra, Rb, Rc         \
	EORW	Rc@>n, Rd, Rd

#define QRTRND(Ra, Rb, Rc, Rd, Re, Rf, Rg, Rh, Ri, Rj, Rk, Rl, n) \
	ADDEORW(Ra, Rb, R19, n, Rc) \
	ADDEORW(Rd, Re, R20, n, Rf) \
	ADDEORW(Rg, Rh, R21, n, Ri) \
	ADDEORW(Rj, Rk, R22, n, Rl)

TEXT ·scrypt(SB), NOSPLIT, $8-16
	MOVD	V+8(FP), R1

L1:	MOVD	X+0(FP), R0

	FLDPQ	0(R0), (F0, F1)
	FSTPQ	(F0, F1), 0(R1)
	FLDPQ	32(R0), (F2, F3)
	FSTPQ	(F2, F3), 32(R1)
	FLDPQ	64(R0), (F4, F5)
	FSTPQ	(F4, F5), 64(R1)
	FLDPQ	96(R0), (F6, F7)
	FSTPQ	(F6, F7), 96(R1)

	MOVD	R1, 8(RSP)
	ADD	$64, R0, R1
	CALL	eor_salsa8(SB)
	MOVD	X+0(FP), R1
	ADD	$64, R1, R0
	CALL	eor_salsa8(SB)

	MOVD	8(RSP), R1
	ADD	$128, R1, R1
	MOVD	V+8(FP), R2
	ADD	$0x20000, R2, R2
	CMP	R1, R2
	BNE	L1

	MOVD	$0, R1

L2:	MOVD	R1, 8(RSP)
	MOVD	X+0(FP), R16
	MOVD	V+8(FP), R17
	MOVWU	64(R16), R0
	AND	$1023, R0, R0
	ADD	R0<<7, R17, R17

	BLK(EORP, 16, 0,  R0, R1, R2, R3, R4, R5, R6, R7)
	BLK(EORP, 16, 64, R0, R1, R2, R3, R4, R5, R6, R7)

	MOVD	R16, R0
	ADD	$64, R0, R1
	CALL	eor_salsa8(SB)
	MOVD	X+0(FP), R1
	ADD	$64, R1, R0
	CALL	eor_salsa8(SB)

	MOVD	8(RSP), R1
	ADD	$1, R1, R1
	CMP	$1024, R1
	BNE	L2

	RET

TEXT eor_salsa8(SB), NOSPLIT, $0
	MOVD	R0, R16
	MOVD	R1, R17

	BLK(EORP, 16, 0, R0, R2, R4, R6, R8, R10, R12, R14)

	LSR	$32, R0, R1
	LSR	$32, R2, R3
	LSR	$32, R4, R5
	LSR	$32, R6, R7
	LSR	$32, R8, R9
	LSR	$32, R10, R11
	LSR	$32, R12, R13
	LSR	$32, R14, R15

	MOVD	$0, R17

L:	QRTRND(R0, R12, R4, R5, R1, R9, R10, R6, R14, R15, R11, R3, 25)
	QRTRND(R4,  R0, R8, R9, R5, R13, R14, R10, R2, R3, R15, R7, 23)
	QRTRND(R8,  R4, R12, R13, R9, R1, R2, R14, R6, R7, R3, R11, 19)
	QRTRND(R12, R8, R0, R1, R13, R5, R6, R2, R10, R11, R7, R15, 14)
	QRTRND(R0, R3, R1, R5, R4, R6, R10, R9, R11, R15, R14, R12, 25)
	QRTRND(R1, R0, R2, R6, R5, R7, R11, R10, R8, R12, R15, R13, 23)
	QRTRND(R2, R1, R3, R7, R6, R4,  R8, R11, R9, R13, R12, R14, 19)
	QRTRND(R3, R2, R0, R4, R7, R5,  R9, R8, R10, R14, R13, R15, 14)

	ADD	$1, R17, R17
	CMP	$4, R17
	BNE	L

	BLK(ADDPW, 8, 0,  R0, R1, R2, R3, R4, R5, R6, R7)
	BLK(ADDPW, 8, 32, R8, R9, R10, R11, R12, R13, R14, R15)

	RET
