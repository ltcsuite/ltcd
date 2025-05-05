#include "textflag.h"

#define BLK_CPY(n) \
	FLDPQ	n(R16), (F0, F1)  \
	FSTPQ.P	(F0, F1), 32(R17)

#define BLK_EOR(n) \
	FLDPQ	n(R16), (F0, F1)       \
	FLDPQ	n+32(R16), (F2, F3)    \
	FLDPQ.P	32(R17), (F4, F5)      \
	FLDPQ.P	32(R17), (F6, F7)      \
	VEOR	V0.B16, V4.B16, V0.B16 \
	VEOR	V1.B16, V5.B16, V1.B16 \
	VEOR	V2.B16, V6.B16, V2.B16 \
	VEOR	V3.B16, V7.B16, V3.B16 \
	FSTPQ	(F0, F1), n(R16)       \
	FSTPQ	(F2, F3), n+32(R16)

#define BLK_MIX \
	ADD	$64, R16, R17  \
	CALL	·eorSalsa8(SB) \
	MOVD	X+0(FP), R17   \
	ADD	$64, R17, R16  \
	CALL	·eorSalsa8(SB) \
	MOVD	X+0(FP), R16

#define MIX_LP1 \
	BLK_CPY(0)           \
	BLK_CPY(32)          \
	BLK_CPY(64)          \
	BLK_CPY(96)          \
	MOVD	R17, p-8(SP) \
	BLK_MIX              \
	MOVD	p-8(SP), R17

#define MIX_LP2 \
	MOVWU	64(R16), R0  \
	MOVD	V+8(FP), R17 \
	ANDW	$1023, R0    \
	ADD	R0<<7, R17   \
	BLK_EOR(0)           \
	BLK_EOR(64)          \
	BLK_MIX

TEXT ·scryptAsm(SB), NOSPLIT, $8-16
	MOVD	X+0(FP), R16
	MOVD	V+8(FP), R17

L1:	MIX_LP1
	MIX_LP1
	MIX_LP1
	MIX_LP1

	MOVD	V+8(FP), R0
	ADD	$0x20000, R0
	CMP	R17, R0
	BNE	L1

	MOVD	$1024, R0

L2:	MOVD	R0, i-8(SP)

	MIX_LP2
	MIX_LP2
	MIX_LP2
	MIX_LP2

	MOVD	i-8(SP), R0
	SUBS	$4, R0
	BNE	L2

	RET

#define ADD_EOR(Ra, Rb, n, Rc) \
	ADDW	Ra, Rb, R17    \
	EORW	R17@>n, Rc

#define QR(Ra, Rb, Rc, Rd, Re, Rf, Rg, Rh, Ri, Rj, Rk, Rl, n) \
	ADD_EOR(Ra, Rb, n, Rc) \
	ADD_EOR(Rd, Re, n, Rf) \
	ADD_EOR(Rg, Rh, n, Ri) \
	ADD_EOR(Rj, Rk, n, Rl)

#define DBL_RND \
	QR(R0, R12, R4, R5, R1, R9, R10, R6, R14, R15, R11, R3, 25) \
	QR(R4,  R0, R8, R9, R5, R13, R14, R10, R2, R3, R15, R7, 23) \
	QR(R8,  R4, R12, R13, R9, R1, R2, R14, R6, R7, R3, R11, 19) \
	QR(R12, R8, R0, R1, R13, R5, R6, R2, R10, R11, R7, R15, 14) \
	QR(R0, R3, R1, R5, R4, R6, R10, R9, R11, R15, R14, R12, 25) \
	QR(R1, R0, R2, R6, R5, R7, R11, R10, R8, R12, R15, R13, 23) \
	QR(R2, R1, R3, R7, R6, R4,  R8, R11, R9, R13, R12, R14, 19) \
	QR(R3, R2, R0, R4, R7, R5,  R9, R8, R10, R14, R13, R15, 14)

#define EOR_MOV(n, Ra, Rb, Rc, Rd, Re, Rf) \
	LDP	n(R16), (R19, R20) \
	LDP	n(R17), (Ra, Rc)   \
	EOR	R19, Ra            \
	EOR	R20, Rc            \
	LSR	$32, Ra, Rb        \
	LSR	$32, Rc, Rd        \
	MOVD	Ra, Re             \
	MOVD	Rc, Rf

#define ADD_STP(Ra, Rb, Rc)      \
	ADDW	Ra, Rb           \
	ADD	Ra>>32, Rc       \
	STPW.P	(Rb, Rc), 8(R16)

TEXT ·eorSalsa8(SB), $0
	EOR_MOV(0,  R0, R1, R2, R3, R21, R22)
	EOR_MOV(16, R4, R5, R6, R7, R23, R24)
	EOR_MOV(32, R8, R9, R10, R11, R25, R26)
	EOR_MOV(48, R12, R13, R14, R15, R19, R20)

	DBL_RND
	DBL_RND
	DBL_RND
	DBL_RND

	ADD_STP(R21, R0, R1)
	ADD_STP(R22, R2, R3)
	ADD_STP(R23, R4, R5)
	ADD_STP(R24, R6, R7)
	ADD_STP(R25, R8, R9)
	ADD_STP(R26, R10, R11)
	ADD_STP(R19, R12, R13)
	ADD_STP(R20, R14, R15)

	RET
