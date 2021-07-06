
/*************************************************************************

File Name: ZUC256_AVX512.c

Author   : Bai Liang(CN 569252860)

Publish Date: 2021.01.08

PURPOSE  : Implementation of ZUC-256 stream cipher algorithm

This is the implementation of our paper: **Efficient software Implementation of ZUC-256
(to be published in the Journal of Cryptography)**. Our code has been tested on Windows 
(mandatory dependency on Microsoft Visual Studio 2017 or 2019). The primary goal of this 
project to obtain *high software performance* of ZUC-256 while being *easy to use*.
The implementation is highly optimized using fast AES-NI and AVX512 instructions
to obtain optimal performance both in the single and multi-threaded setting.

## Help
For any questions on building or running the project, please send a e-mail to
[Bai Liang]gmu.shmily@gmail.com

## License
This project has been placed in the public domain. As such, you are unrestricted in how
you use it, commercial or otherwise. However, no warranty of fitness is provided. If you
found this project helpful, feel free to spread the word and cite us.

Copyright 2021 SDT(CN) Ltd.

*************************************************************************/

///////////////////////////////////////////////////////////////////////////////////////////////////////

#include "ZUC256_AVX512.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////

#define V1SET1B _mm_set1_epi8
#define V1AESLAST _mm_aesenclast_si128

#define V4OR  _mm512_or_si512
#define V4XOR _mm512_xor_si512
#define V4AND _mm512_and_si512
#define V4ADD _mm512_add_epi32
#define V4SHUFB _mm512_shuffle_epi8
#define V4SET1B _mm512_set1_epi8
#define V4SET1S _mm512_set1_epi16
#define V4SET1D _mm512_set1_epi32
#define V4SETD _mm512_set_epi32
#define V4SETRD _mm512_setr_epi32
#define V4SLL _mm512_slli_epi32
#define V4SRL _mm512_srli_epi32
#define V4ROTL(a,imm) V4OR(V4SLL(a,imm),V4SRL(a,32-imm))
#define V4SCATTER(C, vindex, v) _mm512_i32scatter_epi32(C, vindex, v, 4)
#define V4BLENDB(a, b) _mm512_mask_blend_epi8(0x5555555555555555, a, b)
#define V4BLENDS(a, b) _mm512_mask_blend_epi16(0x55555555, a, b)
#define V4LOADU _mm512_loadu_si512
#define V4STOREU _mm512_storeu_si512

///////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
	__m512i LFSR_S[16];
	__m512i F_R[2];
	__m512i BRC_X[4];
} ZUC256_AVX512_State;

__m512i p1_mask;
__m512i p2_mask;
__m512i p3_mask;

#define LOWER_NIBBLE_MASK 0x0F
#define LOWER_5BITS_MASK 0x1F
#define HIGHER_3BITS_MASK 0xE0
__m512i lower_nibble_mask;
__m512i lower_5bits_mask;
__m512i higher_3bits_mask;

#define RIGHT_1BIT_MASK 0x55
#define LEFT_1BIT_MASK 0xAA
#define RIGHT_2BITS_MASK 0x33
#define LEFT_2BITS_MASK 0xCC
#define RIGHT_4BITS_MASK 0x0F
#define LEFT_4BITS_MASK 0xF0
#define RIGHT_8BITS_MASK 0x00FF
#define LEFT_8BITS_MASK 0xFF00
__m512i right_1bit_mask;
__m512i left_1bit_mask;
__m512i right_2bits_mask;
__m512i left_2bits_mask;
__m512i right_4bits_mask;
__m512i left_4bits_mask;
__m512i right_8bits_mask;
__m512i left_8bits_mask;

__m512i k_mul_mask1;
__m512i k_mul_mask2;
__m512i t_mul_mask1;
__m512i t_mul_mask2;
__m512i shuffle_mask;
__m128i aes_const_key;


#define MBP_MASK 0x7FFFFFFF
__m512i mbp_mask;

int SetupSign = 0;

void ZUC256_Setup_AVX512()
{
#define P1_MASK_128 0x09030507,0x0C000400,0x0A020F0F,0x0E000F09
#define P2_MASK_128 0x0209030F,0x0A0E010B,0x040C0007,0x05060D08
#define P3_MASK_128 0x0D0C0900,0x050D0303,0x0F0A0D00,0x060A0602
#define P1_MASK P1_MASK_128,P1_MASK_128,P1_MASK_128,P1_MASK_128
#define P2_MASK P2_MASK_128,P2_MASK_128,P2_MASK_128,P2_MASK_128
#define P3_MASK P3_MASK_128,P3_MASK_128,P3_MASK_128,P3_MASK_128

#define K_MUL_MASK1_128 0xD3D20A0B,0xB8B96160,0xB3B26A6B,0xD8D90100
#define K_MUL_MASK2_128 0x29AB63E1,0xEE6CA426,0x0F8D45C7,0xC84A8200
#define K_MUL_MASK1 K_MUL_MASK1_128,K_MUL_MASK1_128,K_MUL_MASK1_128,K_MUL_MASK1_128
#define K_MUL_MASK2 K_MUL_MASK2_128,K_MUL_MASK2_128,K_MUL_MASK2_128,K_MUL_MASK2_128

#define T_MUL_MASK1_128 0x5B867FA2,0xA479805D,0x538E77AA,0xAC718855
#define T_MUL_MASK2_128 0x47DE73EA,0x33AA079E,0xD940ED74,0xAD349900
#define T_MUL_MASK1 T_MUL_MASK1_128,T_MUL_MASK1_128,T_MUL_MASK1_128,T_MUL_MASK1_128
#define T_MUL_MASK2 T_MUL_MASK2_128,T_MUL_MASK2_128,T_MUL_MASK2_128,T_MUL_MASK2_128

#define AES_SHUF_MASK_128 0x0306090c,0x0f020508,0x0b0e0104,0x070a0d00
#define AES_SHUF_MASK  AES_SHUF_MASK_128,AES_SHUF_MASK_128,AES_SHUF_MASK_128,AES_SHUF_MASK_128
#define AES_CONST_KEY  0x63

	if (SetupSign == 1) return;

	SetupSign = 1;

	p1_mask = V4SETD(P1_MASK);
	p2_mask = V4SETD(P2_MASK);
	p3_mask = V4SETD(P3_MASK);

	lower_nibble_mask = V4SET1B(LOWER_NIBBLE_MASK);
	lower_5bits_mask = V4SET1B(LOWER_5BITS_MASK);
	higher_3bits_mask = V4SET1B(HIGHER_3BITS_MASK);

	right_1bit_mask = V4SET1B(RIGHT_1BIT_MASK);
	left_1bit_mask = V4SET1B(LEFT_1BIT_MASK);
	right_2bits_mask = V4SET1B(RIGHT_2BITS_MASK);
	left_2bits_mask = V4SET1B(LEFT_2BITS_MASK);
	right_4bits_mask = V4SET1B(RIGHT_4BITS_MASK);
	left_4bits_mask = V4SET1B(LEFT_4BITS_MASK);
	right_8bits_mask = V4SET1S(RIGHT_8BITS_MASK);
	left_8bits_mask = V4SET1S(LEFT_8BITS_MASK);

	k_mul_mask1 = V4SETD(K_MUL_MASK1);
	k_mul_mask2 = V4SETD(K_MUL_MASK2);
	t_mul_mask1 = V4SETD(T_MUL_MASK1);
	t_mul_mask2 = V4SETD(T_MUL_MASK2);
	shuffle_mask = V4SETD(AES_SHUF_MASK);
	aes_const_key = V1SET1B(AES_CONST_KEY);

	mbp_mask = V4SET1D(MBP_MASK);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

__m512i sbox0(const __m512i in)
{
	__m512i hi = V4AND(V4SRL(in, 4), lower_nibble_mask);
	__m512i low = V4AND(in, lower_nibble_mask);

	const __m512i t1 = V4XOR(hi, V4SHUFB(p1_mask, low));
	const __m512i t2 = V4XOR(low, V4SHUFB(p2_mask, t1));
	const __m512i t3 = V4XOR(t1, V4SHUFB(p3_mask, t2));

	const __m512i out = V4OR(t2, V4SLL(t3, 4));

	low = V4AND(V4SRL(out, 3), lower_5bits_mask);
	hi = V4AND(V4SLL(out, 5), higher_3bits_mask);

	return V4OR(hi, low);
}


///////////////////////////////////////////////////////////////////////////////////////////////////////

__m512i sbox1(const __m512i in)
{
	__m512i low = V4SHUFB(k_mul_mask1, V4AND(in, lower_nibble_mask));
	__m512i hi = V4SHUFB(k_mul_mask2, V4AND(V4SRL(in, 4), lower_nibble_mask));
	__m512i y_inv = V4SHUFB(V4XOR(low, hi), shuffle_mask);
	__m128i tmp[4];


	tmp[0] = V1AESLAST(_mm512_castsi512_si128(y_inv), aes_const_key);
	tmp[1] = V1AESLAST(_mm512_extracti32x4_epi32(y_inv, 1), aes_const_key);
	tmp[2] = V1AESLAST(_mm512_extracti32x4_epi32(y_inv, 2), aes_const_key);
	tmp[3] = V1AESLAST(_mm512_extracti32x4_epi32(y_inv, 3), aes_const_key);
	y_inv = _mm512_castsi128_si512(tmp[0]);
	y_inv = _mm512_inserti32x4(y_inv, tmp[1], 1);
	y_inv = _mm512_inserti32x4(y_inv, tmp[2], 2);
	y_inv = _mm512_inserti32x4(y_inv, tmp[3], 3);

	low = V4SHUFB(t_mul_mask1, V4AND(y_inv, lower_nibble_mask));
	hi = V4SHUFB(t_mul_mask2, V4AND(V4SRL(y_inv, 4), lower_nibble_mask));

	return V4XOR(low, hi);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////

#define	MBP2(x, k) V4AND(V4OR(V4SLL(x, k), V4SRL(x, 31-k)), mbp_mask)
#define	AMR(c) V4ADD(V4AND(c, mbp_mask), V4SRL(c, 31))

#define V_FEEDBACK(f, v)\
	v = MBP2(LFSR_S[ 0],  8); f = V4ADD(LFSR_S[ 0], v);f = AMR(f);\
	v = MBP2(LFSR_S[ 4], 20); f = V4ADD(f, v);f = AMR(f);\
	v = MBP2(LFSR_S[10], 21); f = V4ADD(f, v);f = AMR(f);\
	v = MBP2(LFSR_S[13], 17); f = V4ADD(f, v);f = AMR(f);\
	v = MBP2(LFSR_S[15], 15); f = V4ADD(f, v);f = AMR(f)

#define V_BITR_INIT() \
	BRC_X[0] = V4BLENDS(V4SLL(LFSR_S[15], 1), LFSR_S[14]);\
	BRC_X[1] = V4OR(V4SLL(LFSR_S[11], 16), V4SRL(LFSR_S[ 9], 15));\
	BRC_X[2] = V4OR(V4SLL(LFSR_S[ 7], 16), V4SRL(LFSR_S[ 5], 15))

#define V_BITR() \
	BRC_X[0] = V4BLENDS(V4SLL(LFSR_S[15], 1), LFSR_S[14]);\
	BRC_X[1] = V4OR(V4SLL(LFSR_S[11], 16), V4SRL(LFSR_S[ 9], 15));\
	BRC_X[2] = V4OR(V4SLL(LFSR_S[ 7], 16), V4SRL(LFSR_S[ 5], 15));\
	BRC_X[3] = V4OR(V4SLL(LFSR_S[ 2], 16), V4SRL(LFSR_S[ 0], 15))

#define V_SHIFT()\
	LFSR_S[ 0] = LFSR_S[ 1];\
	LFSR_S[ 1] = LFSR_S[ 2];\
	LFSR_S[ 2] = LFSR_S[ 3];\
	LFSR_S[ 3] = LFSR_S[ 4];\
	LFSR_S[ 4] = LFSR_S[ 5];\
	LFSR_S[ 5] = LFSR_S[ 6];\
	LFSR_S[ 6] = LFSR_S[ 7];\
	LFSR_S[ 7] = LFSR_S[ 8];\
	LFSR_S[ 8] = LFSR_S[ 9];\
	LFSR_S[ 9] = LFSR_S[10];\
	LFSR_S[10] = LFSR_S[11];\
	LFSR_S[11] = LFSR_S[12];\
	LFSR_S[12] = LFSR_S[13];\
	LFSR_S[13] = LFSR_S[14];\
	LFSR_S[14] = LFSR_S[15];\
	LFSR_S[15] = f


#define V_FSM()\
	W = V4ADD(V4XOR(F_R[0], BRC_X[0]), F_R[1]);\
	W1 = V4ADD(F_R[0], BRC_X[1]);\
	W2 = V4XOR(F_R[1], BRC_X[2]);\
	u = V4OR(V4SLL(W1, 16), V4SRL(W2, 16));\
	v = V4OR(V4SLL(W2, 16), V4SRL(W1, 16));\
	u = V4XOR(V4XOR(V4XOR(V4XOR(u, V4ROTL(u, 2)), V4ROTL(u, 10)), V4ROTL(u, 18)), V4ROTL(u, 24));\
	v = V4XOR(V4XOR(V4XOR(V4XOR(v, V4ROTL(v, 8)), V4ROTL(v, 14)), V4ROTL(v, 22)), V4ROTL(v, 30));\
	a = sbox0(V4BLENDB(u, V4SRL(v, 8)));\
	b = sbox1(V4BLENDB(V4SLL(u, 8), v));\
	F_R[0] = V4BLENDB(a, V4SRL(b, 8));\
	F_R[1] = V4BLENDB(V4SLL(a, 8), b)

#define odd_byte_mask _mm512_set1_epi32(0x00FF00FF)
#define even_byte_mask _mm512_set1_epi32(0xFF00FF00)

// u8 to u31 : a||b||c||d, b with 7 bits
#define MAKEU31(a, b, c, d) V4OR(V4OR(V4OR(V4SLL(a, 23), V4SLL(b, 16)), V4SLL(c, 8)), d)
#define GATHER(a, b) V4AND(_mm512_i32gather_epi32(a, b, 1), V4SET1D(0xFF))

/* the constants d */
static const u8 EK_d[16] = 
{
	0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30
};

/* the constants MAC d */
const u8 EK_d_MAC[3 * 16] = 
{
	0x22, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
	0x23, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
	0x23, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30
};

void ZUC256_LFSRINIT_AVX512(ZUC256_AVX512_State *state, const u8 *k, const u8 *iv, const u8 *d)
{
	__m512i vindex0, vindex1;
	vindex0 = V4SETRD(0, 32, 32 * 2, 32 * 3, 32 * 4, 32 * 5, 32 * 6, 32 * 7,
		32 * 8, 32 * 9, 32 * 10, 32 * 11, 32 * 12, 32 * 13, 32 * 14, 32 * 15);
	vindex1 = V4SETRD(0, 25, 25 * 2, 25 * 3, 25 * 4, 25 * 5, 25 * 6, 25 * 7,
		25 * 8, 25 * 9, 25 * 10, 25 * 11, 25 * 12, 25 * 13, 25 * 14, 25 * 15);

	state->LFSR_S[0] = MAKEU31(GATHER(vindex0, k), V4SET1D(d[0]), GATHER(vindex0, k + 21), GATHER(vindex0, k + 16));
	state->LFSR_S[1] = MAKEU31(GATHER(vindex0, k + 1), V4SET1D(d[1]), GATHER(vindex0, k + 22), GATHER(vindex0, k + 17));
	state->LFSR_S[2] = MAKEU31(GATHER(vindex0, k + 2), V4SET1D(d[2]), GATHER(vindex0, k + 23), GATHER(vindex0, k + 18));
	state->LFSR_S[3] = MAKEU31(GATHER(vindex0, k + 3), V4SET1D(d[3]), GATHER(vindex0, k + 24), GATHER(vindex0, k + 19));
	state->LFSR_S[4] = MAKEU31(GATHER(vindex0, k + 4), V4SET1D(d[4]), GATHER(vindex0, k + 25), GATHER(vindex0, k + 20));
	state->LFSR_S[5] = MAKEU31(GATHER(vindex1, iv), V4OR(V4SET1D(d[5]), GATHER(vindex1, iv + 17)),
		GATHER(vindex0, k + 5), GATHER(vindex0, k + 26));
	state->LFSR_S[6] = MAKEU31(GATHER(vindex1, iv + 1), V4OR(V4SET1D(d[6]), GATHER(vindex1, iv + 18)),
		GATHER(vindex0, k + 6), GATHER(vindex0, k + 27));
	state->LFSR_S[7] = MAKEU31(GATHER(vindex1, iv + 10), V4OR(V4SET1D(d[7]), GATHER(vindex1, iv + 19)),
		GATHER(vindex0, k + 7), GATHER(vindex1, iv + 2));
	state->LFSR_S[8] = MAKEU31(GATHER(vindex0, k + 8), V4OR(V4SET1D(d[8]), GATHER(vindex1, iv + 20)),
		GATHER(vindex1, iv + 3), GATHER(vindex1, iv + 11));
	state->LFSR_S[9] = MAKEU31(GATHER(vindex0, k + 9), V4OR(V4SET1D(d[9]), GATHER(vindex1, iv + 21)),
		GATHER(vindex1, iv + 12), GATHER(vindex1, iv + 4));
	state->LFSR_S[10] = MAKEU31(GATHER(vindex1, iv + 5), V4OR(V4SET1D(d[10]), GATHER(vindex1, iv + 22)),
		GATHER(vindex0, k + 10), GATHER(vindex0, k + 28));
	state->LFSR_S[11] = MAKEU31(GATHER(vindex0, k + 11), V4OR(V4SET1D(d[11]), GATHER(vindex1, iv + 23)),
		GATHER(vindex1, iv + 6), GATHER(vindex1, iv + 13));
	state->LFSR_S[12] = MAKEU31(GATHER(vindex0, k + 12), V4OR(V4SET1D(d[12]), GATHER(vindex1, iv + 24)),
		GATHER(vindex1, iv + 7), GATHER(vindex1, iv + 14));
	state->LFSR_S[13] = MAKEU31(GATHER(vindex0, k + 13), V4SET1D(d[13]), GATHER(vindex1, iv + 15), GATHER(vindex1, iv + 8));
	state->LFSR_S[14] = MAKEU31(GATHER(vindex0, k + 14), V4OR(V4SET1D(d[14]), V4SRL(GATHER(vindex0, k + 31), 4)),
		GATHER(vindex1, iv + 16), GATHER(vindex1, iv + 9));
	state->LFSR_S[15] = MAKEU31(GATHER(vindex0, k + 15), V4OR(V4SET1D(d[15]), V4AND(GATHER(vindex0, k + 31), V4SET1D(0xF))),
		GATHER(vindex0, k + 30), GATHER(vindex0, k + 29));

	state->F_R[0] = _mm512_setzero_si512();
	state->F_R[1] = _mm512_setzero_si512();
}

/***************************************************************************

The ZUC-256 keystream generation algorithm

***************************************************************************/


//======================================================
//=| Function : ZUC256_AVX512
//=| ----------------- output ------------------
//=| ks				: output 16 lane keystreams(wordlen*16 words)
//=| ------------------ input -------------------
//=| wordlen		: word length of each lane ks(32 bits)
//=| k				: key (256*16 bits)
//=| iv				: Initialization vector (184*16 bits)
//======================================================
void ZUC256_AVX512(u32* ks, int wordlen, const u8* k, const u8* iv)
{
	__m512i W, W1, W2, u, v, a, b, f;
	ZUC256_AVX512_State state;
	__m512i *LFSR_S = state.LFSR_S, *F_R = state.F_R, *BRC_X = state.BRC_X;
	int i;

	ZUC256_Setup_AVX512();
	ZUC256_LFSRINIT_AVX512(&state, k, iv, EK_d);

	for (i = 0; i < 32; i++)
	{
		V_BITR();
		V_FSM();
		V_FEEDBACK(f, v);
		f = V4ADD(f, V4SRL(W, 1));
		f = AMR(f);
		V_SHIFT();
	}

	V_BITR();
	V_FSM();

	for (i = 0; i < wordlen; i++)
	{
		V_FEEDBACK(f, v);
		V_SHIFT();
		V_BITR();
		V_FSM();
		v = V4XOR(W, BRC_X[3]);
		V4STOREU(ks + 16 * i, v);
	}
}

/***************************************************************************

The ZUC-256 keystream based crypt algorithm

***************************************************************************/

//======================================================
//=| Function : ZUC256_CRYPT_AVX512
//=| ----------------- output ------------------
//=| C				: output 16 lane ciphers[or plians](LENGTH*16 words)
//=| ------------------ input -------------------
//=| CK				: confidentiality key(256*16 bits)
//=| IV				: Initialization vector (184*16 bits)
//=| M				: input 16 lane messages[or ciphers](LENGTH*16 words)
//=| LENGTH 		: word length of each lane message[or ciphers](32 bits)
//======================================================
void ZUC256_CRYPT_AVX512(u32* C, const u8* CK, const u8 * IV, const u32* M, int LENGTH)
{
	__m512i W, W1, W2, u, v, a, b, f;
	ZUC256_AVX512_State state;
	__m512i *LFSR_S = state.LFSR_S, *F_R = state.F_R, *BRC_X = state.BRC_X;
	int i;

	ZUC256_Setup_AVX512();
	ZUC256_LFSRINIT_AVX512(&state, CK, IV, EK_d);

	for (i = 0; i < 32; i++)
	{
		V_BITR_INIT();
		V_FSM();
		V_FEEDBACK(f, v);
		f = V4ADD(f, V4SRL(W, 1));
		f = AMR(f);
		V_SHIFT();
	}

	V_BITR_INIT();
	V_FSM();

	for (i = 0; i < LENGTH; i++)
	{
		V_FEEDBACK(f, v);
		V_SHIFT();
		V_BITR();
		V_FSM();
		v = V4LOADU(M + 16 * i);
		v = V4XOR(V4XOR(W, BRC_X[3]), v);
		V4STOREU(C + 16 * i, v);
	}
}


/***************************************************************************

The ZUC-256 keystream based MAC generation algorithm

***************************************************************************/

///////////////////////////////////////////////////////////////////////////////////////////////////////
//reverse the bit order of a word
__m512i Word_Reverse(__m512i r)
{
	__m512i t;

	t = V4XOR(V4AND(V4SLL(r, 1), left_1bit_mask ), V4AND(V4SRL(r, 1), right_1bit_mask ));
	t = V4XOR(V4AND(V4SLL(t, 2), left_2bits_mask), V4AND(V4SRL(t, 2), right_2bits_mask));
	t = V4XOR(V4AND(V4SLL(t, 4), left_4bits_mask), V4AND(V4SRL(t, 4), right_4bits_mask));
	t = V4XOR(V4AND(V4SLL(t, 8), left_8bits_mask), V4AND(V4SRL(t, 8), right_8bits_mask));

	return V4XOR(V4SLL(t, 16), V4SRL(t, 16));
}

//======================================================
//=| Function : ZUC256_MAC_AVX512
//=| ----------------- output ------------------
//=| C				: output 16 lane MAC(MAC_BITLEN*16 bits)
//=| ------------------ input -------------------
//=| MAC_BITLEN		: bit length of each lane MAC(32 bits)[three optional lengths:32, 64 and 128 ]
//=| IK				: input key(256*16 bits)
//=| IV				: Initialization vector (184*16 bits)
//=| M				: input 16 lane messages(LENGTH*16 words, NOTE: the unit of M is word, not byte)
//=| LENGTH 		: word length of each lane message(32 bits)
//======================================================
void ZUC256_MAC_AVX512(u32 *MAC, int MAC_BITLEN, const u8 *IK, const u8 *IV, const u32 *M, const u32 LENGTH)
{
	__m512i W, W1, W2, u, v, a, b, f;
	__m128i s[8], r[8], t;
	__m256i z[2];
	__m512i *vecz, t0, t1;
	__m512i tmp[4], temp[4] = { 0 };
	ZUC256_AVX512_State state;
	__m512i *LFSR_S = state.LFSR_S, *F_R = state.F_R, *BRC_X = state.BRC_X;
	u32 d_index = (MAC_BITLEN >> 6) << 4, MAC_WORDLEN = MAC_BITLEN >> 5, L = LENGTH + 2 * MAC_WORDLEN;
	u32 i, j, k;

	vecz = (__m512i*)malloc(L * sizeof(__m512i));

	ZUC256_Setup_AVX512();
	ZUC256_LFSRINIT_AVX512(&state, IK, IV, EK_d_MAC + d_index);

	for (i = 0; i < 32; i++)
	{
		V_BITR();
		V_FSM();
		V_FEEDBACK(f, v);
		f = V4ADD(f, V4SRL(W, 1));
		f = AMR(f);
		V_SHIFT();
	}

	V_BITR();
	V_FSM();

	for (i = 0; i < L; i++)
	{
		V_FEEDBACK(f, v);
		V_SHIFT();
		V_BITR();
		V_FSM();
		vecz[i] = V4XOR(W, BRC_X[3]);
	}

	for (i = 0; i < LENGTH; i++)
	{
		t0 = Word_Reverse(V4LOADU(M + 16 * i));

		z[0] = _mm512_castsi512_si256(t0);
		z[1] = _mm512_extracti32x8_epi32(t0, 1);
		t0 = _mm512_cvtepu32_epi64(z[0]);
		t1 = _mm512_cvtepu32_epi64(z[1]);
		r[0] = _mm512_castsi512_si128(t0);
		r[1] = _mm512_extracti32x4_epi32(t0, 1);
		r[2] = _mm512_extracti32x4_epi32(t0, 2);
		r[3] = _mm512_extracti32x4_epi32(t0, 3);
		r[4] = _mm512_castsi512_si128(t1);
		r[5] = _mm512_extracti32x4_epi32(t1, 1);
		r[6] = _mm512_extracti32x4_epi32(t1, 2);
		r[7] = _mm512_extracti32x4_epi32(t1, 3);

		for (j = 0; j < MAC_WORDLEN; j++)
		{
			t0 = _mm512_unpacklo_epi32(vecz[i + j + MAC_WORDLEN + 1], vecz[i + j + MAC_WORDLEN]);
			t1 = _mm512_unpackhi_epi32(vecz[i + j + MAC_WORDLEN + 1], vecz[i + j + MAC_WORDLEN]);
			s[0] = _mm512_castsi512_si128(t0);
			s[1] = _mm512_castsi512_si128(t1);
			s[2] = _mm512_extracti32x4_epi32(t0, 1);
			s[3] = _mm512_extracti32x4_epi32(t1, 1);
			s[4] = _mm512_extracti32x4_epi32(t0, 2);
			s[5] = _mm512_extracti32x4_epi32(t1, 2);
			s[6] = _mm512_extracti32x4_epi32(t0, 3);
			s[7] = _mm512_extracti32x4_epi32(t1, 3);
			for (k = 0; k < 8; k++)
			{
				t = _mm_clmulepi64_si128(s[k], r[k], 0x00);
				tmp[j].m512i_u32[2 * k] = t.m128i_u32[1];
				t = _mm_clmulepi64_si128(s[k], r[k], 0x11);
				tmp[j].m512i_u32[2 * k + 1] = t.m128i_u32[1];
			}
			tmp[j] = V4XOR(tmp[j], temp[j]);
			temp[j] = tmp[j];
		}
	}

	for (i = 0; i < MAC_WORDLEN; i++)
	{
		tmp[i] = V4XOR(V4XOR(vecz[i], tmp[i]), vecz[LENGTH + MAC_WORDLEN + i]);
		V4STOREU(MAC + 16 * i, tmp[i]);
	}
	free(vecz);
}
