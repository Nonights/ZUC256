#ifndef _ZUC256_AVX512_H_H_
#define _ZUC256_AVX512_H_H_

#include <immintrin.h>
typedef unsigned char u8;
typedef unsigned int u32;

//======================================================
//=| Function : ZUC256_AVX512
//=| ----------------- output ------------------
//=| ks				: output 16 lane keystreams(wordlen*16 words)
//=| ------------------ input -------------------
//=| wordlen		: word length of each lane ks(32 bits)
//=| k				: key (256*16 bits)
//=| iv				: Initialization vector (184*16 bits)
//======================================================
void ZUC256_AVX512(u32* ks, int wordlen, const u8* k, const u8* iv);

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
void ZUC256_CRYPT_AVX512(u32* C, const u8* CK, const u8 * IV, const u32* M, int LENGTH);

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
void ZUC256_MAC_AVX512(u32 *MAC, int MAC_BITLEN, const u8 *IK, const u8 *IV, const u32 *M, const u32 LENGTH);

#endif
