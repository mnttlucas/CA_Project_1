#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "saes.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

// Debug function
void print128_num(__m128i var)
{
    uint8_t val[16];
    memcpy(val, &var, sizeof(val));
    printf("Numerical: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x \n", 
           val[0], val[1], val[2], val[3], val[4], val[5], 
           val[6], val[7], val[8], val[9], val[10], val[11], val[12], val[13], 
           val[14], val[15]);
}

// https://en.wikipedia.org/wiki/Rijndael_S-box unused, see report
void initialize_aes_sbox(uint8_t *sbox)
{
	uint8_t p = 1, q = 1, xformed;
	do {
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;
		xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
		sbox[p] = xformed ^ 0x63;
	} 
	while (p != 1);
	sbox[0] = 0x63;
}

// Unused
void invert_sbox(uint8_t *src, uint8_t *dest)
{
	for(int i = 0; i < 256; i++)
	{
		dest[src[i]] = (uint8_t) i;
	}
}

void XOR_modified_key(AES_parameters *parameters, uint8_t *sk)
{
	int round = parameters -> modified_round;
	for(int i = 0; i < 16; i++)
	{
		parameters -> modified_key[i] = parameters -> round_keys[round * 16 + i] ^ sk[i % 8 + 8];
	}
}

void shuffle_round_keys(AES_parameters *parameters, uint8_t *sk)
{
	uint8_t permutation[11], tmp, original_keys[11 * 16];
	uint32_t seed = 0;
	int i, j;
	for(i = 0; i < 11; i++)
	{
		permutation[i] = (uint8_t) i;
	}
	for(i = 0; i < 4; i++)
	{
		seed |= (uint32_t) sk[i + 4] << (i * 8);
	}
	for(i = 10; i > 0; i--)
	{
		// https://en.wikipedia.org/wiki/Linear_congruential_generator for these coefficients
		seed = seed * 1664525 + 1013904223;
		j = seed % (i + 1);
		tmp = permutation[i];
		permutation[i] = permutation[j];
		permutation[j] = tmp;
	}
	memcpy(original_keys, parameters -> round_keys, sizeof(original_keys));
	for(i = 0; i < 11; i++)
	{
		for(j = 0; j < 16; j++)
		{
			parameters -> round_keys[i * 16 + j] = original_keys[permutation[i] * 16 + j];
		}
	}
}

// https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
void pkcs7_padding(char *buf)
{
	int buf_size = strlen(buf);
	int pad = 16 - buf_size % 16;
	for(int i = 0; i < pad; i++)
	{
		buf[buf_size + i] = pad;
	}
	buf[buf_size + pad] = '\0';
}

__m128i get_round_key(__m128i key, __m128i index)
{
	__m128i tmp;
	index = _mm_shuffle_epi32(index, 0xFF);
	tmp = _mm_slli_si128(key, 0x04);
	key = _mm_xor_si128(key, tmp);
	tmp = _mm_slli_si128(tmp, 0x04);
	key = _mm_xor_si128(key, tmp);
	tmp = _mm_slli_si128(tmp, 0x04);
	key = _mm_xor_si128(key, tmp);
	key = _mm_xor_si128(key, index);
	return(key);
}

void key_expansion(uint8_t *round_keys, uint8_t *key)
{
	__m128i index, round;
	__m128i *rk = (__m128i *) round_keys;
	round = _mm_loadu_si128((__m128i *) key);
	rk[0] = round;
	index = _mm_aeskeygenassist_si128(round, 0x01);
	round = get_round_key(round, index);
	rk[1] = round;
	index = _mm_aeskeygenassist_si128(round, 0x02);
	round = get_round_key(round, index);
	rk[2] = round;
	index = _mm_aeskeygenassist_si128(round, 0x04);
	round = get_round_key(round, index);
	rk[3] = round;
	index = _mm_aeskeygenassist_si128(round, 0x08);
	round = get_round_key(round, index);
	rk[4] = round;
	index = _mm_aeskeygenassist_si128(round, 0x10);
	round = get_round_key(round, index);
	rk[5] = round;
	index = _mm_aeskeygenassist_si128(round, 0x20);
	round = get_round_key(round, index);
	rk[6] = round;
	index = _mm_aeskeygenassist_si128(round, 0x40);
	round = get_round_key(round, index);
	rk[7] = round;
	index = _mm_aeskeygenassist_si128(round, 0x80);
	round = get_round_key(round, index);
	rk[8] = round;
	index = _mm_aeskeygenassist_si128(round, 0x1B);
	round = get_round_key(round, index);
	rk[9] = round;
	index = _mm_aeskeygenassist_si128(round, 0x36);
	round = get_round_key(round, index);
	rk[10] = round;
}

void AES_set_parameters(AES_parameters *parameters, uint8_t *k, uint8_t *sk)
{
	key_expansion(parameters -> round_keys, k);
	initialize_aes_sbox(parameters -> sbox);
	invert_sbox(parameters -> sbox, parameters -> inverted_sbox);
	parameters -> SAES = 0;
	if(sk)
	{
		parameters -> SAES = 1;
		parameters -> modified_round = (sk[0] ^ sk[1] ^ sk[2] ^ sk[3]) % 9 + 1;
		shuffle_round_keys(parameters, sk);
		XOR_modified_key(parameters, sk);
	}
}

void AES_ECB_encrypt(AES_parameters *parameters, uint8_t *input, uint8_t *output, unsigned long length)
{
	__m128i tmp;
	__m128i mkey = _mm_loadu_si128((__m128i *) parameters -> modified_key);
	int i, j;
	if(length % 16)
	{
		length = length / 16 + 1;
	}
	else
	{
		length = length / 16;
	}
	for(i = 0; i < length; i++)
	{
		tmp = _mm_loadu_si128(&((__m128i *) input)[i]);
		tmp = _mm_xor_si128(tmp, ((__m128i *) parameters -> round_keys)[0]);
		for(j = 1; j < 10; j++)
		{
			if(parameters -> SAES && parameters -> modified_round == j)
			{
				tmp = _mm_aesenc_si128(tmp, mkey);
			}
			else
			{
				tmp = _mm_aesenc_si128(tmp, ((__m128i *) parameters -> round_keys)[j]);
			}
		}
		tmp = _mm_aesenclast_si128(tmp, ((__m128i *) parameters -> round_keys)[10]);
		_mm_storeu_si128(&((__m128i *) output)[i], tmp);
	}
}

void AES_ECB_decrypt(AES_parameters *parameters, uint8_t *input, uint8_t *output, unsigned long length)
{
	__m128i tmp;
	__m128i mkey = _mm_loadu_si128((__m128i *) parameters -> modified_key);
	int i, j;
	if(length % 16)
	{
		length = length / 16 + 1;
	}
	else
	{
		length = length / 16;
	}
	for(i = 0; i < length; i++)
	{
		tmp = _mm_loadu_si128(&((__m128i *) input)[i]);
		tmp = _mm_xor_si128(tmp, ((__m128i *) parameters -> round_keys)[10]);
		for(j = 9; j > 0; j--)
		{
			if(parameters -> SAES && parameters -> modified_round == j)
			{
				tmp = _mm_aesdec_si128(tmp, _mm_aesimc_si128(mkey));
			}
			else
			{
				tmp = _mm_aesdec_si128(tmp, _mm_aesimc_si128(((__m128i *) parameters -> round_keys)[j]));
			}
		}
		tmp = _mm_aesdeclast_si128(tmp, ((__m128i *) parameters -> round_keys)[0]);
		_mm_storeu_si128(&((__m128i *) output)[i], tmp);
	}
}