#ifndef SAES_H
#define SAES_H

#include <stdint.h>
#include <wmmintrin.h>

typedef struct AES_parameters
{
	uint8_t round_keys[11 * 16];
	uint8_t sbox[16 * 16];
	uint8_t inverted_sbox[16 * 16];

	uint8_t SAES;
	uint8_t modified_round;
	uint8_t modified_key[16];
} AES_parameters;

void XOR_modified_key(AES_parameters *parameters, uint8_t *sk);
void shuffle_round_keys(AES_parameters *parameters, uint8_t *sk);
void pkcs7_padding(char *buf);
__m128i get_round_key(__m128i key, __m128i index);
void key_expansion(uint8_t *round_keys, uint8_t *key);
void AES_set_parameters(AES_parameters *parameters, uint8_t *k, uint8_t *sk);
void AES_ECB_encrypt(AES_parameters *parameters, uint8_t *input, uint8_t *output, unsigned long length);
void AES_ECB_decrypt(AES_parameters *parameters, uint8_t *input, uint8_t *output, unsigned long length);

#endif /* SAES_H */