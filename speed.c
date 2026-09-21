#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <time.h>
#include "saes.h"

int main(int argc, char **argv)
{
	uint8_t buf[4096];
	uint8_t k[16], sk[16];
	uint8_t out[4096], cln[4096];
	int outlen = 4096;
	double enc_saes = 10000 * 10000, enc_openssl_aes = 10000 * 10000;
	double dec_saes = 10000 * 10000, dec_openssl_aes = 10000 * 10000;
	double elapsed;
	struct timespec begin, end;
	AES_parameters *params = malloc(sizeof(AES_parameters));
	EVP_CIPHER_CTX *ctx;

	RAND_bytes(buf, 4096);
	for(int i = 0; i < 100000; i++)
	{
		RAND_bytes(k, 16);
		RAND_bytes(sk, 16);

		// SAES
		AES_set_parameters(params, k, sk);
		clock_gettime(CLOCK_REALTIME, &begin);
		AES_ECB_encrypt(params, buf, out, 4096);
		clock_gettime(CLOCK_REALTIME, &end);
		elapsed = (end.tv_sec - begin.tv_sec) * 1e9 + (end.tv_nsec - begin.tv_nsec);
		if(elapsed < enc_saes)
		{
			enc_saes = elapsed;
		}
		clock_gettime(CLOCK_REALTIME, &begin);
		AES_ECB_decrypt(params, out, cln, 4096);
		clock_gettime(CLOCK_REALTIME, &end);
		elapsed = (end.tv_sec - begin.tv_sec) * 1e9 + (end.tv_nsec - begin.tv_nsec);
		if(elapsed < dec_saes)
		{
			dec_saes = elapsed;
		}

		// OpenSSL AES
		ctx = EVP_CIPHER_CTX_new();
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL);
		clock_gettime(CLOCK_REALTIME, &begin);
		EVP_EncryptUpdate(ctx, out, &outlen, buf, 4096);
		clock_gettime(CLOCK_REALTIME, &end);
		elapsed = (end.tv_sec - begin.tv_sec) * 1e9 + (end.tv_nsec - begin.tv_nsec);
		if(elapsed < enc_openssl_aes)
		{
			enc_openssl_aes = elapsed;
		}
		EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, k, NULL);
		clock_gettime(CLOCK_REALTIME, &begin);
		EVP_DecryptUpdate(ctx, cln, &outlen, out, 4096);
		clock_gettime(CLOCK_REALTIME, &end);
		elapsed = (end.tv_sec - begin.tv_sec) * 1e9 + (end.tv_nsec - begin.tv_nsec);
		if(elapsed < dec_openssl_aes)
		{
			dec_openssl_aes = elapsed;
		}
	}
	free(params);
	printf("SAES: %.1f (enc) %.1f (dec)\nOpenSSL AES: %.1f (enc) %.1f (dec)\n", enc_saes, dec_saes, enc_openssl_aes, dec_openssl_aes);
	return(0);
}