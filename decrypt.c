#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "saes.h"

int main(int argc, char **argv)
{
	if(argc == 1 || argc > 3)
	{
		printf("[!] Usage : %s k [sk]\n", argv[0]);
		return(-1);
	}
	else
	{
		char salt[4] = {'s', 'a', 'l', 't'};
		char buffer[1024] = {0x92, 0xbc, 0x46, 0x60, 0x5c, 0x59, 0xe2, 0xfc, 0x74, 0x33, 0x42, 0x11, 0x13, 0xcb, 0x13, 0x46};
		uint8_t k[16], sk[16];
		AES_parameters *params = malloc(sizeof(AES_parameters));
		if(argc == 2)
		{
			PKCS5_PBKDF2_HMAC_SHA1(argv[1], strlen(argv[1]), salt, 4, 1000, 16, k);
			AES_set_parameters(params, k, NULL);
		}
		if(argc == 3)
		{
			PKCS5_PBKDF2_HMAC_SHA1(argv[2], strlen(argv[2]), salt, 4, 1000, 16, sk);
			AES_set_parameters(params, k, sk);
		}
		printf("Input to decrypt :\n");
		scanf("%[^\n]", buffer);
		pkcs7_padding(buffer);
		uint8_t *ciphertext = &buffer[0];
		uint8_t *plaintext = malloc(strlen(buffer));
		AES_ECB_decrypt(params, ciphertext, plaintext, strlen(buffer));

		printf("Ciphertext: ");
		for(int i = 0; i < strlen(buffer); i++)
		{
			printf("%.2x ", ciphertext[i]);
		}
		printf("\n");

		printf("Plaintext: ");
		for(int i = 0; i < strlen(buffer); i++)
		{
			printf("%.2x ", plaintext[i]);
		}
		printf("\n");
	}
	return(0);
}