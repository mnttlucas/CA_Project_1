all:
	gcc -o encrypt saes.c encrypt.c -maes -lcrypto
	gcc -o decrypt saes.c decrypt.c -maes -lcrypto
	gcc -o speed saes.c speed.c -maes -lcrypto

clean:
	rm -rf *.o encrypt decrypt speed