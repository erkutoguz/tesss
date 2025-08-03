#include "erktpass.h"

void print_64(char b_8[64])
{
	int i;
	i = 0;
	for (; i < 64; ++i) {
		printf("%d", b_8[i]);

		if ((i + 1) % 8 == 0) {
			printf("\n");
		}
	}
}

int main(int argc, char **argv)
{
	char *msg = "midnight";
	char *key = "#s2Rz1./";
	char b_msg[64];
	char b_key[64];
	char k_56[56];
	char ptd_msg[64];
	char l_msg[32];
	char r_msg[32];

	memset(b_msg, 0, 64);

	str_2_bin(msg, b_msg, 64);

	memset(ptd_msg, 0, 64);
	ip(b_msg, ptd_msg);

	printf("Binary Message:\n");
	print_64(b_msg);
	printf("\n");
	printf("Permutated Message:\n");
	print_64(ptd_msg);

	memset(l_msg, 0, 32);
	memset(r_msg, 0, 32);

	split_text(ptd_msg, l_msg, r_msg, 64);

	memset(b_key, 0, 64);
	str_2_bin(key, b_key, 64);

	memset(k_56, 0, 56);
	generate_key_56(b_key, k_56);

	return 0;
}

void str_2_bin(char *msg, char *dest, int size)
{
	int i, iter;
	iter = size / 8;
	i = 0;
	for (; i < iter; ++i) {
		dest[i * 8] = msg[i] >> 7;
		dest[i * 8 + 1] = (msg[i] >> 6) & 1;
		dest[i * 8 + 2] = (msg[i] >> 5) & 1;
		dest[i * 8 + 3] = (msg[i] >> 4) & 1;
		dest[i * 8 + 4] = (msg[i] >> 3) & 1;
		dest[i * 8 + 5] = (msg[i] >> 2) & 1;
		dest[i * 8 + 6] = (msg[i] >> 1) & 1;
		dest[i * 8 + 7] = msg[i] & 1;
	}
}

void ip(char og[64], char ptd[64])
{
	int i;
	i = 0;
	for (; i < 64; ++i) {
		ptd[i] = og[IP_TABLE[i] - 1];
	}
}

void split_text(char *og, char *l, char *r, int size)
{
	int i, half;
	i = 0;
	half = size / 2;
	for (; i < half; ++i) {
		l[i] = og[i];
		r[half + i] = og[half + i];
	}
}

void generate_key_56(char b_key[64], char key_56[56])
{
	int i, p;
	i = 0;
	p = 0;
	for (; i < 64; ++i) {
		if ((i + 1) % 8 != 0) {
			key_56[p] = b_key[i];
			++p;
		}
	}
}
