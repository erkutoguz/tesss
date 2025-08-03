#include "erktpass.h"
#include <stdint.h>

void print_block(char *b, int size)
{
	int i;
	for (i = 0; i < size;) {
		printf("%d", b[i++]);
		if (i % 8 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
}

void print_hx(char *b)
{
	int i;
	uint64_t res;
	res = 0;
	for (i = 0; i < 64; ++i) {
		res <<= 1;
		res |= (b[i] & 1);
	}

	printf("\n%016lX\n", res);
}

int main(int argc, char **argv)
{
	char *text = "IEOFIT#1";
	char *key = "IEOFIT#1";
	char *encrypted;

	DES *des = initialize_des(text, key);

	generate_keys(des);

	encrypted = (char *)malloc(64);
	memset(encrypted, 0, 64);

	print_hx(des->text);
	encrypt(des, encrypted);
	print_hx(encrypted);
	decrypt(des, encrypted);
	print_hx(encrypted);
	
	free(des);
	return 0;
}

DES *initialize_des(char *plain_text, char *plain_key)
{
	DES *des = (DES *)malloc(sizeof(DES));
	char *btext, *bkey, *ptext, *pkey, *l, *r, *l_1, *r_1;

	btext = str_2_b64(plain_text);
	bkey = str_2_b64(plain_key);

	ptext = ip(btext);
	pkey = gen_key56(bkey);

	memcpy(des->text, ptext, 64);
	memcpy(des->key, pkey, 64);

	l_1 = (char *)malloc(32);
	r_1 = (char *)malloc(32);
	memset(l_1, 0, 32);
	memset(r_1, 0, 32);
	split_half(ptext, l_1, r_1, 64);

	memcpy(des->l_1, l_1, 32);
	memcpy(des->r_1, r_1, 32);

	l = (char *)malloc(32);
	r = (char *)malloc(32);

	memset(l, 0, 32);
	memset(r, 0, 32);

	memcpy(des->l, l, 32);
	memcpy(des->r, r, 32);

	return des;
}

char *str_2_b64(char *text)
{
	int i;
	char *b64;
	b64 = (char *)malloc(64);
	memset(b64, 0, 64);

	for (i = 0; i < 8; ++i) {
		b64[i * 8] = text[i] >> 7;
		b64[i * 8 + 1] = (text[i] >> 6) & 1;
		b64[i * 8 + 2] = (text[i] >> 5) & 1;
		b64[i * 8 + 3] = (text[i] >> 4) & 1;
		b64[i * 8 + 4] = (text[i] >> 3) & 1;
		b64[i * 8 + 5] = (text[i] >> 2) & 1;
		b64[i * 8 + 6] = (text[i] >> 1) & 1;
		b64[i * 8 + 7] = text[i] & 1;
	}

	return b64;
}

char *ip(const char *btext)
{
	int i;
	char *ptext;
	ptext = (char *)malloc(64);
	memset(ptext, 0, 64);

	for (i = 0; i < 64; ++i) {
		ptext[i] = btext[IP_TABLE[i] - 1];
	}
	return ptext;
}

char *gen_key56(const char *bkey)
{
	char *pkey;
	int i, p;
	pkey = (char *)malloc(56);
	memset(pkey, 0, 56);
	p = 0;

	for (i = 0; i < 56; ++i) {
		if ((i + 1) % 8 != 0) {
			pkey[p++] = bkey[i];
		}
	}

	return pkey;
}

void split_half(char *src, char *l, char *r, int size)
{
	int i, half;
	half = size / 2;
	for (i = 0; i < half; ++i) {
		l[i] = src[i];
		r[i] = src[i + half];
	}
}

void generate_keys(DES * des){
	int rd;
	char *kl, *kr, *tk, *k48;
	kl = (char *)malloc(28);
	kr = (char *)malloc(28);
	tk = (char *)malloc(56);
	k48 = (char *)malloc(48);

	memset(kl, 0, 28);
	memset(kr, 0, 28);
	memset(tk, 0, 56);
	memset(k48, 0, 48);

	split_half(des->key, kl, kr, 56);

	rd = 0;

	for (; rd < 16; ++rd) {
	if (rd == 0 || rd == 1 || rd == 8 || rd == 15) {
			shift_left(kl, 1);
			shift_left(kr, 1);
		} else {
			shift_left(kl, 2);
			shift_left(kr, 2);
		}
		combine_halves(tk, kl, kr, 56);
		compress_key(k48, tk);
		memcpy(des->k48[rd], k48, 48);
	}
}

void run_des(DES * des, char *dst, int type) {
	int rd;
	rd = 0;

	char *r48, *r32, *t32;

	r48 = (char *)malloc(48);
	r32 = (char *)malloc(32);
	t32 = (char *)malloc(32);

	memset(r48, 0, 48);
	memset(r32, 0, 32);
	memset(t32, 0, 32);


	for (; rd < 16; ++rd) {
		expand(r48, des->r_1);
		xor_wkey(r48, r48, des->k48[type == 1 ? rd : (15 - rd)], 48);
		sbox(r32, r48, rd);
		perm_r32(r32);
		xor_wkey(des->r, r32, des->l_1, 32);
		memcpy(des->l, des->r_1, 32);
		memcpy(des->l_1, des->l, 32);
		memcpy(des->r_1, des->r, 32);
	}

	memcpy(t32, des->l, 32);
	memcpy(des->l, des->r, 32);
	memcpy(des->r, t32, 32);

	combine_halves(dst, des->l, des->r, 64);
	fp(dst);
}

void decrypt(DES * des, char *dst) {
	run_des(des, dst, 0);
}

void encrypt(DES *des, char *dst)
{
	run_des(des, dst, 1);
}

void shift_left(char *block, int sc)
{
	char b1, b2;
	int i, size;
	size = 28;
	if (sc == 1) {
		b1 = block[0];
		for (i = 0; i < size - 1; ++i) {
			block[i] = block[i + 1];
		}
		block[size - 1] = b1;
	} else if (sc == 2) {
		b1 = block[0];
		b2 = block[1];
		for (i = 0; i < size - 2; ++i) {
			block[i] = block[i + 1];
		}
		block[size - 1] = b2;
		block[size - 2] = b1;
	}
}

void combine_halves(char *dst, char *l, char *r, int size)
{
	int i, half;
	half = size / 2;
	for (i = 0; i < half; ++i) {
		dst[i] = l[i];
		dst[i + half] = r[i];
	}
}

void compress_key(char *k48, char *k56)
{
	int i;
	for (i = 0; i < 48; ++i) {
		k48[i] = k56[PC2_TABLE[i] - 1];
	}
}

void expand(char *r48, char *r_1)
{
	int i;
	for (i = 0; i < 48; ++i) {
		r48[i] = r_1[E_TABLE[i] - 1];
	}
}

void xor_wkey(char *dst, char *r, char *k, int size)
{
	int i;
	for (i = 0; i < size; ++i) {
		dst[i] = r[i] ^ k[i];
	}
}

void sbox(char *r32, char *r48, int rd)
{
	int i, r, c, p;
	char rb[2], cb[4];
	char sbx[4][16];
	char *b4;

	b4 = (char *)malloc(4);
	memset(b4, 0, 4);

	memcpy(sbx, S_BOXES[rd], sizeof(char) * 4 * 16);

	p = 0;

	for (i = 0; i < 8; ++i) {
		rb[0] = r48[i * 6];
		rb[1] = r48[i * 6 + 5];
		r = bin_2_int(rb, 2);
		cb[0] = r48[i * 6 + 1];
		cb[1] = r48[i * 6 + 2];
		cb[2] = r48[i * 6 + 3];
		cb[3] = r48[i * 6 + 4];
		c = bin_2_int(cb, 4);

		int_2_bin(sbx[r][c], b4);

		// fill r32
		r32[p] = b4[0];
		r32[p + 1] = b4[1];
		r32[p + 2] = b4[2];
		r32[p + 3] = b4[3];
		p += 4;
	}
}

int bin_2_int(char *bin, int size)
{
	int i, mul, res;
	mul = 1 << (size - 1);
	res = 0;
	for (i = 0; i < size; ++i) {
		res += bin[i] * mul;
		mul /= 2;
	}
	return res;
}

void int_2_bin(int i, char *dst)
{
	dst[0] = (i >> 3) & 1;
	dst[1] = (i >> 2) & 1;
	dst[2] = (i >> 1) & 1;
	dst[3] = i & 1;
}

void perm_r32(char *r32)
{
	int i;
	for (i = 0; i < 32; ++i) {
		r32[i] = r32[P_TABLE[i] - 1];
	}
}

void fp(char *dst)
{
	int i;
	for (i = 0; i < 64; ++i) {
		dst[i] = dst[FP_TABLE[i] - 1];
	}
}
