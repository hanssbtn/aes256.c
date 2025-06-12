#include "../include/aes256.h"
#include <immintrin.h>

#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)
#define SWAP32(x) __builtin_bswap32(x)
#elif defined(__MSC_VER__)
#define SWAP32(x) _byteswap_ulong(x)
#else
#define SWAP32(x) (((x) >> 24) | ((((x) >> 16) & 0xFF) << 8) | ((((x) >> 8) & 0xFF) << 16) | (((x) & 0xFF) << 24))
#endif // __GNUC__
#else
#define SWAP32(x) (x)
#endif // __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#else 
#define SWAP32(x) (((x) >> 24) | ((((x) >> 16) & 0xFF) << 8) | ((((x) >> 8) & 0xFF) << 16) | (((x) & 0xFF) << 24))
#endif // __BYTE_ORDER__

#define BYTE_READ(x, n) (((x) >> (8 * (n))) & 0xFF)
#define BYTE_SHIFT(b, n) ((b) << (8 * (n)))


uint32_t rot_word(uint32_t word) {
	printf("%08X\t", (word >> 24) | ((word & 0x00FFFFFF) << 8));
	return (word >> 24) | ((word & 0x00FFFFFF) << 8);
}

const uint8_t const SBOX[16 * 16] = {
	/** R/C     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
	/** 0 */  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	/** 1 */  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	/** 2 */  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	/** 3 */  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	/** 4 */  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	/** 5 */  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	/** 6 */  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	/** 7 */  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	/** 8 */  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	/** 9 */  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	/** A */  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	/** B */  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	/** C */  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	/** D */  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	/** E */  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	/** F */  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uint32_t RCON[] = {
	0x00000000, 0x01000000, 0x02000000, 0x04000000, 
	0x08000000, 0x10000000, 0x20000000, 0x40000000, 
	0x80000000, 0x1B000000, 0x36000000,
};

#ifndef MANUAL_CALCULATION

const uint8_t INV[] = {
	  0,   1, 141, 246, 203,  82, 123, 209, 232,  79,  41, 192, 176, 225, 229, 199, 
	116, 180, 170,  75, 153,  43,  96,  95,  88,  63, 253, 204, 255,  64, 238, 178, 
	 58, 110,  90, 241,  85,  77, 168, 201, 193,  10, 152,  21,  48,  68, 162, 194, 
	 44,  69, 146, 108, 243,  57, 102,  66, 242,  53,  32, 111, 119, 187,  89,  25, 
	 29, 254,  55, 103,  45,  49, 245, 105, 167, 100, 171,  19,  84,  37,  233,  9, 
	237,  92,   5, 202,  76,  36, 135, 191,  24,  62,  34, 240,  81, 236,  97,  23, 
	 22,  94, 175, 211,  73, 166,  54,  67, 244,  71, 145, 223,  51, 147,  33,  59, 
	121, 183, 151, 133,  16, 181, 186,  60, 182, 112, 208,   6, 161, 250, 129, 130, 
	131, 126, 127, 128, 150, 115, 190,  86, 155, 158, 149, 217, 247,   2, 185, 164, 
	222, 106,  50, 109, 216, 138, 132, 114,  42,  20, 159, 136, 249, 220, 137, 154, 
	251, 124,  46, 195, 143, 184, 101,  72,  38, 200,  18,  74, 206, 231, 210,  98, 
	 12, 224,  31, 239,  17, 117, 120, 113, 165, 142, 118,  61, 189, 188, 134,  87, 
	 11,  40,  47, 163, 218, 212, 228,  15, 169,  39,  83,   4,  27, 252, 172, 230, 
	122,   7, 174,  99, 197, 219, 226, 234, 148, 139, 196, 213, 157, 248, 144, 107, 
	177,  13, 214, 235, 198,  14, 207, 173,   8,  78, 215, 227,  93,  80,  30, 179, 
	 91,  35,  56,  52, 104,  70,   3, 140, 221, 156, 125, 160, 205,  26,  65,  28 
};

#endif
/**
 *    
 * -----------------------------       -----------------------------       ---------------------------------
 * | in0  | in4  | in8  | in12 | <---> | s0,0 | s0,1 | s0,2 | s0,3 | <---> | out0  | out4  | out8  | out12 |
 * -----------------------------       -----------------------------       ---------------------------------
 * | in1  | in5  | in9  | in13 | <---> | s1,0 | s1,1 | s1,2 | s1,3 | <---> | out1  | out5  | out9  | out13 |
 * -----------------------------       -----------------------------       ---------------------------------
 * | in2  | in6  | in10 | in14 | <---> | s2,0 | s2,1 | s2,2 | s2,3 | <---> | out2  | out6  | out10 | out14 |
 * -----------------------------       -----------------------------       ---------------------------------
 * | in3  | in7  | in11 | in15 | <---> | s3,0 | s3,1 | s3,2 | s3,3 | <---> | out3  | out7  | out11 | out15 |
 * -----------------------------       -----------------------------       ---------------------------------
 */

inline void insert_block(aes256_state_t *state, const aes256_block_t *const in) {
	for (int32_t r = 0; r < 4; ++r) {
		for (int32_t c = 0; c < NB; ++c) {
			state->w8[4 * r + c] = in->w8[r + 4 *c];
		}
	}
}

inline void extract_block(const aes256_state_t *const state, aes256_block_t *out) {
	for (int32_t r = 0; r < 4; ++r) {
		for (int32_t c = 0; c < NB; ++c) {
			out->w8[r + 4 * c] = state->w8[4 * r + c];
		}
	}
}

inline uint8_t gf256_dot(uint8_t a, uint8_t b) {
	uint8_t c = 0;
	while (b > 0) {
		if (b & 1) c ^= a;
		bool overflow = a & 0x80;
		a <<= 1;
		if (overflow) a ^= 0x1B;
		b >>= 1;
	}
	return c;
}

inline uint32_t gf256_cross(uint32_t b) {
	uint32_t a = 0x03010102;
	uint32_t d = 0;
	for (int32_t i = 3; i >= 0; --i) {
		d |= BYTE_SHIFT(
				gf256_dot(BYTE_READ(a, 3), BYTE_READ(b, 0)) 
				^ gf256_dot(BYTE_READ(a, 2), BYTE_READ(b, 1)) 
				^ gf256_dot(BYTE_READ(a, 1), BYTE_READ(b, 2)) 
				^ gf256_dot(BYTE_READ(a, 0), BYTE_READ(b, 3)), 
			i);
		a = rot_word(a);
	}
	return d;
}

#ifdef MANUAL_CALCULATION

uint32_t gf256_mul(uint32_t a, uint32_t b) {
	uint32_t c = 0;
	while (b > 0) {
		if (b & 1) c ^= a;
		b >>= 1;
		a <<= 1;
	}
	return c;
}

uint32_t gf256_div(uint32_t num, uint32_t den) {
	if (num == 0 || num < den) return 0;
	uint32_t res = 0;
	int32_t deg = __builtin_clz(den);
	while (num && 31 - __builtin_clz(num) >= 31 - deg) {
		uint32_t s = (31 - __builtin_clz(num)) - (31 - deg);
		res |= 1 << s;
		num ^= den << s;
	}
	return res;
}

#endif // MANUAL_CALCULATION

uint8_t gf256_inverse(uint8_t b){
	#ifndef MANUAL_CALCULATION
	return INV[b];
	#else
	if (!b) return 0;
	uint32_t t = 0, t_new = 1, r = 0x11BULL, r_new = b;
	while (r_new != 0) {
		uint32_t q = gf256_div(r, r_new);
		uint32_t tmp = t;
		t = t_new;
		t_new = tmp ^ gf256_mul(t_new, q);
		tmp = r;
		r = r_new;
		r_new = tmp ^ gf256_mul(r_new, q);
	}
	return (uint8_t)t;
	#endif // MANUAL_CALCULATION
}

uint32_t sub_words(uint32_t word) {
	uint32_t res = 0;
	for (int32_t c = 0; c < NB; ++c) {
		res |= BYTE_SHIFT(SBOX[BYTE_READ(word, c)], c);
	}
	printf("%08X\t", res);
	return res;
}

void sub_bytes(aes256_state_t *state) {
	for (int32_t r = 0; r < 4; ++r) {
		for (int32_t c = 0; c < NB; ++c) {
			state->w8[4 * r + c] = SBOX[state->w8[4 * r + c]];
		}
	}
}

void shift_rows(aes256_state_t *state) {
	state->w32[1] = (state->w32[1] >> 24) | (state->w32[1] <<  8);
	state->w32[2] = (state->w32[2] >> 16) | (state->w32[2] << 16);
	state->w32[3] = (state->w32[3] >>  8) | (state->w32[3] << 24);
}

void mix_columns(aes256_state_t *state) {
	for (int32_t c = 0; c < NB; ++c) {
		uint32_t s = 0;
		for (int32_t r = 0; r < 4; ++r) {
			s |= BYTE_SHIFT(state->w8[4 * r + c], r); 
		}
		s = gf256_cross(s);
		for (int32_t r = 0; r < 4; ++r) {
			state->w8[4 * r + c] = BYTE_READ(s, r); 
		}
	}
}

void add_round_key(aes256_state_t *state, aes256_key_schedule_t *w, int32_t l) {
	for (int32_t c = 0; c < NB; ++c) {
		for (int32_t r = 0; r < 4; ++r) {
			state->w8[4 * r + c] ^= w->w8[l + 4 * r];
		}
	}
}

void key_expansion(aes256_key_schedule_t *w, const aes256_cipher_key_t *const key) {
	uint32_t tmp = 0;
	int32_t i;
	for (i = 0; i < NK; ++i) {
		w->w32[i] = SWAP32(key->w32[i]);
	}
	for (; i < (NR + 1) * NB; ++i) {
		tmp = w->w32[i - 1];
		printf("%d\t", i);
		printf("%08X\t", tmp);
		if (i % NK == 0) {
			tmp = sub_words(rot_word(tmp)) ^ RCON[i / NK];
			printf("%08X\t", RCON[i / NK]);
			printf("%08X\t", tmp);
		} else if (i % NK == 4) {
			printf("\t\t\t");
			tmp = sub_words(tmp);
			printf("\t\t\t\t\t\t");
		} else {
			printf("\t\t\t\t\t\t\t\t\t\t\t\t");
		}
		printf("%08X\t", w->w32[i - NK]);
		w->w32[i] = w->w32[i - NK] ^ tmp;
		printf("%08X\n", w->w32[i]);
	}
}

void aes256_cipher(aes256_block_t *out, const aes256_block_t *const in, const aes256_cipher_key_t *const key) {
	aes256_key_schedule_t w = {};
	key_expansion(&w, key);
	aes256_state_t state;
	insert_block(&state, in);
	add_round_key(&state, &w, 0);
	int32_t round;
	for (round = 1; round < NR; ++round) {
		sub_bytes(&state);
		shift_rows(&state);
		mix_columns(&state);
		add_round_key(&state, &w, round);
	}
	sub_bytes(&state);
	shift_rows(&state);
	add_round_key(&state, &w, NR);
	extract_block(&state, out);
}

int32_t main(void) {
	aes256_cipher_key_t key = {
		.w32 = {
			0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
			0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4,
		}
	};
	for (int32_t i = 0; i < NK; ++i) {
		key.w32[i] = SWAP32(key.w32[i]);
	}
	aes256_key_schedule_t key_schedule = {};
	key_expansion(&key_schedule, &key);
	return 0;
}