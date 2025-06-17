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

const uint8_t SBOX[16 * 16] = {
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

const uint8_t SBOX_INV[16 * 16] = {
	/** R/C     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
	/** 0 */  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	/** 1 */  0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	/** 2 */  0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	/** 3 */  0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	/** 4 */  0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	/** 5 */  0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	/** 6 */  0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	/** 7 */  0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	/** 8 */  0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	/** 9 */  0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	/** A */  0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	/** B */  0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	/** C */  0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	/** D */  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	/** E */  0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	/** F */  0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const uint32_t RCON[] = {
	0x00000000, 0x01000000, 0x02000000, 0x04000000, 
	0x08000000, 0x10000000, 0x20000000, 0x40000000, 
	0x80000000, 0x1B000000, 0x36000000,
};

void print_byte_array(const uint8_t *const arr, const ssize_t arr_len) {
	for (ssize_t i = 0; i < arr_len; ++i) {
		printf("%02X ", arr[i]);
	}
	printf("\n");
}

#if 0
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

#endif // MANUAL_CALCULATION

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

static inline void insert_block(aes256_state_t *state, const aes256_block_t *const in, const bool BIG_ENDIAN) {
	for (int32_t r = 0; r < NB; ++r) {
		state->w32[r] = BIG_ENDIAN ? SWAP32(in->w32[r]) : in->w32[r];
	}
}

#if 0
static inline void extract_block(const aes256_state_t *const state, aes256_block_t *out) {
	for (int32_t r = 0; r < NB; ++r) {
		out->w32[r] = state->w32[r];
	}
}
#endif

static inline uint8_t gf256_dot(uint8_t a, uint8_t b) {
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

static inline uint32_t gf256_cross(uint32_t b, bool inv) {
	uint32_t d = 0;
	uint32_t a = inv ? 0x0E090D0B : 0x02010103;
	for (int32_t i = 0; i < 4; ++i) {
		d |= BYTE_SHIFT(
			gf256_dot(BYTE_READ(a, 3), BYTE_READ(b, 0)) 
			^ gf256_dot(BYTE_READ(a, 2), BYTE_READ(b, 1)) 
			^ gf256_dot(BYTE_READ(a, 1), BYTE_READ(b, 2)) 
			^ gf256_dot(BYTE_READ(a, 0), BYTE_READ(b, 3)), 
			i);
		a = _rotr(a, 8);
	}
	return d;
}

uint32_t sub_words(uint32_t word) {
	uint32_t res = 0;
	for (int32_t c = 0; c < NB; ++c) {
		res |= BYTE_SHIFT(SBOX[BYTE_READ(word, c)], c);
	}
	return res;
}

void sub_bytes(aes256_state_t *state) {
	for (int32_t r = 0; r < NB; ++r) {
		for (int32_t c = 0; c < 4; ++c) {
			state->w8[4 * r + c] = SBOX[state->w8[4 * r + c]];
		}
	}
}

void inv_sub_bytes(aes256_state_t *state) {
	for (int32_t r = 0; r < NB; ++r) {
		for (int32_t c = 0; c < 4; ++c) {
			state->w8[4 * r + c] = SBOX_INV[state->w8[4 * r + c]];
		}
	}
}

void shift_rows(aes256_state_t *state) {
	uint32_t mask = 0x00FF0000;
	for (int32_t offset = 1; offset < 4; ++offset) {
		uint32_t tmp[] = {state->w32[0] & mask, state->w32[1] & mask, state->w32[2] & mask, state->w32[3] & mask};
		for (int32_t i = 0; i < 4; ++i) {
			state->w32[i] = (state->w32[i] & ~mask) | tmp[(i + offset) % 4];
		}
		mask >>= 8;
	}
}

void inv_shift_rows(aes256_state_t *state) {
	uint32_t mask = 0x000000FF;
	for (int32_t offset = 1; offset < 4; ++offset) {
		uint32_t tmp[] = {state->w32[0] & mask, state->w32[1] & mask, state->w32[2] & mask, state->w32[3] & mask};
		for (int32_t i = 0; i < 4; ++i) {
			state->w32[i] = (state->w32[i] & ~mask) | tmp[(i + offset) % 4];
		}
		mask <<= 8;
	}
}

void mix_columns(aes256_state_t *state, bool inv) {
	for (int32_t r = 0; r < NB; ++r) {
		state->w32[r] = gf256_cross(state->w32[r], inv);
	}
}

void add_round_key(aes256_state_t *state, aes256_key_schedule_t *w, int32_t l) {
	for (int32_t c = 0; c < NB; ++c) {
		state->w32[c] ^= w->w32[4 * l + c];
	}
}

void key_expansion(aes256_key_schedule_t *w, const aes256_cipher_key_t *const key, bool BIG_ENDIAN) {
	uint32_t tmp = 0;
	int32_t i;
	for (i = 0; i < NK; ++i) {
		w->w32[i] = BIG_ENDIAN ? SWAP32(key->w32[i]) : key->w32[i];
	}
	for (; i < (NR + 1) * NB; ++i) {
		tmp = w->w32[i - 1];
		printf("%d\t", i);
		printf("%08X\t", tmp);
		if (i % NK == 0) {
			printf("%08X\t", _rotl(tmp, 8));
			printf("%08X\t", sub_words(_rotl(tmp, 8)));
			tmp = sub_words(_rotl(tmp, 8)) ^ RCON[i / NK];
			printf("%08X\t", RCON[i / NK]);
			printf("%08X\t", tmp);
		} else if (i % NK == 4) {
			printf("\t\t\t");
			tmp = sub_words(tmp);
			printf("%08X\t", tmp);
			printf("\t\t\t\t\t\t");
		} else {
			printf("\t\t\t\t\t\t\t\t\t\t\t\t");
		}
		printf("%08X\t", (w->w32[i - NK]));
		w->w32[i] = w->w32[i - NK] ^ tmp;
		printf("%08X\n", (w->w32[i]));
	}
}

void aes256_block_printf(const aes256_block_t *const block, const uint8_t format) {
	switch (format) {
		case W32_BIG: {
			for (int32_t i = 0; i < NB; ++i) {
				printf("%08X\n", block->w32[i]);
			}
		} break;
		case W32_LITTLE: {
			for (int32_t i = 0; i < NB; ++i) {
				printf("%08X\n", SWAP32(block->w32[i]));
			}
		} break;
		case W8_BIG: {
			for (int32_t i = 0; i < NB * 4; i += 4) {
				printf("%02X %02X %02X %02X\n", block->w8[i], block->w8[i + 1], block->w8[i + 2], block->w8[i + 3]);
			}
		} break;
		case W8_LITTLE: {
			for (int32_t i = 0; i < NB * 4; i += 4) {
				printf("%02X %02X %02X %02X\n", block->w8[i + 3], block->w8[i + 2], block->w8[i + 1], block->w8[i]);
			}
		} break;
		default:
			break;
	}
}

void aes256_key_printf(const aes256_cipher_key_t *const key, const uint8_t format) {
	switch (format) {
		case W32_BIG: {
			for (int32_t i = 0; i < NK; ++i) {
				printf("%08X\n", key->w32[i]);
			}
		} break;
		case W32_LITTLE: {
			for (int32_t i = 0; i < NK; ++i) {
				printf("%08X\n", SWAP32(key->w32[i]));
			}
		} break;
		case W8_BIG: {
			for (int32_t i = 0; i < NK * 4; i += 4) {
				printf("%02X %02X %02X %02X\n", key->w8[i], key->w8[i + 1], key->w8[i + 2], key->w8[i + 3]);
			}
		} break;
		case W8_LITTLE: {
			for (int32_t i = 0; i < NK * 4; i += 4) {
				printf("%02X %02X %02X %02X\n", key->w8[i + 3], key->w8[i + 2], key->w8[i + 1], key->w8[i]);
			}
		} break;
		default:
			break;
	}
}

void aes256_key_schedule_printf(const aes256_key_schedule_t *const w, const bool BIG_ENDIAN) {
	if (BIG_ENDIAN) {
		for (int32_t k = 0; k < 60; k += 4) {
			printf("[%d] ", k / 4);
			for (int32_t i = 0; i < 4; ++i) {
				printf("%08x", SWAP32(w->w32[k + i]));
			}
			printf("\n");
			printf("[%d] ", k / 4);
			for (int32_t i = 0; i < 16; ++i) {
				printf("%02x ", w->w8[k * 4 + i]);
			}
			printf("\n");
		}
		return;
	} 
	for (int32_t k = 0; k < 60; k += 4) {
		printf("[%d] ", k / 4);
		for (int32_t i = 0; i < 4; ++i) {
			printf("%08x", w->w32[k + i]);
		}
		printf("\n");
		printf("[%d] ", k / 4);
		for (int32_t i = 0; i < 4; ++i) {
			for (int32_t j = 3; j >= 0; --j) {
				printf("%02x ", w->w8[k * 4 + 4 * i + j]);
			}
		}
		printf("\n");
	}
}

int32_t aes256_ctx_append_block(aes256_context_t *ctx, const aes256_block_t *const in) {
	if (ctx->out.length == ctx->out.size) {
		ssize_t nsz = ctx->out.size * 2;
		uint8_t *tmp = (uint8_t*)realloc(ctx->out.buf, sizeof(uint8_t) * nsz);
		if (!tmp) {
			return -2;
		}
		ctx->out.buf = tmp;
		ctx->out.size = nsz;
	}
	memcpy(ctx->out.buf + ctx->out.length, in->w8, sizeof(aes256_block_t));
	ctx->out.length += sizeof(aes256_block_t);
	printf("Result: \n");
	print_byte_array(ctx->out.buf, ctx->out.length);
	return 0;
}

int32_t aes256_ctx_free(aes256_context_t *ctx) {
	if (!ctx) return -1;
	free(ctx->out.buf);
	*ctx = (aes256_context_t){};
	return 0;
}

void aes256_encrypt(aes256_context_t *ctx) {
	aes256_key_schedule_t w = {};
	key_expansion(&w, &ctx->key, ctx->big_endian);
	aes256_key_schedule_printf(&w, ctx->big_endian);
	aes256_state_t state;
	insert_block(&state, &ctx->in, ctx->big_endian);
	printf("input:\n");
	aes256_block_printf(&state, W8_LITTLE);
	aes256_block_printf(&state, W32_BIG);
	add_round_key(&state, &w, 0);
	printf("add_round_key:\n");
	aes256_block_printf(&state, W8_LITTLE);
	int32_t round;
	for (round = 1; round < NR; ++round) {
		printf("ROUND %d\n", round);
		sub_bytes(&state);
		printf("sub_bytes:\n");
		aes256_block_printf(&state, W8_LITTLE);
		shift_rows(&state);
		printf("shift_rows:\n");
		aes256_block_printf(&state, W8_LITTLE);
		mix_columns(&state, false);
		printf("mix_columns:\n");
		aes256_block_printf(&state, W8_LITTLE);
		add_round_key(&state, &w, round);
		printf("add_round_key:\n");
		aes256_block_printf(&state, W8_LITTLE);
	}
	
	sub_bytes(&state);
	printf("sub_bytes:\n");
	aes256_block_printf(&state, W8_LITTLE);
	shift_rows(&state);
	printf("shift_rows:\n");
	aes256_block_printf(&state, W8_LITTLE);
	add_round_key(&state, &w, NR);
	printf("add_round_key:\n");
	aes256_block_printf(&state, W8_LITTLE);

	// extract_block(&state, &ctx->in);
	aes256_ctx_append_block(ctx, &state);
}

void aes256_decrypt(aes256_context_t *ctx) {
	aes256_key_schedule_t w = {};
	key_expansion(&w, &ctx->key, ctx->big_endian);
	aes256_state_t state;
	insert_block(&state, &ctx->in, ctx->big_endian);
	printf("input:\n");
	aes256_block_printf(&state, W8_LITTLE);

	add_round_key(&state, &w, NR);
	printf("add_round_key:\n");
	aes256_block_printf(&state, W8_LITTLE);

	inv_sub_bytes(&state);
	printf("inv_sub_bytes:\n");
	aes256_block_printf(&state, W8_LITTLE);

	inv_shift_rows(&state);
	printf("inv_shift_rows:\n");
	aes256_block_printf(&state, W8_LITTLE);

	int32_t round;
	for (round = NR - 1; round > 0; --round) {
		printf("ROUND %d\n", round);

		add_round_key(&state, &w, round);
		printf("add_round_key:\n");
		aes256_block_printf(&state, W8_LITTLE);
		
		mix_columns(&state, true);
		printf("inv_mix_columns:\n");
		aes256_block_printf(&state, W8_LITTLE);

		inv_sub_bytes(&state);
		printf("inv_sub_bytes:\n");
		aes256_block_printf(&state, W8_LITTLE);
		
		inv_shift_rows(&state);
		printf("inv_shift_rows:\n");
		aes256_block_printf(&state, W8_LITTLE);
	}

	printf("add_round_keys:\n");
	aes256_block_printf(&state, W8_LITTLE);
	add_round_key(&state, &w, 0);

	aes256_ctx_append_block(ctx, &state);
}

int32_t aes256_ctx_init(aes256_context_t *ctx, const uint8_t key[NK * 4], bool BIG_ENDIAN) {
	ctx->big_endian = BIG_ENDIAN;
	ctx->out.buf = (uint8_t*)malloc(sizeof(uint8_t) * 16);
	if (!ctx->out.buf) {
		return -1;
	}
	ctx->out.size = 16;
	ctx->out.length = 0;
	ctx->in = (aes256_block_t){};
	if (BIG_ENDIAN) {
		for (int32_t i = 0; i < NK * 4; i += 4) {
			ctx->key.w32[i / 4] = BYTE_SHIFT(key[i + 3], 0) | BYTE_SHIFT(key[i + 2], 1) | BYTE_SHIFT(key[i + 1], 2) | BYTE_SHIFT(key[i], 3);
		}
	} else {
		for (int32_t i = 0; i < NK * 4; i += 4) {
			ctx->key.w32[i / 4] = BYTE_SHIFT(key[i], 0) | BYTE_SHIFT(key[i + 1], 1) | BYTE_SHIFT(key[i + 2], 2) | BYTE_SHIFT(key[i + 3], 3);
		}
	}
	aes256_key_printf(&ctx->key, W32_BIG);
	aes256_key_printf(&ctx->key, W8_LITTLE);
	return 0;
}

int32_t aes256_ctx_encrypt_digest(aes256_context_t *ctx, const uint8_t *plaintext, const ssize_t plaintext_length) {
	if (!ctx || !plaintext) return -1;
	if (plaintext_length < 0) return 0;
	ssize_t count = plaintext_length / sizeof(aes256_block_t), rem = plaintext_length % sizeof(aes256_block_t);
	for (ssize_t i = 0; i < count; ++i) {
		memcpy(&ctx->in, plaintext, sizeof(aes256_block_t));
		plaintext += sizeof(aes256_block_t);
		aes256_encrypt(ctx);
	}
	if (rem > 0) {
		memcpy(&ctx->in, plaintext, rem);
		memset(&ctx->in + rem, 0, sizeof(aes256_block_t));
		aes256_encrypt(ctx);
	}
	return 0;
}

int32_t aes256_ctx_decrypt_digest(aes256_context_t *ctx, const uint8_t *ciphertext, const ssize_t ciphertext_length) {
	if (!ctx || !ciphertext) return -1;
	if (ciphertext_length < 0) return 0;
	ssize_t count = ciphertext_length / sizeof(aes256_block_t), rem = ciphertext_length % sizeof(aes256_block_t);
	printf("-----------------------------------------------\n");
	print_byte_array(ciphertext, ciphertext_length);
	for (ssize_t i = 0; i < count; ++i) {
		memcpy(&ctx->in, ciphertext, sizeof(aes256_block_t));
		ciphertext += sizeof(aes256_block_t);
		aes256_decrypt(ctx);
	}
	if (rem > 0) {
		memcpy(&ctx->in, ciphertext, rem);
		memset(&ctx->in + rem, 0, sizeof(aes256_block_t));
		aes256_decrypt(ctx);
	}
	return 0;
}

int32_t aes256_ctx_finalize(aes256_context_t *ctx, uint8_t **buf, ssize_t *buf_length) {
	if (!ctx || !buf || !ctx->out.buf || !buf_length) return -1;
	*buf = ctx->out.buf;
	*buf_length = ctx->out.length;
	*ctx = (aes256_context_t){};
	return 0;
}

int32_t main(void) {
	aes256_block_t _plaintext = {
		.w32 = {
			// SWAP32(0x6BC1BEE2), SWAP32(0x2E409F96), SWAP32(0xE93D7E11), SWAP32(0x7393172A)
			0x6BC1BEE2, 0x2E409F96, 0xE93D7E11, 0x7393172A
			// SWAP32(0x00112233), SWAP32(0x44556677), SWAP32(0x8899aabb), SWAP32(0xccddeeff)
			// 0xAE2D8A57, 0x1E03AC9C, 0x9EB76FAC, 0x45AF8E51,
			// 0x30C81C46 0xA35CE411 0xE5FBC119 0x1A0A52EF
			// 0xF69F2445 0xDF4F9B17 0xAD2B417B 0xE66C3710 
		}
	}, _ciphertext = {};
	aes256_cipher_key_t key = {
		// .w8 = {
			// 	0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
			// 	0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
		.w32 = {
			0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
			0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4
			// 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 
			// 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f
		}
	};

	uint8_t plaintext[] = {
		0xE2, 0xBE, 0xC1, 0x6B, 
		0x96, 0x9F, 0x40, 0x2E, 
		0x11, 0x7E, 0x3D, 0xE9, 
		0x2A, 0x17, 0x93, 0x73
	};
	uint8_t *ciphertext = NULL;
	const ssize_t plaintext_length = 16;
	const ssize_t ciphertext_length = 16;
	ssize_t len = 0;
	aes256_context_t ctx;
	aes256_ctx_init(&ctx, key.w8, false);
	
	// aes256_key_schedule_t w = {};
	// key_expansion(&w, &key, false);
	aes256_ctx_encrypt_digest(&ctx, plaintext, plaintext_length);
	aes256_ctx_finalize(&ctx, &ciphertext, &len);
	printf("encrypt:\n");
	print_byte_array(ciphertext, len);
	
	
	aes256_ctx_init(&ctx, key.w8, false);
	aes256_ctx_decrypt_digest(&ctx, ciphertext, len);
	free(ciphertext);
	aes256_ctx_finalize(&ctx, &ciphertext, &len);
	printf("decrypt:\n");
	print_byte_array(ciphertext, len);
	free(ciphertext);

	return 0;
}