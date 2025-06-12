#ifndef AES256_H__
#define AES256_H__

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define NB 4
#define NK 8
#define NR (NK + 6)

#define W32 0
#define W8 1

typedef struct {
	union {
		uint32_t w32[NK];
		uint8_t w8[NK * 4];
	};
} aes256_cipher_key_t;

typedef struct {
	union {
		uint32_t w32[NB];
		uint8_t w8[NB * 4];
	};
} aes256_block_t;

typedef aes256_block_t aes256_state_t;

typedef struct {
	union {
		uint32_t w32[NB * (NR + 1)];
		uint8_t w8[NB * (NR + 1) * 4];
	};
} aes256_key_schedule_t;

typedef struct {
	
} aes256_context_t;

#endif // AES256_H__