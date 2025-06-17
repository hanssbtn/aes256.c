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

typedef enum {
	// Prints words in hex in big endian notation
	W32_BIG,
	// Prints words in hex in little endian notation
	W32_LITTLE,
	// Prints bytes in hex in big endian notation
	W8_BIG,
	// Prints bytes in hex in little endian notation
	W8_LITTLE
} aes256_block_format_t;

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
	bool big_endian;
	struct {
		ssize_t length, size;
		uint8_t *buf;
	} out;
	aes256_block_t in;
	aes256_cipher_key_t key;
} aes256_context_t;

int32_t aes256_ctx_init(aes256_context_t *ctx, const uint8_t key[NK * 4], bool BIG_ENDIAN);
int32_t aes256_ctx_encrypt_digest(aes256_context_t *ctx, const uint8_t *plaintext, const ssize_t plaintext_length);
int32_t aes256_ctx_decrypt_digest(aes256_context_t *ctx, const uint8_t *ciphertext, const ssize_t ciphertext_length);
int32_t aes256_ctx_finalize(aes256_context_t *ctx, uint8_t *buf, const ssize_t buf_length);

#endif // AES256_H__