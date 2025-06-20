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
		uint64_t w64[NK / 2];
		uint32_t w32[NK];
		uint8_t w8[NK * 4];
	};
} aes256_cipher_key_t;

typedef struct {
	union {
		uint64_t w64[NB / 2];
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
	struct {
		ssize_t length, size;
		uint8_t *buf;
	} out;
	aes256_key_schedule_t key_schedule;
	aes256_block_t in;
} aes256_context_t;

typedef enum {
	AES256_BYTE_ORDER_W8,
	AES256_BYTE_ORDER_W32,
	AES256_BYTE_ORDER_W64
} __attribute__((packed)) aes256_byte_order_t;

int32_t aes256_ctx_init(aes256_context_t *ctx, const uint8_t key[NK * 4], const bool BIG_ENDIAN);
int32_t aes256_ctx_set_key(aes256_context_t *ctx, const uint8_t key[NK * 4], const bool BIG_ENDIAN);
void aes256_block_printf(const aes256_block_t *const block, const uint8_t format);
int32_t aes256_byte_order_swap(uint8_t *buf, const uint32_t buf_length, const aes256_byte_order_t from, const aes256_byte_order_t to);
void aes256_key_printf(const aes256_cipher_key_t *const key, const uint8_t format);
void aes256_key_schedule_printf(const aes256_key_schedule_t *const w, const bool BIG_ENDIAN);

/// @brief Encrypts plaintext (assumes big endian ordering).
/// @param ctx AES256 context
/// @param plaintext plaintext to encrypt
/// @param plaintext_length length of plaintext
/// @return 0 if encryption is successful. non-zero error code otherwise.
int32_t aes256_ctx_encrypt_digest(aes256_context_t *ctx, const uint8_t *plaintext, const ssize_t plaintext_length);

/// @brief Decrypts ciphertext (assumes big endian ordering).
/// @param ctx AES256 context
/// @param ciphertext ciphertext to encrypt
/// @param ciphertext_length length of ciphertext
/// @return 0 if decryption is successful. non-zero error code otherwise.
int32_t aes256_ctx_decrypt_digest(aes256_context_t *ctx, const uint8_t *ciphertext, const ssize_t ciphertext_length);

/// @brief Copies encryption/decryption result to buffer
/// @param ctx AES256 context 
/// @param out buffer to copy result to
/// @param out_length length of buffer
/// @return 0 if copy is successful. non-zero error code otherwise.
int32_t aes256_ctx_finalize(aes256_context_t *ctx, uint8_t *out, const ssize_t buf_length);
int32_t aes256_ctx_free(aes256_context_t *ctx);
#endif // AES256_H__