#ifndef argon2_encoding_H
#define argon2_encoding_H

#include "argon2.h"
#include "private/quirks.h"
#include "crypto_pwhash.h"

/*
 * encode an Argon2 hash string into the provided buffer. 'dst_len'
 * contains the size, in characters, of the 'dst' buffer; if 'dst_len'
 * is less than the number of required characters (including the
 * terminating 0), then this function returns 0.
 *
 * if ctx->outlen is 0, then the hash string will be a salt string
 * (no output). if ctx->saltlen is also 0, then the string will be a
 * parameter-only string (no salt and no output).
 *
 * On success, ARGON2_OK is returned.
 *
 * No other parameters are checked
 */
int argon2_encode_string(char *dst, size_t dst_len, argon2_context *ctx,
                         argon2_type type);

/*
 * Decodes an Argon2 hash string into the provided structure 'ctx'.
 * The fields ctx.saltlen, ctx.adlen, ctx.outlen set the maximal salt, ad, out
 * length values
 * that are allowed; invalid input string causes an error
 *
 * Returned value is ARGON2_OK on success.
 */
int
argon2_decode_string(argon2_context *ctx, const char *str,
                         argon2_type type);

int
argon2_relief_encode_init_str(char *dst, size_t dst_len, argon2_type type,
                                  const unsigned char * salt,
                                  size_t salt_len,
                                  unsigned long long client_opslimit,
                                  size_t client_memlimit);

int
argon2_encode_server_init_str(uint8_t out[crypto_pwhash_argon2id_relief_STRBYTES],
                              uint8_t saltout[crypto_pwhash_argon2id_SALTBYTES],
                              unsigned long long client_opslimit, size_t client_memlimit);

/*
 *
 * TODO
 */
int
argon2_encode_relief_server_str(uint8_t out[crypto_pwhash_argon2id_relief_STRBYTES], const uint8_t *client_str,
                                size_t client_str_len,
                                unsigned char *const server_hash, size_t server_hashlen,
                                uint32_t server_opslimit, uint32_t server_memlimit, uint32_t server_threads,
                                argon2_type type);


int
argon2_relief_decode_init_string(argon2_context *ctx, const char *str, argon2_type type);

#endif
