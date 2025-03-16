#include "argon2-encoding.h"
#include "argon2-core.h"
#include "utils.h"
#include "crypto_pwhash_argon2id.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/*
 * Example code for a decoder and encoder of "hash strings", with Argon2
 * parameters.
 *
 * The code was originally written by Thomas Pornin <pornin@bolet.org>,
 * to whom comments and remarks may be sent. It is released under what
 * should amount to Public Domain or its closest equivalent; the
 * following mantra is supposed to incarnate that fact with all the
 * proper legal rituals:
 *
 * ---------------------------------------------------------------------
 * This file is provided under the terms of Creative Commons CC0 1.0
 * Public Domain Dedication. To the extent possible under law, the
 * author (Thomas Pornin) has waived all copyright and related or
 * neighboring rights to this file. This work is published from: Canada.
 * ---------------------------------------------------------------------
 *
 * Copyright (c) 2015 Thomas Pornin
 */

/* ==================================================================== */

/* ==================================================================== */
/*
 * Code specific to Argon2.
 *
 * The code below applies the following format:
 *
 *  $argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>
 *
 * where <T> is either 'i', <num> is a decimal integer (positive, fits in an
 * 'unsigned long') and <bin> is Base64-encoded data (no '=' padding characters,
 * no newline or whitespace).
 *
 * The last two binary chunks (encoded in Base64) are, in that order,
 * the salt and the output. Both are required. The binary salt length and the
 * output length must be in the allowed ranges defined in argon2.h.
 *
 * The ctx struct must contain buffers large enough to hold the salt and pwd
 * when it is fed into argon2_decode_string.
 */

/*
 * Decode an Argon2i hash string into the provided structure 'ctx'.
 * Returned value is ARGON2_OK on success.
 */
int
argon2_decode_string(argon2_context *ctx, const char *str, argon2_type type)
{
    int validation_result;
    int out_loc=0;
    int salt_loc=0;
    size_t str_len;

    uint32_t version = 0;

    str_len = strnlen(str, crypto_pwhash_argon2id_STRBYTES - 1);

    if (str_len == crypto_pwhash_argon2id_STRBYTES - 1)
        return ARGON2_DECODING_FAIL;

    switch (type) {
    case Argon2_id:
        validation_result = sscanf(str, "$argon2id$v=%u$m=%u,t=%u,p=%u$%n%*[^$]$%n", &version, &ctx->m_cost,
                                   &ctx->t_cost, &ctx->lanes, &salt_loc, &out_loc);
        break;
    case Argon2_i:
        validation_result = sscanf(str, "$argon2i$v=%u$m=%u,t=%u,p=%u$%n%*[^$]$%n", &version, &ctx->m_cost,
                                   &ctx->t_cost, &ctx->lanes, &salt_loc, &out_loc);
        break;
    default:
        return ARGON2_INCORRECT_PARAMETER;
    }

    if (validation_result != 4)
        return ARGON2_DECODING_FAIL;
    if (version != ARGON2_VERSION_NUMBER)
        return ARGON2_INCORRECT_TYPE;
    if (salt_loc > crypto_pwhash_argon2id_STRBYTES || out_loc > crypto_pwhash_argon2id_STRBYTES || salt_loc == 0 ||
        out_loc == 0) {
        return ARGON2_DECODING_FAIL;
    }

    ctx->threads = ctx->lanes;


    size_t bin_len;

    if (sodium_base642bin(ctx->salt, ctx->saltlen, &str[salt_loc], (out_loc - salt_loc) - 1, NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
        return ARGON2_DECODING_FAIL;

    ctx->saltlen = (uint32_t) bin_len;
    if (sodium_base642bin(ctx->out, ctx->outlen, &str[out_loc], str_len - out_loc, NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
        return ARGON2_DECODING_FAIL;
    ctx->outlen = (uint32_t) bin_len;
    // The previous checks in this function were either impossible
    // to fail (a uint32 can't be greater than the max uint32...)
    // or get rechecked in this validation function anyway.
    validation_result = argon2_validate_inputs(ctx);
    if (validation_result != ARGON2_OK) {
        return validation_result;
    }
    //because the code uses strnlen now the null check is redundant
    return ARGON2_OK;
}

/*
 * Encode an argon2i hash string into the provided buffer. 'dst_len'
 * contains the size, in characters, of the 'dst' buffer; if 'dst_len'
 * is less than the number of required characters (including the
 * terminating 0), then this function returns 0.
 *
 * If pp->output_len is 0, then the hash string will be a salt string
 * (no output). if pp->salt_len is also 0, then the string will be a
 * parameter-only string (no salt and no output).
 *
 * On success, ARGON2_OK is returned.
 */
int
argon2_encode_string(char *dst, size_t dst_len, argon2_context *ctx, argon2_type type)
{
    int validation_result;
    int dst_loc = 0;
    const char *argon_code;


    switch (type) {
    case Argon2_id:
        argon_code = "id";
        break;
    case Argon2_i:
        argon_code = "i";
        break;
    default:
        return ARGON2_ENCODING_FAIL;
    }

    validation_result = argon2_validate_inputs(ctx);
    if (validation_result != ARGON2_OK) {
        return validation_result;
    }

    dst_loc = snprintf(dst, dst_len, "$argon2%s$v=%u$m=%u,t=%u,p=%u$", argon_code, ARGON2_VERSION_NUMBER, ctx->m_cost,
                       ctx->t_cost, ctx->lanes);
    if (dst_loc < 0)
        return ARGON2_ENCODING_FAIL;
    if (sodium_bin2base64(&dst[dst_loc], dst_len - dst_loc, ctx->salt, ctx->saltlen,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == NULL) {
        return ARGON2_ENCODING_FAIL;
    }
    dst_loc += sodium_base64_ENCODED_LEN(ctx->saltlen, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    dst[dst_loc - 1] = '$';
    if (sodium_bin2base64(&dst[dst_loc], dst_len - dst_loc, ctx->out, ctx->outlen,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) == NULL) {
        return ARGON2_ENCODING_FAIL;
    }

    return ARGON2_OK;
}
