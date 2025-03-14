
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "argon2-core.h"
#include "argon2.h"
#include "argon2-encoding.h"
#include "crypto_pwhash_argon2id.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"

#define STR_HASHBYTES 32U

int
crypto_pwhash_argon2id_alg_argon2id13(void)
{
    return crypto_pwhash_argon2id_ALG_ARGON2ID13;
}

size_t
crypto_pwhash_argon2id_bytes_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_BYTES_MIN >= ARGON2_MIN_OUTLEN);
    return crypto_pwhash_argon2id_BYTES_MIN;
}

size_t
crypto_pwhash_argon2id_bytes_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_BYTES_MAX <= ARGON2_MAX_OUTLEN);
    return crypto_pwhash_argon2id_BYTES_MAX;
}

size_t
crypto_pwhash_argon2id_passwd_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_PASSWD_MIN >= ARGON2_MIN_PWD_LENGTH);
    return crypto_pwhash_argon2id_PASSWD_MIN;
}

size_t
crypto_pwhash_argon2id_passwd_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_PASSWD_MAX <= ARGON2_MAX_PWD_LENGTH);
    return crypto_pwhash_argon2id_PASSWD_MAX;
}

size_t
crypto_pwhash_argon2id_saltbytes(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_SALTBYTES >= ARGON2_MIN_SALT_LENGTH);
    COMPILER_ASSERT(crypto_pwhash_argon2id_SALTBYTES <= ARGON2_MAX_SALT_LENGTH);
    return crypto_pwhash_argon2id_SALTBYTES;
}

size_t
crypto_pwhash_argon2id_strbytes(void)
{
    return crypto_pwhash_argon2id_STRBYTES;
}

size_t
crypto_pwhash_argon2id_relief_strbytes(void)
{
    return crypto_pwhash_argon2id_relief_STRBYTES;
}

const char *
crypto_pwhash_argon2id_strprefix(void)
{
    return crypto_pwhash_argon2id_STRPREFIX;
}

unsigned long long
crypto_pwhash_argon2id_opslimit_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_OPSLIMIT_MIN >= ARGON2_MIN_TIME);
    return crypto_pwhash_argon2id_OPSLIMIT_MIN;
}

unsigned long long
crypto_pwhash_argon2id_opslimit_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_OPSLIMIT_MAX <= ARGON2_MAX_TIME);
    return crypto_pwhash_argon2id_OPSLIMIT_MAX;
}

size_t
crypto_pwhash_argon2id_memlimit_min(void)
{
    COMPILER_ASSERT((crypto_pwhash_argon2id_MEMLIMIT_MIN / 1024U) >= ARGON2_MIN_MEMORY);
    return crypto_pwhash_argon2id_MEMLIMIT_MIN;
}

size_t
crypto_pwhash_argon2id_memlimit_max(void)
{
    COMPILER_ASSERT((crypto_pwhash_argon2id_MEMLIMIT_MAX / 1024U) <= ARGON2_MAX_MEMORY);
    return crypto_pwhash_argon2id_MEMLIMIT_MAX;
}

unsigned long long
crypto_pwhash_argon2id_opslimit_interactive(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
}

size_t
crypto_pwhash_argon2id_memlimit_interactive(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;
}

unsigned long long
crypto_pwhash_argon2id_opslimit_moderate(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_MODERATE;
}

size_t
crypto_pwhash_argon2id_memlimit_moderate(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_MODERATE;
}

unsigned long long
crypto_pwhash_argon2id_opslimit_sensitive(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE;
}

size_t
crypto_pwhash_argon2id_memlimit_sensitive(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE;
}

int
crypto_pwhash_argon2id(unsigned char *const out, unsigned long long outlen,
                       const char *const passwd, unsigned long long passwdlen,
                       const unsigned char *const salt,
                       unsigned long long opslimit, size_t memlimit, int alg)
{
    memset(out, 0, outlen);
    if (outlen > crypto_pwhash_argon2id_BYTES_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (outlen < crypto_pwhash_argon2id_BYTES_MIN) {
        errno = EINVAL;
        return -1;
    }
    if (passwdlen > crypto_pwhash_argon2id_PASSWD_MAX ||
        opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < crypto_pwhash_argon2id_PASSWD_MIN ||
        opslimit < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
        memlimit < crypto_pwhash_argon2id_MEMLIMIT_MIN) {
        errno = EINVAL;
        return -1;
    }
    if ((const void *) out == (const void *) passwd) {
        errno = EINVAL;
        return -1;
    }
    switch (alg) {
    case crypto_pwhash_argon2id_ALG_ARGON2ID13:
        if (argon2id_hash_raw((uint32_t) opslimit, (uint32_t) (memlimit / 1024U),
                              (uint32_t) 1U, passwd, (size_t) passwdlen, salt,
                              (size_t) crypto_pwhash_argon2id_SALTBYTES, out,
                              (size_t) outlen) != ARGON2_OK) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

int
crypto_pwhash_argon2id_str(char out[crypto_pwhash_argon2id_STRBYTES],
                           const char *const passwd,
                           unsigned long long passwdlen,
                           unsigned long long opslimit, size_t memlimit)
{
    unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    return crypto_pwhash_argon2id_salt_str(out, passwd, passwdlen, salt, opslimit, memlimit);
}

int
crypto_pwhash_argon2id_salt_str(char out[crypto_pwhash_argon2id_STRBYTES],
                                const char *const passwd,
                                unsigned long long passwdlen,
                                const unsigned char *const salt,
                                unsigned long long opslimit, size_t memlimit)
{

    memset(out, 0, crypto_pwhash_argon2id_STRBYTES);
    if (passwdlen > crypto_pwhash_argon2id_PASSWD_MAX ||
        opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < crypto_pwhash_argon2id_PASSWD_MIN ||
        opslimit < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
        memlimit < crypto_pwhash_argon2id_MEMLIMIT_MIN) {
        errno = EINVAL;
        return -1;
    }

    if (argon2id_hash_encoded((uint32_t) opslimit, (uint32_t) (memlimit / 1024U),
                              (uint32_t) 1U, passwd, (size_t) passwdlen, salt,
                              crypto_pwhash_argon2id_SALTBYTES, STR_HASHBYTES, out,
                              crypto_pwhash_argon2id_STRBYTES) != ARGON2_OK) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

int
crypto_pwhash_argon2id_relief_server_init_str(char out[crypto_pwhash_argon2id_STRBYTES], const char *const relief_str)
{
//    size_t rstr_len;
//    size_t rstr_pos=0;
//    uint32_t version;
//    const char * str = relief_str;
///* Prefix checking */
//#define CC(prefix)                               \
//    do {                                         \
//        size_t cc_len = strlen(prefix);          \
//        if (strncmp(str, prefix, cc_len) != 0) { \
//            return ARGON2_DECODING_FAIL;         \
//        }                                        \
//        str += cc_len;                           \
//    } while ((void) 0, 0)
//
///* Optional prefix checking with supplied code */
//#define CC_opt(prefix, code)                     \
//    do {                                         \
//        size_t cc_len = strlen(prefix);          \
//        if (strncmp(str, prefix, cc_len) == 0) { \
//            str += cc_len;                       \
//            {                                    \
//                code;                            \
//            }                                    \
//        }                                        \
//    } while ((void) 0, 0)
//
///* Decoding prefix into decimal */
//#define DECIMAL(x)                         \
//    do {                                   \
//        unsigned long dec_x;               \
//        str = decode_decimal(str, &dec_x); \
//        if (str == NULL) {                 \
//            return ARGON2_DECODING_FAIL;   \
//        }                                  \
//        (x) = dec_x;                       \
//    } while ((void) 0, 0)
//
///* Decoding prefix into uint32_t decimal */
//#define DECIMAL_U32(x)                           \
//    do {                                         \
//        unsigned long dec_x;                     \
//        str = decode_decimal(str, &dec_x);       \
//        if (str == NULL || dec_x > UINT32_MAX) { \
//            return ARGON2_DECODING_FAIL;         \
//        }                                        \
//        (x) = (uint32_t)dec_x;                   \
//    } while ((void)0, 0)
//
///* Decoding base64 into a binary buffer */
//#define BIN(buf, max_len, len)                                                   \
//    do {                                                                         \
//        size_t bin_len = (max_len);                                              \
//        const char *str_end;                                                     \
//        if (sodium_base642bin((buf), (max_len), str, strlen(str), NULL,          \
//                              &bin_len, &str_end,                                \
//                              sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0 || \
//            bin_len > UINT32_MAX) {                                              \
//            return ARGON2_DECODING_FAIL;                                         \
//        }                                                                        \
//        (len) = (uint32_t) bin_len;                                              \
//        str = str_end;                                                           \
//    } while ((void) 0, 0)
//
//
//
//    //58 is min length of parseable relief_str "r$argon2id$v=19$m=8,t=1,p=1$s:$argon2id$v=19$m=8,t=1,p=1$h\0"
//    const size_t MIN_RSTR_LEN = 59;
//
    memset(out, 0, crypto_pwhash_argon2id_STRBYTES);
//    rstr_len = strlen(relief_str);
//    if (rstr_len < MIN_RSTR_LEN) {
//        return ARGON2_DECODING_LENGTH_FAIL;
//    }
//    if (relief_str[rstr_pos++] != 'r') {
//        return ARGON2_DECODING_FAIL;
//    }
//    CC(crypto_pwhash_argon2id_STRPREFIX);
//    CC("$v=");
//    DECIMAL_U32(version);
//
//    return ARGON2_OK;
//#undef CC
//#undef CC_opt
//#undef DECIMAL
//#undef BIN

    return 0;
}

int
crypto_pwhash_argon2id_relief_str(char out[crypto_pwhash_argon2id_relief_STRBYTES],
                                  const char *const pwhash_str,
                                  unsigned long long client_opslimit, size_t client_memlimit,
                                  unsigned long long server_opslimit, size_t server_memlimit)
{
    argon2_context ctx;
    int decode_result;
    int fast_pwhash_result;

    char server_hash[32];

    size_t encoded_len;
    size_t last_out_delim_loc = 0;
    size_t sub_str_hash_loc = 0;
    size_t sub_str_salt_loc = 0;
    size_t sub_str_hash_len = 0;


    out[0] = 'r';
    memset(++out, 0, crypto_pwhash_argon2id_relief_STRBYTES - 1);
    memset(&ctx, 0, sizeof ctx);

    ctx.pwd = NULL;
    ctx.pwdlen = 0;
    ctx.secret = NULL;
    ctx.secretlen = 0;

    /* max values, to be updated in argon2_decode_string */
    encoded_len = strlen(pwhash_str);
    if (encoded_len > UINT32_MAX) {
        return ARGON2_DECODING_LENGTH_FAIL;
    }
    ctx.adlen = (uint32_t) encoded_len;
    ctx.saltlen = (uint32_t) encoded_len;
    ctx.outlen = crypto_pwhash_argon2id_STRBYTES;

    ctx.ad = (uint8_t *) malloc(ctx.adlen);
    ctx.salt = (uint8_t *) malloc(ctx.saltlen);
    ctx.out = (uint8_t *) malloc(crypto_pwhash_argon2id_STRBYTES);
    if (!ctx.out || !ctx.salt || !ctx.ad) {
        free(ctx.ad);
        free(ctx.salt);
        free(ctx.out);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    decode_result = argon2_decode_string(&ctx, pwhash_str, Argon2_id);
    free(ctx.ad);

    if (decode_result != ARGON2_OK) {
        free(ctx.salt);
        free(ctx.out);
        return decode_result;
    }
    if (ctx.m_cost != client_memlimit || ctx.t_cost != client_opslimit) {
        free(ctx.salt);
        free(ctx.out);
        return ARGON2_INCORRECT_PARAMETER;
    }
    last_out_delim_loc = crypto_pwhash_argon2id_relief_STRBYTES;
    while (pwhash_str[last_out_delim_loc--] != '$');

    memcpy(out, pwhash_str, last_out_delim_loc);
    out[last_out_delim_loc++] = ':';

    fast_pwhash_result = crypto_pwhash_argon2id(server_hash, 32, (const char *) ctx.out, ctx.outlen, ctx.salt,
                                                server_opslimit, server_memlimit,
                                                crypto_pwhash_argon2id_ALG_ARGON2ID13);
    free(ctx.salt);
    free(ctx.out);

    if (fast_pwhash_result != 0)
        return fast_pwhash_result;

    return argon2_encode_relief_server_str_portion(&out[last_out_delim_loc],
                                                   crypto_pwhash_argon2id_relief_STRBYTES - last_out_delim_loc,
                                                   server_hash, 32, server_opslimit, server_memlimit);


}

int
crypto_pwhash_argon2id_str_verify(const char *str,
                                  const char *const passwd,
                                  unsigned long long passwdlen)
{
    int verify_ret;

    if (passwdlen > crypto_pwhash_argon2id_PASSWD_MAX) {
        errno = EFBIG;
        return -1;
    }
    /* LCOV_EXCL_START */
    if (passwdlen < crypto_pwhash_argon2id_PASSWD_MIN) {
        errno = EINVAL;
        return -1;
    }
    /* LCOV_EXCL_STOP */

    verify_ret = argon2id_verify(str, passwd, (size_t) passwdlen);
    if (verify_ret == ARGON2_OK) {
        return 0;
    }
    if (verify_ret == ARGON2_VERIFY_MISMATCH) {
        errno = EINVAL;
    }
    return -1;
}
