#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "argon2-core.h"
#include "argon2.h"
#include "argon2-encoding.h"
#include "crypto_pwhash_argon2id.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"

#define STR_HASHBYTES 32U

int crypto_pwhash_argon2id_alg_argon2id13(void)
{
    return crypto_pwhash_argon2id_ALG_ARGON2ID13;
}

size_t crypto_pwhash_argon2id_bytes_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_BYTES_MIN >= ARGON2_MIN_OUTLEN);
    return crypto_pwhash_argon2id_BYTES_MIN;
}

size_t crypto_pwhash_argon2id_bytes_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_BYTES_MAX <= ARGON2_MAX_OUTLEN);
    return crypto_pwhash_argon2id_BYTES_MAX;
}

size_t crypto_pwhash_argon2id_passwd_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_PASSWD_MIN >= ARGON2_MIN_PWD_LENGTH);
    return crypto_pwhash_argon2id_PASSWD_MIN;
}

size_t crypto_pwhash_argon2id_passwd_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_PASSWD_MAX <= ARGON2_MAX_PWD_LENGTH);
    return crypto_pwhash_argon2id_PASSWD_MAX;
}

size_t crypto_pwhash_argon2id_saltbytes(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_SALTBYTES >= ARGON2_MIN_SALT_LENGTH);
    COMPILER_ASSERT(crypto_pwhash_argon2id_SALTBYTES <= ARGON2_MAX_SALT_LENGTH);
    return crypto_pwhash_argon2id_SALTBYTES;
}

size_t crypto_pwhash_argon2id_strbytes(void)
{
    return crypto_pwhash_argon2id_STRBYTES;
}

size_t crypto_pwhash_argon2id_relief_strbytes(void)
{
    return crypto_pwhash_argon2id_relief_STRBYTES;
}

const char *crypto_pwhash_argon2id_strprefix(void)
{
    return crypto_pwhash_argon2id_STRPREFIX;
}

unsigned long long crypto_pwhash_argon2id_opslimit_min(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_OPSLIMIT_MIN >= ARGON2_MIN_TIME);
    return crypto_pwhash_argon2id_OPSLIMIT_MIN;
}

unsigned long long crypto_pwhash_argon2id_opslimit_max(void)
{
    COMPILER_ASSERT(crypto_pwhash_argon2id_OPSLIMIT_MAX <= ARGON2_MAX_TIME);
    return crypto_pwhash_argon2id_OPSLIMIT_MAX;
}

size_t crypto_pwhash_argon2id_memlimit_min(void)
{
    COMPILER_ASSERT((crypto_pwhash_argon2id_MEMLIMIT_MIN / 1024U) >= ARGON2_MIN_MEMORY);
    return crypto_pwhash_argon2id_MEMLIMIT_MIN;
}

size_t crypto_pwhash_argon2id_memlimit_max(void)
{
    COMPILER_ASSERT((crypto_pwhash_argon2id_MEMLIMIT_MAX / 1024U) <= ARGON2_MAX_MEMORY);
    return crypto_pwhash_argon2id_MEMLIMIT_MAX;
}

unsigned long long crypto_pwhash_argon2id_opslimit_interactive(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
}

size_t crypto_pwhash_argon2id_memlimit_interactive(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE;
}

unsigned long long crypto_pwhash_argon2id_opslimit_moderate(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_MODERATE;
}

size_t crypto_pwhash_argon2id_memlimit_moderate(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_MODERATE;
}

unsigned long long crypto_pwhash_argon2id_opslimit_sensitive(void)
{
    return crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE;
}

size_t crypto_pwhash_argon2id_memlimit_sensitive(void)
{
    return crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE;
}

int crypto_pwhash_argon2id(unsigned char *const out, unsigned long long outlen, const char *const passwd,
                           unsigned long long passwdlen, const unsigned char *const salt, unsigned long long opslimit,
                           size_t memlimit, int alg)
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
    if (passwdlen > crypto_pwhash_argon2id_PASSWD_MAX || opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < crypto_pwhash_argon2id_PASSWD_MIN || opslimit < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
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
        if (argon2id_hash_raw((uint32_t) opslimit, (uint32_t) (memlimit / 1024U), (uint32_t) 1U, passwd,
                              (size_t) passwdlen, salt, (size_t) crypto_pwhash_argon2id_SALTBYTES, out,
                              (size_t) outlen) != ARGON2_OK) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

int crypto_pwhash_argon2id_str(char out[crypto_pwhash_argon2id_STRBYTES], const char *const passwd,
                               unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit)
{
    unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    return crypto_pwhash_argon2id_salt_str(out, passwd, passwdlen, salt, opslimit, memlimit);
}

int crypto_pwhash_argon2id_salt_str(char out[crypto_pwhash_argon2id_STRBYTES], const char *const passwd,
                                    unsigned long long passwdlen, const unsigned char *const salt,
                                    unsigned long long opslimit, size_t memlimit)
{

    memset(out, 0, crypto_pwhash_argon2id_STRBYTES);
    if (passwdlen > crypto_pwhash_argon2id_PASSWD_MAX || opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < crypto_pwhash_argon2id_PASSWD_MIN || opslimit < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
        memlimit < crypto_pwhash_argon2id_MEMLIMIT_MIN) {
        errno = EINVAL;
        return -1;
    }

    if (argon2id_hash_encoded((uint32_t) opslimit, (uint32_t) (memlimit / 1024U), (uint32_t) 1U, passwd,
                              (size_t) passwdlen, salt, crypto_pwhash_argon2id_SALTBYTES, STR_HASHBYTES, out,
                              crypto_pwhash_argon2id_STRBYTES) != ARGON2_OK) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

int
crypto_pwhash_argon2id_relief_server_init_str(uint8_t out[crypto_pwhash_argon2id_STRBYTES],
                                              uint8_t saltout[crypto_pwhash_argon2id_SALTBYTES],
                                              unsigned long long client_opslimit, size_t client_memlimit){

    randombytes(saltout,crypto_pwhash_argon2id_SALTBYTES);

    return argon2_relief_encode_init_str(out,crypto_pwhash_argon2id_STRBYTES,Argon2_id,saltout,crypto_pwhash_argon2id_SALTBYTES,
                                         client_opslimit,client_memlimit/1024);

}


int
crypto_pwhash_argon2id_relief_server_auth_param_str(char out[crypto_pwhash_argon2id_STRBYTES], const char *const relief_str)
{
    int delim_loc =crypto_pwhash_argon2id_STRBYTES;

    while(delim_loc > 0 && relief_str[delim_loc] != ':')
        delim_loc--;
    if (delim_loc <= 0)
        return ARGON2_DECODING_FAIL;
    memcpy(out,relief_str,delim_loc);
    memset(&out[delim_loc], 0, crypto_pwhash_argon2id_STRBYTES-delim_loc);

    return 0;
}

int
crypto_pwhash_argon2id_relief_client_str(char out[crypto_pwhash_argon2id_STRBYTES],uint8_t* passwd,
                                             size_t passwdlen,
                                             uint8_t server_init_str[crypto_pwhash_argon2id_STRBYTES]){
    argon2_context ctx;
    int decode_result;
    uint8_t salt_buf[crypto_pwhash_argon2id_SALTBYTES];
    uint8_t hash_buf[STR_HASHBYTES];

    memset(&ctx,0,sizeof(ctx));
    ctx.saltlen = crypto_pwhash_argon2id_SALTBYTES;
    ctx.salt = salt_buf;
    ctx.out = hash_buf;
    ctx.outlen = STR_HASHBYTES;

    decode_result = argon2_relief_decode_init_string(&ctx,server_init_str,Argon2_id);
    if(decode_result != ARGON2_OK)
        return decode_result;

    return crypto_pwhash_argon2id_salt_str(out,passwd,passwdlen,ctx.salt,ctx.t_cost,ctx.m_cost*1024);

}

int crypto_pwhash_argon2id_relief_str(char out[crypto_pwhash_argon2id_relief_STRBYTES], const char *const pwhash_str,
                                      uint8_t salt[crypto_pwhash_argon2id_SALTBYTES],
                                      unsigned long long client_opslimit, size_t client_memlimit,
                                      unsigned long long server_opslimit,
                                      size_t server_memlimit)
{
    const uint32_t client_threads = 1;
    const uint32_t server_threads = 1;
    argon2_context ctx;
    uint8_t saltbuf[crypto_pwhash_argon2id_SALTBYTES];
    uint8_t client_hash[STR_HASHBYTES];
    uint8_t server_hash[STR_HASHBYTES];
    int decode_result;
    int fast_pwhash_result;
    size_t pwhash_str_len;


    memset(&ctx, 0, sizeof(ctx));

    /* max values, to be updated in argon2_decode_string */
    pwhash_str_len = strnlen(pwhash_str, crypto_pwhash_argon2id_STRBYTES);
    if (pwhash_str_len > UINT32_MAX || pwhash_str_len == crypto_pwhash_argon2id_STRBYTES) {
        return ARGON2_DECODING_LENGTH_FAIL;
    }


    ctx.saltlen = crypto_pwhash_argon2id_SALTBYTES;
    ctx.outlen = STR_HASHBYTES;

    ctx.salt = saltbuf;
    ctx.out = client_hash;


    decode_result = argon2_decode_string(&ctx, pwhash_str, Argon2_id);
    if (decode_result != ARGON2_OK) {
        return decode_result;
    }
    if (ctx.m_cost * 1024 != client_memlimit || ctx.t_cost != client_opslimit ||
        crypto_pwhash_argon2id_SALTBYTES != ctx.saltlen ||
        memcmp(ctx.salt, (const void *) salt, crypto_pwhash_argon2id_SALTBYTES) != 0 || ctx.outlen != STR_HASHBYTES ||
        ctx.threads != ctx.lanes || ctx.threads != client_threads)
        return ARGON2_INCORRECT_PARAMETER;

    fast_pwhash_result = crypto_pwhash_argon2id((uint8_t *) server_hash, STR_HASHBYTES, (const char *) ctx.out,
                                                ctx.outlen, ctx.salt, server_opslimit, server_memlimit,
                                                crypto_pwhash_argon2id_ALG_ARGON2ID13);


    if (fast_pwhash_result != 0)
        return fast_pwhash_result;

    return argon2_encode_relief_server_str(out, pwhash_str, pwhash_str_len, (uint8_t *) server_hash, STR_HASHBYTES,
                                           server_opslimit, server_memlimit / 1024, server_threads, Argon2_id);


}

int crypto_pwhash_argon2id_relief_str_verify(const char *relief_str, const char* client_str){

    int decode_result;
    int relief_str_client_delim_loc;
    int server_hash_loc;
    int salt_loc;
    int client_hash_loc;
    int scan_loc;
    int client_str_len;
    int relief_str_len;
    int fast_pwhash_result;

    uint32_t version,memlimit,opslimit,threads;
    int num_decoded_vals = 0;

    uint8_t salt_buf[crypto_pwhash_argon2id_SALTBYTES];
    uint8_t client_hash_buf[STR_HASHBYTES];
    uint8_t server_hash_buf[STR_HASHBYTES];
    uint8_t calc_server_hash_buf[STR_HASHBYTES];

    relief_str_len = strnlen(relief_str,crypto_pwhash_argon2id_relief_STRBYTES);
    scan_loc = relief_str_len;
    while(scan_loc > 0 && relief_str[scan_loc] != '$')
        scan_loc--;
    server_hash_loc = scan_loc+1;

    while(scan_loc > 0 && relief_str[scan_loc] != ':')
        scan_loc--;
    relief_str_client_delim_loc = scan_loc;

    //this ensures the client hasn't used incorrect params
    if (memcmp(&relief_str[1],client_str,relief_str_client_delim_loc-1)!= 0)
        return ARGON2_INCORRECT_PARAMETER;

    while(scan_loc > 0 && relief_str[scan_loc] != '$')
        scan_loc--;
    salt_loc = scan_loc+1;
    client_str_len = strnlen(client_str,crypto_pwhash_argon2id_STRBYTES);
    scan_loc = client_str_len;
    while(scan_loc > 0 && client_str[scan_loc] != '$')
        scan_loc--;
    client_hash_loc = scan_loc+1;



    num_decoded_vals = sscanf(&relief_str[relief_str_client_delim_loc+1],"$argon2id$v=%u$m=%u,t=%u,p=%u$",&version,&memlimit,&opslimit,&threads);
    if (num_decoded_vals != 4)
        return ARGON2_DECODING_FAIL;
    memlimit = memlimit*1024;
    if (version != ARGON2_VERSION_NUMBER ||
        memlimit < crypto_pwhash_argon2id_MEMLIMIT_MIN || memlimit > crypto_pwhash_argon2id_MEMLIMIT_MAX ||
        opslimit < crypto_pwhash_argon2id_OPSLIMIT_MIN || opslimit > crypto_pwhash_argon2id_OPSLIMIT_MAX)
        return ARGON2_INCORRECT_PARAMETER;

    size_t bin_len;
    if (sodium_base642bin(client_hash_buf, STR_HASHBYTES,
                          &client_str[client_hash_loc],client_str_len-client_hash_loc,
                          NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
        return ARGON2_DECODING_FAIL;

    if (sodium_base642bin(salt_buf, crypto_pwhash_argon2id_SALTBYTES,
                          &relief_str[salt_loc],relief_str_client_delim_loc-salt_loc,
                          NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
        return ARGON2_DECODING_FAIL;
    if (sodium_base642bin(server_hash_buf, STR_HASHBYTES,
                          &relief_str[server_hash_loc],relief_str_len-server_hash_loc,
                          NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
        return ARGON2_DECODING_FAIL;

    fast_pwhash_result = crypto_pwhash_argon2id((uint8_t *) calc_server_hash_buf, STR_HASHBYTES, client_hash_buf,
                                                STR_HASHBYTES, salt_buf, opslimit, memlimit,
                                                crypto_pwhash_argon2id_ALG_ARGON2ID13);

    if (fast_pwhash_result != ARGON2_OK)
        return fast_pwhash_result;

    if (memcmp(calc_server_hash_buf,server_hash_buf,STR_HASHBYTES) != 0){
        errno = EINVAL;
        return -1;
    }


    return ARGON2_OK;
}


int crypto_pwhash_argon2id_str_verify(const char *str, const char *const passwd, unsigned long long passwdlen)
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
