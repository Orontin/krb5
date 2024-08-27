#include "crypto_int.h"
#include "../gost_helper.h"
#include <openssl/evp.h>

#define BLOCK_SIZE 8

static krb5_error_code
krb5int_gost_encrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
                size_t num_data)
{
    int ret, olen = BLOCK_SIZE;
    unsigned char iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    struct iov_cursor cursor;
    EVP_CIPHER_CTX *ctx;

    krb5int_init_gost();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ENOMEM;

    ret = EVP_EncryptInit_ex(ctx, EVP_get_cipherbynid(NID_gost89_cbc), NULL,
                             key->keyblock.contents,
                             (ivec) ? (unsigned char*)ivec->data : NULL);
    if (!ret) {
        EVP_CIPHER_CTX_free(ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    EVP_CIPHER_CTX_set_padding(ctx,0);

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    while (k5_iov_cursor_get(&cursor, iblock)) {
        ret = EVP_EncryptUpdate(ctx, oblock, &olen, iblock, BLOCK_SIZE);
        if (!ret)
            break;
        k5_iov_cursor_put(&cursor, oblock);
    }

    if (ivec != NULL)
        memcpy(ivec->data, oblock, BLOCK_SIZE);

    EVP_CIPHER_CTX_free(ctx);

    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
krb5int_gost_decrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
                size_t num_data)
{
    int ret, olen = BLOCK_SIZE;
    unsigned char iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    struct iov_cursor cursor;
    EVP_CIPHER_CTX *ctx;

    krb5int_init_gost();
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return ENOMEM;

    ret = EVP_DecryptInit_ex(ctx, EVP_get_cipherbynid(NID_gost89_cbc), NULL,
                             key->keyblock.contents,
                             (ivec) ? (unsigned char*)ivec->data : NULL);
    if (!ret) {
        EVP_CIPHER_CTX_free(ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    EVP_CIPHER_CTX_set_padding(ctx,0);

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    while (k5_iov_cursor_get(&cursor, iblock)) {
        ret = EVP_DecryptUpdate(ctx, oblock, &olen,
                                (unsigned char *)iblock, BLOCK_SIZE);
        if (!ret)
            break;
        k5_iov_cursor_put(&cursor, oblock);
    }

    if (ivec != NULL)
        memcpy(ivec->data, iblock, BLOCK_SIZE);

    EVP_CIPHER_CTX_free(ctx);

    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    if (ret != 1)
        return KRB5_CRYPTO_INTERNAL;
    return 0;
}

static krb5_error_code
krb5int_gost_init_state (const krb5_keyblock *key, krb5_keyusage usage,
                        krb5_data *state)
{
    state->length = 8;
    state->data = (void *) malloc(8);
    if (state->data == NULL)
        return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}

static void
krb5int_gost_free_state(krb5_data *state)
{
    free(state->data);
    *state = empty_data();
}

const struct krb5_enc_provider krb5int_enc_gost89 = {
    BLOCK_SIZE,
    32, 32,
    krb5int_gost_encrypt,
    krb5int_gost_decrypt,
    NULL,
    krb5int_gost_init_state,
    krb5int_gost_free_state
};
