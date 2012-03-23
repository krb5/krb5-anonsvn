/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/enc_provider/des.c
 *
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "crypto_int.h"
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/internal.h>

static krb5_error_code
validate(krb5_key key, const krb5_data *ivec, const krb5_crypto_iov *data,
         size_t num_data, krb5_boolean *empty)
{
    size_t i, input_length;

    for (i = 0, input_length = 0; i < num_data; i++) {
        const krb5_crypto_iov *iov = &data[i];

        if (ENCRYPT_IOV(iov))
            input_length += iov->data.length;
    }

    /* Is our key the correct length? */
    if (key->keyblock.length != DES_KEY_SIZE)
        return(KRB5_BAD_KEYSIZE);

    /* Is our input a multiple of the block size, and
       the IV the correct length? */
    if ((input_length%DES_BLOCK_SIZE) != 0 
        || (ivec != NULL && ivec->length != DES_BLOCK_SIZE))
        return(KRB5_BAD_MSIZE);

    *empty = (input_length == 0);
    return 0;
}

/*
 * k5_des_encrypt: Encrypt data buffer using DES.  
 *  
 * @key      DES key (with odd parity)
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place encryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_des_encrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
               size_t num_data)
{
    int ret;
    Des des_ctx; 
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char iblock[DES_BLOCK_SIZE];
    unsigned char oblock[DES_BLOCK_SIZE];
    struct iov_block_state input_pos, output_pos;
    krb5_boolean empty;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos);

    ret = validate(key, ivec, data, num_data, &empty);
    if (ret != 0 || empty)
        return ret;

    memset(iv, 0, sizeof(iv));

    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data, ivec->length);
    }

    Des_SetKey(&des_ctx, key->keyblock.contents, iv, DES_ENCRYPTION);

    for (;;) {
        if (!krb5int_c_iov_get_block(iblock, DES_BLOCK_SIZE, data, 
                                     num_data, &input_pos))
            break;
   
        Des_CbcEncrypt(&des_ctx, oblock, iblock, DES_BLOCK_SIZE);

        krb5int_c_iov_put_block(data, num_data, oblock, DES_BLOCK_SIZE, 
                                &output_pos);
    }
    /* Store last encrypted block in IV */
    if (ivec != NULL) {
        memcpy(ivec->data, oblock, DES_BLOCK_SIZE);
    }

    zap(iv, sizeof(iv));    
    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    return 0;
}

/*
 * k5_des_decrypt: Decrypt data buffer using DES.  
 *  
 * @key      DES key (with odd parity)
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place decryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_des_decrypt(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
               size_t num_data)
{
    int ret;
    Des des_ctx; 
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char iblock[DES_BLOCK_SIZE];
    unsigned char oblock[DES_BLOCK_SIZE];
    struct iov_block_state input_pos, output_pos;
    krb5_boolean empty;

    IOV_BLOCK_STATE_INIT(&input_pos);
    IOV_BLOCK_STATE_INIT(&output_pos); 

    ret = validate(key, ivec, data, num_data, &empty);
    if (ret != 0 || empty)
        return ret;
   
    memset(iv, 0, sizeof(iv));
    
    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data, ivec->length);
    }

    Des_SetKey(&des_ctx, key->keyblock.contents, iv, DES_DECRYPTION);

    for (;;) {
       if (!krb5int_c_iov_get_block(iblock, DES_BLOCK_SIZE, data, 
                                    num_data, &input_pos))
          break;

        Des_CbcDecrypt(&des_ctx, oblock, iblock, DES_BLOCK_SIZE);

        krb5int_c_iov_put_block(data, num_data, oblock, DES_BLOCK_SIZE,
                                &output_pos);
    }

    /* Store last encrypted block in IV */
    if (ivec != NULL) {
        memcpy(ivec->data, iblock, DES_BLOCK_SIZE);
    }

    zap(iv, sizeof(iv));
    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    return 0;
}

/*
 * k5_des_decrypt: Decrypt data buffer using DES.  
 *  
 * @key      DES key (with odd parity)
 * @ivec     Initialization Vector
 * @data     Input/Output buffer (in-place decryption, block-by-block)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_des_cbc_mac(krb5_key key, const krb5_crypto_iov *data, size_t num_data,
               const krb5_data *ivec, krb5_data *output)
{
    int ret;
    Des des_ctx; 
    unsigned char iv[DES_BLOCK_SIZE];
    unsigned char iblock[DES_BLOCK_SIZE];
    unsigned char oblock[DES_BLOCK_SIZE];
    struct iov_block_state input_pos;
    krb5_boolean empty;

    IOV_BLOCK_STATE_INIT(&input_pos);

    ret = validate(key, ivec, data, num_data, &empty);
    if (ret != 0 || empty)
        return ret;

    if (output->length != DES_BLOCK_SIZE)
        return KRB5_CRYPTO_INTERNAL;

    memset(iv, 0, sizeof(iv));

    /* Check if IV exists and is the correct size */
    if (ivec && ivec->data) {
        if (ivec->length != sizeof(iv))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv, ivec->data, ivec->length);
    }

    Des_SetKey(&des_ctx, key->keyblock.contents, iv, DES_ENCRYPTION);

    for (;;) {
        if (!krb5int_c_iov_get_block(iblock, DES_BLOCK_SIZE, data, 
                                     num_data, &input_pos))
            break;
  
        Des_CbcEncrypt(&des_ctx, oblock, iblock, DES_BLOCK_SIZE);
    }
    /* Store last encrypted block as MAC */
    memcpy(output->data, oblock, DES_BLOCK_SIZE);

    zap(iv, sizeof(iv));    
    zap(iblock, sizeof(iblock));
    zap(oblock, sizeof(oblock));

    return 0;
}


const struct krb5_enc_provider krb5int_enc_des = {
    8,
    7, 8,
    k5_des_encrypt,
    k5_des_decrypt,
    k5_des_cbc_mac,
    krb5int_des_init_state,
    krb5int_default_free_state,
    NULL
};
