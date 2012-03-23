/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/enc_provider/camellia.c
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
 *
 * CyaSSL doesn't currently support the Camellia cipher.
 *
 */

#include "crypto_int.h"

#ifdef CAMELLIA

static krb5_error_code
krb5int_camellia_encrypt(krb5_key key, const krb5_data *ivec,
			 krb5_crypto_iov *data, size_t num_data)
{
    return KRB5_CRYPTO_INTERNAL;
}

static krb5_error_code
krb5int_camellia_decrypt(krb5_key key, const krb5_data *ivec,
			 krb5_crypto_iov *data, size_t num_data)
{
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
krb5int_camellia_cbc_mac(krb5_key key, const krb5_crypto_iov *data,
                         size_t num_data, const krb5_data *iv,
			 krb5_data *output)
{
    return KRB5_CRYPTO_INTERNAL; 
} 

static krb5_error_code
krb5int_camellia_init_state (const krb5_keyblock *key, krb5_keyusage usage,
			     krb5_data *state)
{
    return KRB5_CRYPTO_INTERNAL; 
} 
   
const struct krb5_enc_provider krb5int_enc_camellia128 = {
    16,
    16, 16,
    krb5int_camellia_encrypt,
    krb5int_camellia_decrypt,
    krb5int_camellia_cbc_mac,
    krb5int_camellia_init_state,
    krb5int_default_free_state
};

const struct krb5_enc_provider krb5int_enc_camellia256 = {
    16,
    32, 32,
    krb5int_camellia_encrypt,
    krb5int_camellia_decrypt,
    krb5int_camellia_cbc_mac,
    krb5int_camellia_init_state,
    krb5int_default_free_state
};

#else /* CAMELLIA */

/* These won't be used, but are still in the export table. */

krb5_error_code
krb5int_camellia_cbc_mac(krb5_key key, const krb5_crypto_iov *data,
                         size_t num_data, const krb5_data *iv,
			 krb5_data *output)
{
    return EINVAL;
}

const struct krb5_enc_provider krb5int_enc_camellia128 = {
};

const struct krb5_enc_provider krb5int_enc_camellia256 = {
};

#endif /* CAMELLIA */
