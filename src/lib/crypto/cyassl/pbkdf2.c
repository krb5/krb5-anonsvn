/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/pbkdf2.c
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
#include <cyassl/ctaocrypt/pwdbased.h>

/*
 * krb5int_pbkdf2_hmac_sha1: Password based key derivation using CyaSSL
 *                           PBKDF2 from PKCS#5.
 * 
 * Returns 0 on success, krb5_error_code on error
 */
krb5_error_code
krb5int_pbkdf2_hmac_sha1 (const krb5_data *out, unsigned long count,
                          const krb5_data *pass, const krb5_data *salt)
{

    /* CyaSSL PBKDF2 from PKCS#5 */
    PBKDF2( (unsigned char *)out->data, (unsigned char *) pass->data,
           pass->length, (unsigned char *)salt->data,
           salt->length, count, out->length, SHA);
    
    return 0;
}
