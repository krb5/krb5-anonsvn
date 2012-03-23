/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*  lib/crypto/cyassl/enc_provider/rc4.c
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
#include <cyassl/ctaocrypt/arc4.h>

/* Structure to save ARC4 state. Loopback field is NULL if Arc4 struct
 * is uninitialized, otherwise a pointer to the structure address if
 * initialized 
 */
struct arcfour_state {
    struct arcfour_state *loopback;
    Arc4 *arc4;
};

#define RC4_KEY_SIZE 16
#define RC4_BLOCK_SIZE 1

/*
 * k5_arcfour_docrypt: Encrypt data buffer using ARC4. With ARC4,
 *                     encryption and decryption are the same, so
 *                     we can use one function for both.
 * @key      ARC4 key
 * @state    Possible saved state from previous encryption/decryption
 * @data     Input/Output buffer (in-place encrypt/decrypt)
 * @num_data Number of blocks
 *
 * Returns 0 on success, krb5_error_code on error
 */
static krb5_error_code
k5_arcfour_docrypt(krb5_key key,const krb5_data *state, 
        krb5_crypto_iov *data, size_t num_data)
{
    size_t i;
    Arc4 *arc4;
    krb5_crypto_iov *iov = NULL;
    struct arcfour_state *arcstate;
    
    if(key->keyblock.length != 16) {
        return KRB5_BAD_KEYSIZE;
    }

    if (state != NULL)
        arcstate = (struct arcfour_state *) state->data;
    else
        arcstate = NULL;

    /* If we have no previous state, initialize new Arc4 struct */
    if(arcstate == NULL || arcstate->loopback == NULL) {
        if ( (arc4 = malloc(sizeof(Arc4))) == NULL ) {
            return ENOMEM;
        }
        Arc4SetKey(arc4, key->keyblock.contents, key->keyblock.length);

        if(arcstate) {
            arcstate->loopback = arcstate;
            arcstate->arc4 = arc4;
        }
    }
    else {
        arc4 = arcstate->arc4;

        if(arcstate->loopback != arcstate) {
            return KRB5_CRYPTO_INTERNAL;
        }
    }

    for (i = 0; i < num_data; i++) {
        iov = &data[i];
        if (iov->data.length <= 0)
            break;

        if (ENCRYPT_IOV(iov)) {
            Arc4Process(arc4, (unsigned char *) iov->data.data, 
                        (unsigned char *) iov->data.data, iov->data.length);
        }
    }

    /* Mark Arc4 struct as initialized */
    if (arcstate)
        arcstate->loopback = arcstate;

    if (state == NULL) {
        free(arc4);
        arc4 = NULL;
    }

    return 0;
}

static krb5_error_code
k5_arcfour_free_state ( krb5_data *state)
{
    if (state != NULL) {
        struct arcfour_state *arcstate = (struct arcfour_state *) state->data;
        free(arcstate);
        arcstate = NULL;
    }
    return 0;
}

static krb5_error_code
k5_arcfour_init_state (const krb5_keyblock *key,
                       krb5_keyusage keyusage, krb5_data *new_state)
{
    struct arcfour_state *arcstate;

    /* Create a state structure with an uninitialized context.  */
    arcstate = calloc(1, sizeof(*arcstate));
    if (arcstate == NULL)
        return ENOMEM;
    arcstate->loopback = NULL;
    new_state->data = (char *) arcstate;
    new_state->length = sizeof(*arcstate);
    return 0;
}

const struct krb5_enc_provider krb5int_enc_arcfour = {
    RC4_BLOCK_SIZE,
    RC4_KEY_SIZE, RC4_KEY_SIZE,
    k5_arcfour_docrypt,
    k5_arcfour_docrypt,
    NULL,
    k5_arcfour_init_state,
    k5_arcfour_free_state
};
