/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/cyassl/des/des_keys.c - Key functions used by Kerberos code */
/*
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
#include <cyassl/internal.h>

typedef unsigned char DES_key[8];

/* Table of known weak and semi-weak DES keys */
static const DES_key weak_keys[] = {
    /* Weak Keys */
    {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
    {0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
    {0xE0,0xE0,0xE0,0xE0,0xF1,0xF1,0xF1,0xF1},
    {0x1F,0x1F,0x1F,0x1F,0x0E,0x0E,0x0E,0x0E},

    /* Semi-weak Key Pairs */
    {0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
    {0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},

    {0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
    {0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},

    {0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
    {0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},

    {0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
    {0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},

    {0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
    {0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},

    {0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
    {0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

/*
 * k5_des_fixup_key_parity: Forces DES key to have odd parity, parity 
 *                          bit is the lowest order bit (ie: 
 *                          positions 8, 16, ... 64).
 * @keybits 8-byte DES key
 */
void
k5_des_fixup_key_parity(unsigned char *keybits)
{
	unsigned long int i;
    char tmp;

    for (i=0; i < DES_KEY_SIZE; i++) {
        keybits[i] &= 0xfe;
        tmp = keybits[i];
        tmp ^= (tmp >> 4);
        tmp ^= (tmp >> 2);
        tmp ^= (tmp >> 1);
        tmp = (~tmp & 0x01);
        keybits[i] |= tmp;
    }
    return;
}

/*
 * k5_des_is_weak_key: returns true iff key is a weak or 
                       semi-weak DES key.
 *
 * Requires: key has correct odd parity, meaning the inverted weak
 *           and semi-weak keys are not checked.
 * 
 * @keybits 8-byte DES key
 *
 * Returns 0 on success, 1 on error
 */
krb5_boolean
k5_des_is_weak_key(unsigned char *keybits)
{
    unsigned int i;
    for (i = 0; i < (sizeof(weak_keys)/sizeof(DES_key)); i++) {
        if(!memcmp(weak_keys[i], keybits, DES_KEY_SIZE)){
            return 1;
        }
    }
    return 0;
}
