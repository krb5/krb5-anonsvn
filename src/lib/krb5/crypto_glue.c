/*
 * lib/krb5/krb/crypto_glue.c
 *
 * Copyright 1996 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Exported routines:
 *   krb5_use_enctype()
 *   krb5_checksum_size()
 *   krb5_encrypt_size()
 *   krb5_calculate_checksum()
 *   krb5_verify_checksum()
 *
 * Internal library routines:
 *   is_coll_proof_cksum()
 *   is_keyed_cksum()
 *   valid_cksumtype()
 *   valid_enctype()
 */

#include "k5-int.h"


KRB5_DLLIMP size_t KRB5_CALLCONV
krb5_encrypt_size(length, crypto)
    size_t			length;
    krb5_cryptosystem_entry	FAR * crypto;
{
    return krb5_roundup(length + crypto->pad_minimum, crypto->block_length);
}

krb5_boolean KRB5_CALLCONV
valid_enctype(ktype)
    krb5_enctype	ktype;
{
    return ((ktype<=krb5_max_enctype) && (ktype>0) && krb5_enctype_array[ktype]);
}

krb5_boolean KRB5_CALLCONV
valid_cksumtype(cktype)
    krb5_cksumtype	cktype;
{
    return ((cktype<=krb5_max_cksum) && (cktype>0) && krb5_cksumarray[cktype]);
}

krb5_boolean KRB5_CALLCONV
is_coll_proof_cksum(cktype)
    krb5_cksumtype	cktype;
{
    return(krb5_cksumarray[cktype]->is_collision_proof);
}

krb5_boolean KRB5_CALLCONV
is_keyed_cksum(cktype)
    krb5_cksumtype	cktype;
{
    return (krb5_cksumarray[cktype]->uses_key);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_use_enctype(context, eblockp, enctype)
    krb5_context	context;
    krb5_encrypt_block	FAR * eblockp;
    krb5_enctype	enctype;
{
    (eblockp)->crypto_entry = krb5_enctype_array[(enctype)]->system;
    return 0;
}

KRB5_DLLIMP size_t KRB5_CALLCONV
krb5_checksum_size(context, cktype)
    krb5_context	context;
    krb5_cksumtype	cktype;
{
    return krb5_cksumarray[cktype]->checksum_length;
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_calculate_checksum(context, cktype, in, in_length, seed, seed_length, outcksum)
    krb5_context	context;
    krb5_cksumtype	cktype;
    krb5_pointer	in;
    size_t		in_length;
    krb5_pointer	seed;
    size_t		seed_length;
    krb5_checksum	FAR *outcksum;
{
    return krb5_x(((*krb5_cksumarray[cktype]->sum_func)),
		  (in, in_length, seed, seed_length, outcksum));
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_verify_checksum(context, cktype, cksum, in, in_length, seed, seed_length)
    krb5_context	context;
    krb5_cksumtype	cktype;
    krb5_checksum	FAR *cksum;
    krb5_pointer	in;
    size_t		in_length;
    krb5_pointer	seed;
    size_t		seed_length;
{
    return krb5_x((*krb5_cksumarray[cktype]->sum_verf_func),
		  (cksum, in, in_length, seed, seed_length));
}
