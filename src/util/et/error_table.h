/*
 * Copyright 1988 by the Student Information Processing Board of the
 * Massachusetts Institute of Technology.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#ifndef _ET_H

/* This directory doesn't really know about the krb5 world. The following
   windows defines are usually hidden in k5-config.h. For now I'll just
   place here what is needed from that file. Later we may decide to do
   it differently.
*/
#if defined(_MSDOS) || defined(_WIN32) || defined(_MACINTOSH)
#include <win-mac.h>
#endif

#ifndef KRB5_CALLCONV
#define KRB5_CALLCONV
#define KRB5_CALLCONV_C
#define KRB5_DLLIMP
#define KRB5_EXPORTVAR
#define INTERFACE
#define INTERFACE_C
#endif /* KRB5_CALLCONV */

#ifndef FAR
#define FAR
#define NEAR
#endif

#include <errno.h>

struct error_table {
    char const FAR * const FAR * msgs;
    long base;
    int n_msgs;
};
struct et_list {
    struct et_list FAR *next;
    const struct error_table FAR *table;
};
extern KRB5_DLLIMP struct et_list KRB5_EXPORTVAR * _et_list;

#define	ERRCODE_RANGE	8	/* # of bits to shift table number */
#define	BITS_PER_CHAR	6	/* # bits to shift per character in name */

#if (defined(__STDC__) || defined(_WINDOWS)) && !defined(KRB5_NO_PROTOTYPES)
extern const char *error_table_name (long);
#else 
extern const char *error_table_name ();
#endif

#define _ET_H
#endif
