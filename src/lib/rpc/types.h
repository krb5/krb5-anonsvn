/* @(#)types.h	2.3 88/08/15 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*      @(#)types.h 1.18 87/07/24 SMI      */

/*
 * Rpc additions to <sys/types.h>
 */
#ifndef __TYPES_RPC_HEADER__
#define __TYPES_RPC_HEADER__

#include <sys/types.h>

#if (mc68000 || sparc || vax || i386 || hpux || defined(_AIX))
typedef u_long u_int32;	/* 32-bit unsigned integers */
typedef long int32;	/* 32-bit signed integers */
#endif
#if defined(__alpha) && defined(__osf__)
typedef unsigned int u_int32;
typedef int int32;
#endif

#define	bool_t	int
#define	enum_t	int
#ifndef FALSE
#	define	FALSE	(0)
#endif
#ifndef TRUE
#	define	TRUE	(1)
#endif
#define __dontcare__	-1
#ifndef NULL
#	define NULL 0
#endif

#if defined(__osf__)
#include <stdlib.h>
#endif
#define mem_alloc(bsize)	(char *) malloc(bsize)
#define mem_free(ptr, bsize)	free(ptr)

#ifndef makedev /* ie, we haven't already included it */
#include <sys/types.h>
#endif
#ifdef _AIX
#include <sys/select.h>
#endif
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <netdb.h> /* XXX This should not have to be here.
		    * I got sick of seeing the warnings for MAXHOSTNAMELEN
		    * and the two values were different. -- shanzer 
		    */

#ifndef INADDR_LOOPBACK
#define       INADDR_LOOPBACK         (rpc_u_int32)0x7F000001
#endif
#ifndef MAXHOSTNAMELEN
#define        MAXHOSTNAMELEN  64
#endif

#endif /* ndef __TYPES_RPC_HEADER__ */
