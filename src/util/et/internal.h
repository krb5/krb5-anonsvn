/*
 * internal include file for com_err package
 */
#include "mit-sipb-copyright.h"

#include <errno.h>

#if defined(_MSDOS) || defined(_WIN32)
#define HDR_HAS_PERROR
#define HAVE_STRERROR
#endif

#if !defined(HAVE_STRERROR) && !defined(SYS_ERRLIST_DECLARED)
extern char const * const sys_errlist[];
extern const int sys_nerr;
#endif

#if defined(__STDC__) && !defined(HDR_HAS_PERROR)
void perror (const char *);
#endif
