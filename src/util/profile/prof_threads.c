/*
 * prof_threads.c
 * 
 * Generic interface to (a subset) of the OS threads interface
 *
 */

#include "prof_threads.h"
 
/* Under Mac OS, we are just nopping out this stuff, because we don't support
multi-threaded apps calling Kerberos from different threads right now... */
#if defined (macintosh)

int	prof_mutex_init (prof_mutex*		mutex) {return 0;}
int	prof_mutex_destroy (prof_mutex*		mutex) {return 0;}
int prof_mutex_lock (prof_mutex*		mutex) {return 0;}
int prof_mutex_unlock (prof_mutex*		mutex) {return 0;}

#endif /* macintosh */
