/*
 * prof_threads.h
 * 
 * Generic interface to (a subset) of the OS threads interface
 *
 */
 
#ifndef PROF_THREADS_H
#define PROF_THREADS_H

#ifdef HAVE_PTHREADS
#include <pthread.h>

typedef pthread_mutex_t prof_mutex;

#define prof_mutex_init(mutex)											\
	pthread_mutex_init (mutex, PTHREAD_PROCESS_PRIVATE)
#define prof_mutex_lock(mutex)											\
	pthread_mutex_lock (mutex)
#define prof_mutex_unlock(mutex)										\
	pthread_mutex_unlock (mutex)
#define PROF_MUTEX_INITIALIZER											\
	PTHREAD_MUTEX_INITIALIZER

/* end HAVE_PTHREADS */
#elif defined (macintosh)

typedef struct opaque_prof_mutex*	prof_mutex;

int	prof_mutex_init (prof_mutex*		mutex);
int prof_mutex_lock (prof_mutex*		mutex);
int prof_mutex_unlock (prof_mutex*		mutex);

#define PROF_MUTEX_INITIALIZER		NULL

#endif /* macintosh */

#endif /* PROF_THREADS_H */