/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.14.2.1  1996/06/20 02:16:26  marc
 * File added to the repository on a branch
 *
 * Revision 1.14  1996/05/30  22:23:52  bjaspan
 * zero db *correctly* before using
 *
 * Revision 1.13  1996/05/30 21:13:41  bjaspan
 * zero db before using
 *
 * Revision 1.12  1996/05/08 19:12:29  bjaspan
 * use file names specifies in realm params instead of hard-coded constants
 *
 * Revision 1.11  1995/11/07  23:23:12  grier
 * Add stdlib.h
 *
 * Revision 1.10  1995/08/27  12:22:54  jik
 * Include <unistd.h> for F_OK.  See PR 3463.
 *
 * Revision 1.9  1995/08/24 20:23:26  bjaspan
 * initialize perm = 0
 *
 * Revision 1.8  1995/08/24  19:05:10  bjaspan
 * remove extraneous return
 *
 * Revision 1.7  1995/08/22  20:24:25  marc
 * correct race condition where db was unlocked, then closed
 *
 * Revision 1.6  1995/08/22  20:14:57  marc
 * clean up mode grossity
 *
 * Revision 1.5  1995/08/22  19:58:41  marc
 * [secure-admin/3394]
 * fix off-by-one error which was causing the db never to be closed.
 * clarification changes
 *
 * Revision 1.4  1995/08/22  18:48:06  bjaspan
 * [secure-admin/3394: fix design flaw with multiple open database
 * locking
 *
 * Revision 1.3  1995/08/10  22:42:09  bjaspan
 * [secure-admin/3394] first cut at unit tests for locking
 *
 * Revision 1.2  1995/08/09  19:00:17  bjaspan
 * [secure-admin/3394] add permanent lock mode, fix import/export
 *
 * Revision 1.1  1995/08/08  18:30:25  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include	<sys/file.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	"adb.h"
#include	<stdlib.h>

#define MAX_LOCK_TRIES 5

osa_adb_ret_t osa_adb_init_db(osa_adb_db_t *dbp, char *filename,
			      char *lockfilename, int magic)
{
     osa_adb_db_t db;
     static osa_adb_lock_ent lockinfo = { NULL, NULL, 0, 0, 0, NULL };
     krb5_error_code code;

     if (dbp == NULL || filename == NULL)
	  return EINVAL;

     db = (osa_adb_princ_t) malloc(sizeof(osa_adb_db_ent));
     if (db == NULL)
	  return ENOMEM;

     memset(db, 0, sizeof(*db));
     db->info.hash = NULL;
     db->info.bsize = 256;
     db->info.ffactor = 8;
     db->info.nelem = 25000;
     db->info.lorder = 0;

     if (lockinfo.lockfile == NULL) {
	  if (code = krb5_init_context(&lockinfo.context)) {
	     free(db);
	     return((osa_adb_ret_t) code);
	  }

	  /*
	   * needs be open read/write so that write locking can work with
	   * POSIX systems
	   */
	  lockinfo.filename = lockfilename;
	  if ((lockinfo.lockfile = fopen(lockinfo.filename, "r+")) == NULL) {
	       /*
		* maybe someone took away write permission so we could only
		* get shared locks?
		*/
	       if ((lockinfo.lockfile = fopen(lockinfo.filename, "r")) == NULL) {
		    free(db);
		    return OSA_ADB_NOLOCKFILE;
	       }
	  }
	  lockinfo.lockmode = lockinfo.lockcnt = 0;
     }

     db->lock = &lockinfo;
     db->lock->refcnt++;

     db->filename = filename;
     db->magic = magic;

     *dbp = db;
     
     return OSA_ADB_OK;
}

osa_adb_ret_t osa_adb_fini_db(osa_adb_db_t db, int magic)
{
     if (db->magic != magic)
	  return EINVAL;
     if (db->lock->refcnt == 0) {
	  /* barry says this can't happen */
	  return OSA_ADB_FAILURE;
     } else {
	  db->lock->refcnt--;
     }

     if (db->lock->refcnt == 0) {
	  if (fclose(db->lock->lockfile) != 0)
	       return OSA_ADB_NOLOCKFILE;
	  db->lock->lockfile = NULL;
	  krb5_free_context(db->lock->context);
     }
     
     db->magic = 0;
     free(db);
     return OSA_ADB_OK;
}     
     
osa_adb_ret_t osa_adb_get_lock(osa_adb_db_t db, int mode)
{
     int tries, gotlock, perm, krb5_mode, ret;

     if (db->lock->lockmode >= mode) {
	  /* No need to upgrade lock, just incr refcnt and return */
	  db->lock->lockcnt++;
	  return(OSA_ADB_OK);
     }

     perm = 0;
     switch (mode) {
	case OSA_ADB_PERMANENT:
	  perm = 1;
	case OSA_ADB_EXCLUSIVE:
	  krb5_mode = KRB5_LOCKMODE_EXCLUSIVE;
	  break;
	case OSA_ADB_SHARED:
	  krb5_mode = KRB5_LOCKMODE_SHARED;
	  break;
	default:
	  return(EINVAL);
     }

     for (gotlock = tries = 0; tries < MAX_LOCK_TRIES; tries++) {
	  if ((ret = krb5_lock_file(db->lock->context,
				    fileno(db->lock->lockfile),
				    krb5_mode|KRB5_LOCKMODE_DONTBLOCK)) == 0) {
	       gotlock++;
	       break;
	  } else if (ret == EBADF && mode == OSA_ADB_EXCLUSIVE)
	       /* tried to exclusive-lock something we don't have */
	       /* write access to */
	       return OSA_ADB_NOEXCL_PERM;

	  sleep(1);
     }

     /* test for all the likely "can't get lock" error codes */
     if (ret == EACCES || ret == EAGAIN || ret == EWOULDBLOCK)
	  return OSA_ADB_CANTLOCK_DB;
     else if (ret != 0)
	  return ret;

     /*
      * If the file no longer exists, someone acquired a permanent
      * lock.  If that process terminates its exclusive lock is lost,
      * but if we already had the file open we can (probably) lock it
      * even though it has been unlinked.  So we need to insist that
      * it exist.
      */
     if (access(db->lock->filename, F_OK) < 0) {
	  (void) krb5_lock_file(db->lock->context,
				fileno(db->lock->lockfile),
				KRB5_LOCKMODE_UNLOCK);
	  return OSA_ADB_NOLOCKFILE;
     }
     
     /* we have the shared/exclusive lock */
     
     if (perm) {
	  if (unlink(db->lock->filename) < 0) {
	       int ret;

	       /* somehow we can't delete the file, but we already */
	       /* have the lock, so release it and return */

	       ret = errno;
	       (void) krb5_lock_file(db->lock->context,
				     fileno(db->lock->lockfile),
				     KRB5_LOCKMODE_UNLOCK);
	       
	       /* maybe we should return CANTLOCK_DB.. but that would */
	       /* look just like the db was already locked */
	       return ret;
	  }

	  /* this releases our exclusive lock.. which is okay because */
	  /* now no one else can get one either */
	  (void) fclose(db->lock->lockfile);
     }
     
     db->lock->lockmode = mode;
     db->lock->lockcnt++;
     return OSA_ADB_OK;
}

osa_adb_ret_t osa_adb_release_lock(osa_adb_db_t db)
{
     int ret;
     
     if (!db->lock->lockcnt)		/* lock already unlocked */
	  return OSA_ADB_NOTLOCKED;

     if (db->lock->lockmode == OSA_ADB_PERMANENT) {
	  /* now we need to create the file since it does not exist */
	  if ((db->lock->lockfile = fopen(db->lock->filename, "w+")) == NULL) {
	       return OSA_ADB_NOLOCKFILE;
	  }

	  /* the file was closed and reopen, so we have no more locks */
	  db->lock->lockmode = 0;
	  db->lock->lockcnt = 0;
	  return OSA_ADB_OK;
     }
     
     if (--db->lock->lockcnt == 0) {
	  ret = krb5_lock_file(db->lock->context,
			       fileno(db->lock->lockfile),
			       KRB5_LOCKMODE_UNLOCK);
	  if (ret)
	       return ret;
	  
	  db->lock->lockmode = 0;
     }
     return OSA_ADB_OK;
}

osa_adb_ret_t osa_adb_open_and_lock(osa_adb_princ_t db, int locktype)
{
     int ret;

     ret = osa_adb_get_lock(db, locktype);
     if (ret != OSA_ADB_OK)
	  return ret;
     
     db->db = dbopen(db->filename, O_RDWR | O_CREAT, 0600, DB_HASH,
		     &db->info);
     if (db->db == NULL) {
	  (void) osa_adb_release_lock(db);
	  if(errno == EINVAL)
	       return OSA_ADB_BAD_DB;
	  return errno;
     }
     return OSA_ADB_OK;
}

osa_adb_ret_t osa_adb_close_and_unlock(osa_adb_princ_t db)
{
     int ret;

     if(db->db->close(db->db) == -1) {
	  (void) osa_adb_release_lock(db);
	  return OSA_ADB_FAILURE;
     }

     db->db = NULL;

     return(osa_adb_release_lock(db));
}

