/*
 * prof_file.c ---- routines that manipulate an individual profile file.
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#include "prof_int.h"

#ifndef NO_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef NO_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>


#if defined(_MSDOS) || defined(_WIN32)
#include <io.h>
#define HAVE_STAT	
#define stat _stat
#endif

#ifdef SHARE_TREE_DATA
#include "prof_threads.h"

/* This is the head of the global list of shared trees */
prf_data_t g_shared_trees;
/* This is the mutex used to lock it */
prof_mutex g_shared_trees_mutex;
#endif /* SHARE_TREE_DATA */

#ifndef PROFILE_USES_PATHS
#include <FSp_fopen.h>

static OSErr GetMacOSTempFilespec (
	const	FSSpec*	inFilespec,
			FSSpec*	outFilespec);

#endif

static int rw_access(filespec)
	profile_filespec_t filespec;
{
#ifdef HAVE_ACCESS
	if (access(filespec, R_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the read permissions.
	 */
	FILE	*f;

#ifdef PROFILE_USES_PATHS
	f = fopen(filespec, "r");
#else
	f = FSp_fopen(&filespec, "r");
#endif
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

static int read_access(filespec)
	profile_filespec_t filespec;
{
#ifdef HAVE_ACCESS
	if (access(filespec, W_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the r/w permissions.
	 */
	FILE	*f;

#ifdef PROFILE_USES_PATHS
	f = fopen(filespec, "r+");
#else
	f = FSp_fopen(&filespec, "r+");
#endif
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

errcode_t profile_open_file(filespec, ret_prof)
	const_profile_filespec_t filespec;
	prf_file_t *ret_prof;
{
	prf_file_t	prf = NULL;
	prf_data_t	data = NULL;
	errcode_t	retval;
	char		*home_env = NULL;
	int		len;
	
	prf = malloc(sizeof(struct _prf_file_t));
	if (prf == NULL) {
		retval = ENOMEM;
		goto end;
	}

	memset(prf, 0, sizeof(struct _prf_file_t));
		
#ifdef SHARE_TREE_DATA
	/* If we are sharing tree data, we only create a new tree if we
	   don't already have one for this file. When using paths, we
	   only allow reuse of existing trees if the paths are absolute and
	   they match. */
	   
	/* Note that it's possible for a process to read in a profile as root and then switch
	to a normal user. First, the profile handle read as root has to remain valid; second,
	new handles acquired as a normal user must not share the data acquired as root. This is
	handled by checking whether we have read access on the file before sharing the data */
	{
		prof_mutex_lock (&g_shared_trees_mutex);
		data = g_shared_trees;
		
		while (data != NULL) {
#ifdef PROFILE_USES_PATHS
			if ((data -> filespec [0] == '/') && (filespec [0] != '/')
				&& (strcmp (data -> filespec, filespec) != 0)
				&& read_access (filespec)) {
				/* Both absolute, and they match, and we have read access to the cached copy */
					break;
			}
#else /* !PROFILE_USES_PATHS */
			if ((data -> filespec.vRefNum == filespec.vRefNum) &&
				(data -> filespec.parID == filespec.parID) &&
				(EqualString (data -> filespec.name, filespec.name, false, true))
				&& read_access (filespec)) {
				/* Match, and we have read access to the cached copy */
					break;
			}
#endif /* PROFILE_USES_PATHS */
			data = data -> next;
		}
		
		/* If we found one, we need to check whether we still have privileges to  */
		if (data != NULL) {
			data -> refcount++;
			prf -> data = data;
			*ret_prof = prf;
			retval = 0;
			prof_mutex_unlock (&g_shared_trees_mutex);
			goto end;
		}
		/* We unlock the mutex here to avoid holding the mutex while we are reading in 
		the new file */
		prof_mutex_unlock (&g_shared_trees_mutex);
	}
#endif /* SHARE_TREE_DATA */

	if (data == NULL) {
		data = malloc (sizeof (struct _prf_data_t));
	}
	
	if (data == NULL) {
		retval = ENOMEM;
		goto end;
	}
	
	memset (data, 0, sizeof (struct _prf_data_t));

#ifdef PROFILE_USES_PATHS
	len = strlen(filespec)+1;
	if (filespec[0] == '~' && filespec[1] == '/') {
		home_env = getenv("HOME");
		if (home_env)
			len += strlen(home_env);
	}

	data->filespec = malloc(len);
	if (data->filespec == NULL) {
		goto end;
	}

	if (home_env) {
		strcpy(data->filespec, home_env);
		strcat(data->filespec, filespec+1);
	} else {
		strcpy(data->filespec, filespec);
	}
#else
	data->filespec = filespec;
#endif

	prf->magic = PROF_MAGIC_FILE;
	prf -> data = data;
	data -> magic = PROF_MAGIC_FILE_DATA;
	data -> refcount = 1;

	retval = profile_update_file_data(data);
	if (retval) {
		profile_close_file(prf);
		prf = NULL;
		data = NULL;
		goto end;
	}
	
#ifdef SHARE_TREE_DATA
	/* If we are here, that means that we created a new tree and
	   we need to insert it into the global list */
	prof_mutex_lock (&g_shared_trees_mutex);
	data -> next = g_shared_trees;
	data -> flags |= PROFILE_FILE_SHARED;
	g_shared_trees = data;
	prof_mutex_unlock (&g_shared_trees_mutex);
#endif /* SHARE_TREE_DATA */

	*ret_prof = prf;
	
end:
	if (retval != 0) {
		if (prf != NULL)
			free (prf);
		if (data != NULL) {
#ifdef PROFILE_USES_PATHS
			if (data -> filespec != NULL) 
				free (data -> filespec);
#endif /* PROFILE_USES_PATHS */
			free (data);
		}
	}
	return retval;
}

errcode_t profile_update_file_data(data)
	prf_data_t data;
{
	errcode_t retval;
#ifdef HAVE_STAT
	struct stat st;
#endif
	FILE *f;
#ifdef SHARE_TREE_DATA
	int havelock = 1;
	
	prof_mutex_lock (&g_shared_trees_mutex);
	if ((data -> flags & PROFILE_FILE_SHARED) == 0) {
		/* Not shared, don't need the lock */
		havelock = 0;
		prof_mutex_unlock (&g_shared_trees_mutex);
	}
#endif /* SHARE_TREE_DATA */

#ifdef HAVE_STAT
	if (stat(data->filespec, &st)) {
		retval = errno;
		goto end;
	}
	if (st.st_mtime == data->timestamp) {
		retval = 0;
		goto end;
	}
	if (data->root) {
		profile_free_node(data->root);
		data->root = 0;
	}
	if (data->comment) {
		free(data->comment);
		data->comment = 0;
	}
#else
	/*
	 * If we don't have the stat() call, assume that our in-core
	 * memory image is correct.  That is, we won't reread the
	 * profile file if it changes.
	 */
	if (data->root) {
		retval = 0;
		goto end;
	}

#endif
	errno = 0;
#ifdef PROFILE_USES_PATHS
	f = fopen(data->filespec, "r");
#else
	f = FSp_fopen (&data->filespec, "r");
#endif
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = ENOENT;
		goto end;
	}
	data->upd_serial++;
	data->flags = 0;
	if (rw_access(data->filespec))
		data->flags |= PROFILE_FILE_RW;
	retval = profile_parse_file(f, &data->root);
	fclose(f);
	if (retval) {
		goto end;
	}

#ifdef HAVE_STAT
	data->timestamp = st.st_mtime;
#endif

end:
#ifdef SHARE_TREE_DATA
	if (havelock) 
		prof_mutex_unlock (&g_shared_trees_mutex);
#endif /* SHARE_TREE_DATA */
	return retval;
}

#ifndef PROFILE_USES_PATHS
OSErr GetMacOSTempFilespec (
	const	FSSpec*	inFileSpec,
			FSSpec*	outFileSpec)
{
	OSErr	err;
	
	err = FindFolder (inFileSpec -> vRefNum, kTemporaryFolderType,
		kCreateFolder, &(outFileSpec -> vRefNum), &(outFileSpec -> parID));
	if (err != noErr)
		return err;
		
	BlockMoveData (&(inFileSpec -> name), &(outFileSpec -> name), StrLength (inFileSpec -> name) + 1);
	return noErr;
}
#endif


errcode_t profile_flush_file_data(data)
	prf_data_t data;
{
	FILE		*f;
	profile_filespec_t new_file;
	profile_filespec_t old_file;
	errcode_t	retval = 0;
	
#ifdef SHARE_TREE_DATA
	int havelock = 1;
	
	prof_mutex_lock (&g_shared_trees_mutex);
	if ((data -> flags & PROFILE_FILE_SHARED) == 0) {
		/* Not shared, don't need the lock */
		havelock = 0;
		prof_mutex_unlock (&g_shared_trees_mutex);
	}
#endif /* SHARE_TREE_DATA */
	
	if (!data || data->magic != PROF_MAGIC_FILE_DATA) {
		retval = PROF_MAGIC_FILE_DATA;
		goto end;
	}
	
	if ((data->flags & PROFILE_FILE_DIRTY) == 0) {
		retval = 0;
		goto end;
	}

	retval = ENOMEM;
	
#ifdef PROFILE_USES_PATHS
	new_file = old_file = 0;
	new_file = malloc(strlen(data->filespec) + 5);
	if (!new_file)
		goto end;
	old_file = malloc(strlen(data->filespec) + 5);
	if (!old_file)
		goto end;

	sprintf(new_file, "%s.$$$", data->filespec);
	sprintf(old_file, "%s.bak", data->filespec);

	errno = 0;

	f = fopen(new_file, "w");
#else
	/* On MacOS, we do this by writing to a new file and then atomically
	swapping the files with a file system call */
	GetMacOSTempFilespec (&data->filespec, &new_file);
	f = FSp_fopen (&new_file, "w");
#endif
	
	if (!f) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		goto end;
	}

	profile_write_tree_file(data->root, f);
	if (fclose(f) != 0) {
		retval = errno;
		goto end;
	}

#ifdef PROFILE_USES_PATHS
	unlink(old_file);
	if (rename(data->filespec, old_file)) {
		retval = errno;
		goto end;
	}
	if (rename(new_file, data->filespec)) {
		retval = errno;
		rename(old_file, data->filespec); /* back out... */
		goto end;
	}
#else
	{
		OSErr err = FSpExchangeFiles (&data->filespec, &new_file);
		if (err != noErr) {
			retval = ENOENT;
			goto end;
		}
		FSpDelete (&new_file);
	}
#endif


	data->flags &= ~PROFILE_FILE_DIRTY;
	if (rw_access(data->filespec))
		data->flags |= PROFILE_FILE_RW;
	else
		data->flags &= ~PROFILE_FILE_RW;
	retval = 0;
	
end:
#ifdef PROFILE_USES_PATHS
	if (new_file)
		free(new_file);
	if (old_file)
		free(old_file);
#endif

#ifdef SHARE_TREE_DATA
	if (havelock)
		prof_mutex_unlock (&g_shared_trees_mutex);
#endif /* SHARE_TREE_DATA */

	return retval;
}


void profile_free_file(prf)
	prf_file_t prf;
{
	if (prf->data) {
#ifdef SHARE_TREE_DATA
		prof_mutex_lock (&g_shared_trees_mutex);
		prf->data->refcount--;
		if (prf->data->refcount == 0) {
#endif
			profile_free_file_data(prf->data);
#ifdef SHARE_TREE_DATA
		}
		prof_mutex_unlock (&g_shared_trees_mutex);
#endif
	}
		
	free(prf);

	return;
}

void profile_free_file_data(data)
	prf_data_t data;
{
#ifdef SHARE_TREE_DATA
	if ((data -> flags & PROFILE_FILE_SHARED) != 0) {
		/* Remove from the global list first */
		prof_mutex_lock (&g_shared_trees_mutex);
		if (g_shared_trees == data) {
			g_shared_trees = data -> next;
		} else {
			prf_data_t previous = g_shared_trees;
			prf_data_t next = previous -> next;
			
			while (next != NULL) {
				if (next == data) {
					previous -> next = next -> next;
					break;
				}
				
				previous = next;
				next = next -> next;
			}
		}
		prof_mutex_unlock (&g_shared_trees_mutex);
	}
#endif /* SHARE_TREE_DATA */


#ifdef PROFILE_USES_PATHS
	if (data->filespec)
		free(data->filespec);
#endif
	if (data->root)
		profile_free_node(data->root);
	if (data->comment)
		free(data->comment);
	data->magic = 0;
	free(data);

	return;
}

errcode_t profile_close_file(prf)
	prf_file_t prf;
{
	errcode_t	retval;
	
	retval = profile_flush_file_data(prf -> data);
	if (retval)
		return retval;
	profile_free_file(prf);
	return 0;
}

