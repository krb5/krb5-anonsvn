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
#ifndef NO_PWD_H
#include <pwd.h>
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

#ifdef COPY_RESOURCE_FORK
#include <Kerberos/FileCopy.h>
#endif

static int read_write_access(filespec)
	profile_filespec_t filespec;
{
#ifdef HAVE_ACCESS
	if (access(filespec, R_OK | W_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the read and write permissions.
	 */
	FILE	*f;

	f = fopen(filespec, "r+");
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

	f = fopen(filespec, "r+");
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
	errcode_t	retval = 0;
	char		*filespecExpandedPath = NULL;
    int			filespecExpandedPathLen = strlen (filespec) + 1;
    struct passwd *pw = NULL;
    
	if (filespec[0] == '~' && filespec[1] == '/') {
        /* Get the homedir for homedir relative paths */
        /* client might be setuid root so favor euid but avoid root */
        uid_t uid = (geteuid () == 0) ? getuid () : geteuid ();
        
        /* Use the password database instead of an environment variable */
        /* because getenv defeats the krb5 "secure" context */
        pw = getpwuid (uid);
    
        if ((pw != NULL) && (strlen (pw->pw_dir) > 0)) {
            filespecExpandedPathLen += strlen (pw->pw_dir);
        }
    }
    
    filespecExpandedPath = (char *) malloc (filespecExpandedPathLen* sizeof (char));
    if (filespecExpandedPath == NULL) {
        retval = ENOMEM;
        goto end;
    }
    
	if (filespec[0] == '~' && filespec[1] == '/') {
        if ((pw != NULL) && (strlen (pw->pw_dir) > 0)) {
            strcpy (filespecExpandedPath, pw->pw_dir);
            strcpy (&filespecExpandedPath[strlen (pw->pw_dir)], &filespec[1]);
        } else {
            strcpy (filespecExpandedPath, &filespec[1]);
        }
    } else {
        /* Absolute path, just copy */
        strcpy (filespecExpandedPath, filespec);
    }
    
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
            /* check for absolute paths */
			if ((strcmp (data -> filespec, filespecExpandedPath) == 0) && read_access (data->filespec)) {
				/* They match, and we have read access to the cached copy */
                break;
			}
			data = data -> next;
		}
		
		/* If we found one, we need to check whether we still have privileges to  */
		if (data != NULL) {
			data -> refcount++;
			prf -> data = data;
			*ret_prof = prf;
			retval = profile_update_file_data (data); /* make sure the saved file hasn't changed */
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

    /* Since we already made a copy to expand homedir relative paths, just absorb it */
	data->filespec = filespecExpandedPath;
    filespecExpandedPath = NULL; /* remember we're saving it */
    
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
    if (filespecExpandedPath != NULL) {
        free (filespecExpandedPath);
    }
	if (retval != 0) {
		if (prf != NULL)
			free (prf);
		if (data != NULL) {
			if (data -> filespec != NULL) 
				free (data -> filespec);
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
	f = fopen(data->filespec, "r");
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = ENOENT;
		goto end;
	}
	data->upd_serial++;
	data->flags = 0;
	if (read_write_access(data->filespec))
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


errcode_t profile_flush_file_data(data)
	prf_data_t data;
{
	FILE		*f;
	profile_filespec_t new_file;
	profile_filespec_t old_file;
	errcode_t	retval = 0;
	
#ifdef SHARE_TREE_DATA
	int havelock = 1;
#endif

	new_file = old_file = 0;

#ifdef SHARE_TREE_DATA	
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
        
#ifdef COPY_RESOURCE_FORK
	{
		FSSpec from;
		FSSpec to;
		OSErr err = FSpLocationFromFullPOSIXPath (data -> filespec, &from);
		if (err == noErr) {
			err = FSpLocationFromFullPOSIXPath (new_file, &to);
		}
		if (err == noErr) {
			err = FSpResourceForkCopy (&from, &to);
		}
		if (err != noErr) {
			retval = ENOENT;
			goto end;
		}
	}
#endif

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

	data->flags &= ~PROFILE_FILE_DIRTY;
	if (read_write_access(data->filespec))
		data->flags |= PROFILE_FILE_RW;
	else
		data->flags &= ~PROFILE_FILE_RW;
	retval = 0;
	
end:
	if (new_file)
		free(new_file);
	if (old_file)
		free(old_file);

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


	if (data->filespec)
		free(data->filespec);
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

