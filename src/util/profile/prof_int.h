#ifndef PROF_INT_H
#define PROF_INT_H

/*
 * prof-int.h
 */

#include <time.h>

#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <TargetConditionals.h>
#include <Kerberos/com_err.h>
#include <Kerberos/FullPOSIXPath.h>
#include <Kerberos/FileCopy.h>
#include <CoreServices/CoreServices.h>
#else
#include "com_err.h"
#endif

#include "profile.h"
#ifndef ERROR_TABLE_BASE_prof
#include "prof_err.h"
#endif

#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif

#if defined(_MSDOS)
/* From k5-config.h */
#define SIZEOF_INT      2
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4
#endif 

#if defined(_WIN32)
#define SIZEOF_INT      4
#define SIZEOF_SHORT    2
#define SIZEOF_LONG     4
#endif

/* If you want the library to share read-only profile data to save memory, define SHARE_TREE_DATA */
/* If you want the library to support foreign newlines in the profile file, define PROFILE_SUPPORTS_FOREIGN_NEWLINES */
#if TARGET_OS_MAC
#define PROFILE_SUPPORTS_FOREIGN_NEWLINES 1
#define SHARE_TREE_DATA 1
#endif /* TARGET_OS_MAC */

typedef long prf_magic_t;

/*
 * This is the structure which holds profile data for a particular
 * configuration file. When using SHARE_TREE_DATA, one copy of this structure
 * can be shared among multiple profiles.
 */

struct _prf_data_t {
	prf_magic_t 			magic;			/* magic */
	profile_filespec_t		filespec;		/* file from which the configuration was read */
	char*					comment;		/* top of the file comment (I think) */
	struct profile_node*	root;			/* profile tree for this file */
	time_t					timestamp;		/* time tree last updated */
	int						upd_serial;		/* incremented every time the data changes */
	int						flags;			/* read/write, dirty/clean */
	int						refcount;		/* number of profiles sharing this data */
	struct _prf_data_t*		next;			/* next data in the list */
};

typedef struct _prf_data_t* prf_data_t;

#ifdef SHARE_TREE_DATA
#include "prof_threads.h"
/* This is the head of the global list of shared trees */
extern prf_data_t g_shared_trees;
/* This is the mutex used to lock it */
extern prof_mutex g_shared_trees_mutex;
#endif /* SHARE_TREE_DATA */

/*
 * This is the structure which stores the profile information for a
 * particular configuration file.
 */
struct _prf_file_t {
	prf_magic_t				magic;			/* magic */
	prf_data_t				data;			/* data for this file */
	struct _prf_file_t*		next;			/* next data in the profile */
};

typedef struct _prf_file_t *prf_file_t;

/*
 * The profile flags
 */
#define PROFILE_FILE_RW		0x0001
#define PROFILE_FILE_DIRTY	0x0002
#define PROFILE_FILE_SHARED	0x0004

/*
 * This structure defines the high-level, user visible profile_t
 * object, which is used as a handle by users who need to query some
 * configuration file(s)
 */
struct _profile_t {
	prf_magic_t	magic;
	prf_file_t	first_file;
};

/*
 * Used by the profile iterator in prof_get.c
 */
#define PROFILE_ITER_LIST_SECTION	0x0001
#define PROFILE_ITER_SECTIONS_ONLY	0x0002
#define PROFILE_ITER_RELATIONS_ONLY	0x0004

#define PROFILE_ITER_FINAL_SEEN		0x0100

/*
 * Check if a filespec is last in a list (NULL on UNIX, invalid FSSpec on MacOS
 */

#ifdef PROFILE_USES_PATHS
#define	PROFILE_LAST_FILESPEC(x) (((x) == NULL) || ((x)[0] == '\0'))
#else
#define PROFILE_LAST_FILESPEC(x) (((x).vRefNum == 0) && ((x).parID == 0) && ((x).name[0] == '\0'))
#endif

/* profile_parse.c */

errcode_t profile_parse_file
	PROTOTYPE((FILE *f, struct profile_node **root));

errcode_t profile_write_tree_file
	PROTOTYPE((struct profile_node *root, FILE *dstfile));


/* prof_tree.c */

void profile_free_node
	PROTOTYPE((struct profile_node *relation));

errcode_t profile_create_node
	PROTOTYPE((const char *name, const char *value,
		   struct profile_node **ret_node));

errcode_t profile_verify_node
	PROTOTYPE((struct profile_node *node));

errcode_t profile_add_node
	PROTOTYPE ((struct profile_node *section,
		    const char *name, const char *value,
		    struct profile_node **ret_node));

errcode_t profile_make_node_final
	PROTOTYPE((struct profile_node *node));
	
int profile_is_node_final
	PROTOTYPE((struct profile_node *node));

const char *profile_get_node_name
	PROTOTYPE((struct profile_node *node));

const char *profile_get_node_value
	PROTOTYPE((struct profile_node *node));

errcode_t profile_find_node
	PROTOTYPE ((struct profile_node *section,
		    const char *name, const char *value,
		    int section_flag, void **state,
		    struct profile_node **node));

errcode_t profile_find_node_relation
	PROTOTYPE ((struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, char **value));

errcode_t profile_find_node_subsection
	PROTOTYPE ((struct profile_node *section,
		    const char *name, void **state,
		    char **ret_name, struct profile_node **subsection));
		   
errcode_t profile_get_node_parent
	PROTOTYPE ((struct profile_node *section,
		   struct profile_node **parent));
		   
errcode_t profile_delete_node_relation
	PROTOTYPE ((struct profile_node *section, const char *name));

errcode_t profile_find_node_name
	PROTOTYPE ((struct profile_node *section, void **state,
		    char **ret_name));

errcode_t profile_node_iterator_create
	PROTOTYPE((profile_t profile, const char **names,
		   int flags, void **ret_iter));

void profile_node_iterator_free
	PROTOTYPE((void	**iter_p));

errcode_t profile_node_iterator
	PROTOTYPE((void	**iter_p, struct profile_node **ret_node,
		   char **ret_name, char **ret_value));

errcode_t profile_remove_node
	PROTOTYPE((struct profile_node *node));

errcode_t profile_set_relation_value
	PROTOTYPE((struct profile_node *node, const char *new_value));

errcode_t profile_rename_node
	PROTOTYPE((struct profile_node *node, const char *new_name));

/* prof_file.c */

errcode_t profile_open_file
	PROTOTYPE ((const_profile_filespec_t file, prf_file_t *ret_prof));

errcode_t profile_update_file_data
	PROTOTYPE ((prf_data_t profile));

errcode_t profile_flush_file_data
    PROTOTYPE ((prf_data_t data));
    
void profile_free_file
	PROTOTYPE ((prf_file_t profile));

void profile_free_file_data
	PROTOTYPE ((prf_data_t data));

errcode_t profile_close_file
	PROTOTYPE ((prf_file_t profile));

/* prof_init.c -- included from profile.h */

/* prof_get.c */

errcode_t profile_get_value
	PROTOTYPE ((profile_t profile, const char **names,
		    const char	**ret_value));
/* Others included from profile.h */
	
/* prof_set.c -- included from profile.h */

#endif /* PROF_INT_H */