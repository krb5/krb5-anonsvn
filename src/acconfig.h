/* just stuff needed by kerberos 5 */
/* This is in the top level so that it is in the same "local" directory
   as aclocal.m4, so autoreconf causes autoheader to find it. Nothing actually
   includes this file, it is always processed into something else. */

/* Don't use too large a block, because the autoheader processing can't
   handle it on some systems.  */

#undef ANSI_STDIO
#undef HAS_SETVBUF
#undef HAS_STDLIB_H
#undef HAVE_LABS
#undef HAVE_STRDUP
#undef HAS_VOID_TYPE
#undef KRB5_NO_PROTOTYPES
#undef KRB5_PROVIDE_PROTOTYPES
#undef KRB5_NO_NESTED_PROTOTYPES
#undef NO_STDLIB_H

#undef NO_YYLINENO
#undef POSIX_FILE_LOCKS
#undef POSIX_SIGTYPE
#undef POSIX_TERMIOS
#undef POSIX_TYPES
#undef USE_DIRENT_H
#undef USE_STRING_H
#undef WAIT_USES_INT
#undef krb5_sigtype
#undef HAS_UNISTD_H
#undef KRB5_USE_INET
#undef ODBM

#undef HAVE_STDARG_H
#undef HAVE_VARARGS_H

#undef HAVE_UNISTD_H

/* for lib/krb5/krb */

#undef HAVE_STRFTIME
#undef HAVE_STRPTIME
#undef HAVE_GETEUID

/* for lib/krb5/ccache/file */

#undef HAVE_FLOCK

/* for lib/krb5/os */

#undef HAVE_REGCOMP
#undef HAVE_REGEX_H
#undef HAVE_REGEXP_H
#undef HAVE_RECOMP

/* for lib/krb5/posix */

#undef HAVE_SETENV
#undef HAVE_UNSETENV
#undef HAVE_GETENV
#undef HAVE_SETSID

/* for lib/krb5/os */
#undef AN_TO_LN_RULES

/* Define if MIT Project Athena default configuration should be used */
#undef KRB5_ATHENA_COMPAT

/* Define if Kerberos V4 backwards compatibility should be supported */
#undef KRB5_KRB4_COMPAT
