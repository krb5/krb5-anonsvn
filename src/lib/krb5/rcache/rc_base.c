/*
Copyright 1990, Daniel J. Bernstein. All rights reserved.

Please address any questions or comments to the author at brnstnd@acf10.nyu.edu.
*/

#include <string.h>
#include <malloc.h>
#ifdef SEMAPHORE
#include <semaphore.h>
#endif
#include "rc_base.h"

static struct krb5_rc_typelist
 {
  struct krb5_rc_type *ops;
  struct krb5_rc_typelist *next;
 }
*typehead = (struct krb5_rc_typelist *) 0;

#ifdef SEMAPHORE
semaphore ex_typelist = 1;
#endif

krb5_error_code krb5_rc_register_type(ops)
struct krb5_rc_type *ops;
{
 struct krb5_rc_typelist *t;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 for (t = typehead;t && strcmp(t->ops->type,ops->type);t = t->next)
   ;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 if (t)
   return KRB5_RC_TYPE_EXISTS;
 if (!(t = (struct krb5_rc_typelist *) malloc(sizeof(struct krb5_rc_typelist))))
   return KRB5_RC_MALLOC;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 t->next = typehead;
 t->ops = ops;
 typehead = t;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 return 0;
}

krb5_error_code krb5_rc_resolve_type(id, type)
krb5_RC *id;
char *type;
{
 struct krb5_rc_typelist *t;
#ifdef SEMAPHORE
 down(&ex_typelist);
#endif
 for (t = typehead;t && strcmp(t->ops->type,type);t = t->next)
   ;
#ifdef SEMAPHORE
 up(&ex_typelist);
#endif
 if (!t)
   return KRB5_RC_TYPE_NOTFOUND;
 /* allocate *id? nah */
 (*id)->ops = t->ops;
 return 0;
}

char *krb5_rc_get_type(id)
krb5_RC id;
{
 return id->ops->type;
}

#ifdef __STDC__
char *krb5_rc_default_type(void)
#else
char *krb5_rc_default_type()
#endif
{
 char *s;
 if (s = getenv("KRB5RCACHETYPE"))
   return s;
 else
   return "dfl";
}

#ifdef notdef
#ifdef __STDC__
char *krb5_rc_default_name(void)
#else
char *krb5_rc_default_name()
#endif
{
 char *s;
 if (s = getenv("KRB5RCACHENAME"))
   return s;
 else
   return (char *) 0;
}
#endif
