/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 * 
 * $Log$
 * Revision 1.1.2.1  1996/06/20 21:49:56  marc
 * File added to the repository on a branch
 *
 * Revision 1.1  1993/12/15  00:05:16  bjaspan
 * Initial revision
 *
 * Revision 1.1  1993/12/15  00:04:37  bjaspan
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <ovsec_admin/admin.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <com_err.h>

/* XXX */
#define krb5_free_keyblock_contents(k) (free((k)->contents))

#define ARGV0 "kdbkeys"

krb5_principal	    master_princ;
krb5_encrypt_block  master_encblock;
krb5_keyblock	    master_keyblock;

krb5_error_code dump_iterator(krb5_pointer ptr, krb5_db_entry *entry)
{
   krb5_error_code code;
   char *name;
   krb5_keyblock key;
   int i;

   if (code = krb5_unparse_name(entry->principal, &name)) {
      com_err(ARGV0, code, "while unparsing principal");
      exit(1);
   }

   if (code = krb5_kdb_decrypt_key(&master_encblock, &entry->key, &key)) { 
      com_err(ARGV0, code, "in krb5_kdb_decrypt_key");
      exit(1);
   }

   printf("%s\t", name);

   for (i=0; i<key.length; i++) {
      printf("%02x", key.contents[i]);
   }

   printf("\n");

   krb5_free_keyblock_contents(&key);
   free(name);
}

int main(int argc, char *argv[])
{
   krb5_error_code code;

   krb5_init_ets();

   if (code = kdb_init_master(NULL, 0)) {
      com_err(ARGV0, code, "from kdb_init_master");
      exit(1);
   }

   (void) krb5_db_iterate(dump_iterator, NULL);

   exit(0);
}
