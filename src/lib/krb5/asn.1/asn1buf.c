/* Coding Buffer Implementation */

/*
  Implementation

    Encoding mode

    The encoding buffer is filled from bottom (lowest address) to top
    (highest address).  This makes it easier to expand the buffer,
    since realloc preserves the existing portion of the buffer.

    Note: Since ASN.1 encoding must be done in reverse, this means
    that you can't simply memcpy out the buffer data, since it will be
    backwards.  You need to reverse-iterate through it, instead.

    ***This decision may have been a mistake.  In practice, the
    implementation will probably be tuned such that reallocation is
    rarely necessary.  Also, the realloc probably has recopy the
    buffer itself, so we don't really gain that much by avoiding an
    explicit copy of the buffer.  --Keep this in mind for future reference.


    Decoding mode

    The decoding buffer is in normal order and is created by wrapping
    an asn1buf around a krb5_data structure.
  */

/* Abstraction Function

   Programs should use just pointers to asn1buf's (e.g. asn1buf *mybuf).
   These pointers must always point to a valid, allocated asn1buf
   structure or be NULL.

   The contents of the asn1buf represent an octet string.  This string
   begins at base and continues to the octet immediately preceding next.
   If next == base or mybuf == NULL, then the asn1buf represents an empty
   octet string. */

/* Representation Invariant

   Pointers to asn1buf's must always point to a valid, allocated
   asn1buf structure or be NULL.

   base points to a valid, allocated octet array or is NULL
   next >= base
   next <= bound+2  (i.e. next should be able to step just past the bound,
                     but no further.  (The bound should move out in response
		     to being crossed by next.)) */

#include "asn1buf.h"
#include <stdlib.h>

asn1_error_code asn1buf_create(DECLARG(asn1buf **, buf))
     OLDDECLARG(asn1buf **, buf)
{
  *buf = (asn1buf*)calloc(1,sizeof(asn1buf));
  if (*buf == NULL) return ENOMEM;
  (*buf)->base = NULL;
  (*buf)->bound = NULL;
  (*buf)->next = NULL;
  return 0;
}

asn1_error_code asn1buf_wrap_data(DECLARG(asn1buf *, buf),
				  DECLARG(const krb5_data *, code))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const krb5_data *, code)
{
  if(code == NULL || code->data == NULL) return ASN1_MISSING_FIELD;
  buf->next = buf->base = code->data;
  buf->bound = code->data + code->length - 1;
  return 0;
}

asn1_error_code asn1buf_imbed(DECLARG(asn1buf *, subbuf),
			      DECLARG(const asn1buf *, buf),
			      DECLARG(const int , length))
     OLDDECLARG(asn1buf *, subbuf)
     OLDDECLARG(const asn1buf *, buf)
     OLDDECLARG(const int , length)
{
  subbuf->base = subbuf->next = buf->next;
  subbuf->bound = subbuf->base + length - 1;
  if(subbuf->bound > buf->bound) return ASN1_OVERRUN;
  return 0;
}

void asn1buf_sync(DECLARG(asn1buf *, buf),
		  DECLARG(asn1buf *, subbuf))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(asn1buf *, subbuf)
{
  buf->next = subbuf->next;
}

asn1_error_code asn1buf_destroy(DECLARG(asn1buf **, buf))
     OLDDECLARG(asn1buf **, buf)
{
  if (*buf != NULL) {
    if ((*buf)->base != NULL) free((*buf)->base);
    free(*buf);
    *buf = NULL;
  }
  return 0;
}

asn1_error_code asn1buf_insert_octet(DECLARG(asn1buf *, buf),
				     DECLARG(const asn1_octet , o))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const asn1_octet , o)
{
  asn1_error_code retval;

  retval = asn1buf_ensure_space(buf,1);
  if(retval) return retval;
  *(buf->next) = (char)o;
  (buf->next)++;
  return 0;
}

asn1_error_code asn1buf_insert_octetstring(DECLARG(asn1buf *, buf),
					   DECLARG(const int , len),
					   DECLARG(const krb5_octet *, s))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const krb5_octet *, s)
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_ensure_space(buf,len);
  if(retval) return retval;
  for(length=1; length<=len; length++,(buf->next)++)
    *(buf->next) = (char)(s[len-length]);
  return 0;
}

asn1_error_code asn1buf_insert_charstring(DECLARG(asn1buf *, buf),
					  DECLARG(const int , len),
					  DECLARG(const char *, s))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(const char *, s)
{
  asn1_error_code retval;
  int length;

  retval = asn1buf_ensure_space(buf,len);
  if(retval) return retval;
  for(length=1; length<=len; length++,(buf->next)++)
    *(buf->next) = (char)(s[len-length]);
  return 0;
}

asn1_error_code asn1buf_remove_octet(DECLARG(asn1buf *, buf),
				     DECLARG(asn1_octet *, o))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(asn1_octet *, o)
{
  if(buf->next > buf->bound) return ASN1_OVERRUN;
  *o = (asn1_octet)(*((buf->next)++));
  return 0;
}

asn1_error_code asn1buf_remove_octetstring(DECLARG(asn1buf *, buf),
					   DECLARG(const int , len),
					   DECLARG(asn1_octet **, s))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(asn1_octet **, s)
{
  int i;

  if(buf->next + len - 1 > buf->bound) return ASN1_OVERRUN;
  *s = (asn1_octet*)calloc(len,sizeof(asn1_octet));
  if(*s == NULL) return ENOMEM;
  for(i=0; i<len; i++)
    (*s)[i] = (asn1_octet)(buf->next)[i];
  buf->next += len;
  return 0;
}

asn1_error_code asn1buf_remove_charstring(DECLARG(asn1buf *, buf),
					  DECLARG(const int , len),
					  DECLARG(char **, s))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , len)
     OLDDECLARG(char **, s)
{
  int i;

  if(buf->next + len - 1 > buf->bound) return ASN1_OVERRUN;
  *s = (char*)calloc(len,sizeof(char));
  if(*s == NULL) return ENOMEM;
  for(i=0; i<len; i++)
    (*s)[i] = (char)(buf->next)[i];
  buf->next += len;
  return 0;
}

int asn1buf_remains(DECLARG(const asn1buf *, buf))
     OLDDECLARG(const asn1buf *, buf)
{
  if(buf == NULL || buf->base == NULL) return 0;
  else return buf->bound - buf->next + 1;
}

asn1_error_code asn12krb5_buf(DECLARG(const asn1buf *, buf),
			      DECLARG(krb5_data **, code))
     OLDDECLARG(const asn1buf *, buf)
     OLDDECLARG(krb5_data **, code)
{
  int i;
  *code = (krb5_data*)calloc(1,sizeof(krb5_data));
  if(*code == NULL) return ENOMEM;
  (*code)->data = NULL;
  (*code)->length = 0;
  (*code)->length = asn1buf_len(buf);
  (*code)->data = (char*)calloc(((*code)->length)+1,sizeof(char));
  for(i=0; i < (*code)->length; i++)
    ((*code)->data)[i] = (buf->base)[((*code)->length)-i-1];
  ((*code)->data)[(*code)->length] = '\0';
  return 0;
}



/* These parse and unparse procedures should be moved out. They're
   useful only for debugging and superfluous in the production version. */

asn1_error_code asn1buf_unparse(DECLARG(const asn1buf *, buf),
				DECLARG(char **, s))
     OLDDECLARG(const asn1buf *, buf)
     OLDDECLARG(char **, s)
{
  if(*s != NULL) free(*s);
  if(buf == NULL){
    *s = calloc(sizeof("<NULL>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(buf->base == NULL){
    *s = calloc(sizeof("<EMPTY>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int length = asn1buf_len(buf);
    int i;

    *s = calloc(length+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    (*s)[length] = '\0';
    for(i=0; i<length; i++)
      OLDDECLARG( (*s)[i] = , (buf->base)[length-i-1])
  }
  return 0;
}

asn1_error_code asn1buf_hex_unparse(DECLARG(const asn1buf *, buf),
				    DECLARG(char **, s))
     OLDDECLARG(const asn1buf *, buf)
     OLDDECLARG(char **, s)
{
#define hexchar(d) ((d)<=9 ? ('0'+(d)) :\
		    ((d)<=15 ? ('A'+(d)-10) :\
		    'X'))

  if(*s != NULL) free(*s);

  if(buf == NULL){
    *s = calloc(sizeof("<NULL>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<NULL>");
  }else if(buf->base == NULL){
    *s = calloc(sizeof("<EMPTY>")+1, sizeof(char));
    if(*s == NULL) return ENOMEM;
    strcpy(*s,"<EMPTY>");
  }else{
    int length = asn1buf_len(buf);
    int i;

    *s = calloc(3*length, sizeof(char));
    if(*s == NULL) return ENOMEM;
    for(i = length-1; i >= 0; i--){
      (*s)[3*(length-i-1)] = hexchar(((buf->base)[i]&0xF0)>>4);
      (*s)[3*(length-i-1)+1] = hexchar((buf->base)[i]&0x0F);
      (*s)[3*(length-i-1)+2] = ' ';
    }
    (*s)[3*length-1] = '\0';
  }
  return 0;
}

/****************************************************************/
/* Private Procedures */

int asn1buf_size(DECLARG(const asn1buf *, buf))
     OLDDECLARG(const asn1buf *, buf)
{
  if(buf == NULL || buf->base == NULL) return 0;
  return buf->bound - buf->base + 1;
}

int asn1buf_free(DECLARG(const asn1buf *, buf))
     OLDDECLARG(const asn1buf *, buf)
{
  if(buf == NULL || buf->base == NULL) return 0;
  else return buf->bound - buf->next + 1;
}

asn1_error_code asn1buf_ensure_space(DECLARG(asn1buf *, buf),
				     DECLARG(const int , amount))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , amount)
{
  int free = asn1buf_free(buf);
  if(free < amount){
    asn1_error_code retval = asn1buf_expand(buf, amount-free);
    if(retval) return retval;
  }
  return 0;
}

asn1_error_code asn1buf_expand(DECLARG(asn1buf *, buf),
			       DECLARG(const int , inc))
     OLDDECLARG(asn1buf *, buf)
     OLDDECLARG(const int , inc)
{
#define STANDARD_INCREMENT 200
  int next_offset = buf->next - buf->base;
  int bound_offset;
  if(buf->base == NULL) bound_offset = -1;
  else bound_offset = buf->bound - buf->base;

  
  buf->base = realloc(buf->base,
		      (asn1buf_size(buf)+(inc>STANDARD_INCREMENT ?
					  inc : STANDARD_INCREMENT))
		      * sizeof(asn1_octet));
  if(buf->base == NULL) return ENOMEM;
  buf->bound = (buf->base) + bound_offset + inc;
  buf->next = (buf->base) + next_offset;
  return 0;
}

int asn1buf_len(DECLARG(const asn1buf *, buf))
     OLDDECLARG(const asn1buf *, buf)
{
  return buf->next - buf->base;
}
