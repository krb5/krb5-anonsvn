/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"
#include <memory.h>

/*
 * $Id$
 */

/* message_buffer is an input if SIGN, output if SEAL, and ignored if DEL_CTX
   conf_state is only valid if SEAL.
   */

OM_uint32
kg_unseal(context, minor_status, context_handle, input_token_buffer,
	  message_buffer, conf_state, qop_state, toktype)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_buffer_t input_token_buffer;
     gss_buffer_t message_buffer;
     int *conf_state;
     int *qop_state;
     int toktype;
{
   krb5_gss_ctx_id_rec *ctx;
   krb5_error_code code;
   int bodysize;
   int tmsglen;
   int conflen;
   int signalg;
   int sealalg;
   gss_buffer_desc token;
   unsigned char *ptr;
   krb5_checksum desmac;
   krb5_checksum md5cksum;
   char *data_ptr;
   unsigned char *cksum;
   krb5_timestamp now;
   unsigned char *plain;
   int plainlen;
   int err;
   int direction;
   unsigned int seqnum;
   OM_uint32 retval;

   if (toktype == KG_TOK_SEAL_MSG) {
      message_buffer->length = 0;
      message_buffer->value = NULL;
   }

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      *minor_status = KG_CTX_INCOMPLETE;
      return(GSS_S_NO_CONTEXT);
   }

   /* parse the token, leave the data in message_buffer, setting conf_state */

   /* verify the header */

   ptr = (unsigned char *) input_token_buffer->value;

   if (err = g_verify_token_header((gss_OID) gss_mech_krb5, &bodysize,
				   &ptr, toktype,
				   input_token_buffer->length)) {
      *minor_status = err;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   if (toktype == KG_TOK_SEAL_MSG)
      tmsglen = bodysize-22;

   /* get the sign and seal algorithms */

   signalg = ptr[0] + (ptr[1]<<8);
   sealalg = ptr[2] + (ptr[3]<<8);

   if (((signalg != 0) && (signalg != 1)) ||
       ((toktype != KG_TOK_SEAL_MSG) && (sealalg != 0xffff)) ||
       ((toktype == KG_TOK_SEAL_MSG) && 
	((sealalg != 0xffff) && (sealalg != 0))) ||
       (ptr[4] != 0xff) ||
       (ptr[5] != 0xff)) {
      *minor_status = 0;
      return(GSS_S_DEFECTIVE_TOKEN);
   }

   /* get the token parameters */

   /* decode the message, if SEAL */

   if (toktype == KG_TOK_SEAL_MSG) {
      if (sealalg == 0) {
	 if ((plain = (unsigned char *) xmalloc(tmsglen)) == NULL) {
	    *minor_status = ENOMEM;
	    return(GSS_S_FAILURE);
	 }

	 if (code = kg_decrypt(&ctx->enc, NULL, ptr+22, plain, tmsglen)) {
	    xfree(plain);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
      } else {
	 plain = ptr+22;
      }

      plainlen = tmsglen;

      if (sealalg && ctx->big_endian) {
	 token.length = tmsglen;
      } else {
	 conflen = kg_confounder_size(&ctx->enc);
	 token.length = tmsglen - conflen - plain[tmsglen-1];
      }

      if (token.length) {
	 if ((token.value = xmalloc(token.length)) == NULL) {
	    if (sealalg == 0)
	       xfree(plain);
	    *minor_status = ENOMEM;
	    return(GSS_S_FAILURE);
	 }

	 if (sealalg && ctx->big_endian)
	    memcpy(token.value, plain, token.length);
	 else
	    memcpy(token.value, plain+conflen, token.length);
      }
   } else if (toktype == KG_TOK_SIGN_MSG) {
      token = *message_buffer;
      plain = token.value;
      plainlen = token.length;
   } else {
      token.length = 0;
      token.value = NULL;
      plain = token.value;
      plainlen = token.length;
   }

   /* compute the checksum of the message */

   if (signalg == 0) {
      /* compute the checksum of the message */

      /* 8 = bytes of token body to be checksummed according to spec */

      if (! (data_ptr =
	     xmalloc(8 + (ctx->big_endian ? token.length : plainlen)))) {
	  if (sealalg == 0)
	      xfree(plain);
	  if (toktype == KG_TOK_SEAL_MSG)
	      xfree(token.value);
	  *minor_status = ENOMEM;
	  return(GSS_S_FAILURE);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      if (ctx->big_endian)
	  (void) memcpy(data_ptr+8, token.value, token.length);
      else
	  (void) memcpy(data_ptr+8, plain, plainlen);
      code = krb5_calculate_checksum(context, CKSUMTYPE_RSA_MD5, data_ptr, 8 +
				     (ctx->big_endian ? token.length :
				      plainlen), 0, 0, &md5cksum);
      xfree(data_ptr);
      if (code) {
	  if (sealalg == 0)
	      xfree(plain);
	  if (toktype == KG_TOK_SEAL_MSG)
	      xfree(token.value);
	  *minor_status = code;
	  return(GSS_S_FAILURE);
      }

      if (sealalg == 0)
	 xfree(plain);

      /* XXX this depends on the key being a single-des key, but that's
	 all that kerberos supports right now */

      code = krb5_calculate_checksum(context, CKSUMTYPE_DESCBC,
				     md5cksum.contents, 16,
				     ctx->seq.key->contents, 
				     ctx->seq.key->length,
				     &desmac);
      krb5_xfree(md5cksum.contents);
      if (code) {
	 if (toktype == KG_TOK_SEAL_MSG)
	    xfree(token.value);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      cksum = desmac.contents;
   } else {
      if (! ctx->seed_init) {
	 if (code = kg_make_seed(ctx->subkey, ctx->seed)) {
	    if (sealalg == 0)
	       xfree(plain);
	    if (toktype == KG_TOK_SEAL_MSG)
	       xfree(token.value);
	    *minor_status = code;
	    return(GSS_S_FAILURE);
	 }
	 ctx->seed_init = 1;
      }

      if (! (data_ptr =
	     xmalloc(8 + (ctx->big_endian ? token.length : plainlen)))) {
	  if (sealalg == 0)
	      xfree(plain);
	  if (toktype == KG_TOK_SEAL_MSG)
	      xfree(token.value);
	  *minor_status = ENOMEM;
	  return(GSS_S_FAILURE);
      }
      (void) memcpy(data_ptr, ptr-2, 8);
      if (ctx->big_endian)
	  (void) memcpy(data_ptr+8, token.value, token.length);
      else
	  (void) memcpy(data_ptr+8, plain, plainlen);
      code = krb5_calculate_checksum(context, CKSUMTYPE_RSA_MD5, data_ptr, 8 +
				     (ctx->big_endian ? token.length :
				      plainlen), 0, 0, &md5cksum);
      xfree(data_ptr);
      if (code) {
	  if (sealalg == 0)
	      xfree(plain);
	  if (toktype == KG_TOK_SEAL_MSG)
	      xfree(token.value);
	  *minor_status = code;
	  return(GSS_S_FAILURE);
      }
      cksum = md5cksum.contents;

      if (sealalg == 0)
	 xfree(plain);
   }
      
   /* compare the computed checksum against the transmitted checksum */

   code = memcmp(cksum, ptr+14, 8);
   /* XXX krb5_free_checksum_contents() ? */
   krb5_xfree(cksum);

   if (code) {
      if (toktype == KG_TOK_SEAL_MSG)
	 xfree(token.value);
      *minor_status = 0;
      return(GSS_S_BAD_SIG);
   }

   /* it got through unscathed.  Make sure the context is unexpired */

   if (toktype == KG_TOK_SEAL_MSG)
      *message_buffer = token;

   if (conf_state)
      *conf_state = (sealalg == 0);

   if (qop_state)
      *qop_state = GSS_C_QOP_DEFAULT;

   if (code = krb5_timeofday(context, &now)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (now > ctx->endtime) {
      *minor_status = 0;
      return(GSS_S_CONTEXT_EXPIRED);
   }

   /* do sequencing checks */

   if (code = kg_get_seq_num(&(ctx->seq), ptr+14, ptr+6, &direction,
			     &seqnum)) {
      if (toktype == KG_TOK_SEAL_MSG)
	 xfree(token.value);
      *minor_status = code;
      return(GSS_S_BAD_SIG);
   }

   if ((ctx->initiate && direction != 0xff) ||
       (!ctx->initiate && direction != 0)) {
      if (toktype == KG_TOK_SEAL_MSG)
	 xfree(token.value);
      *minor_status = G_BAD_DIRECTION;
      return(GSS_S_BAD_SIG);
   }

   retval = g_order_check(&(ctx->seqstate), seqnum);
   
   /* success or ordering violation */

   *minor_status = 0;
   return(retval);
}
