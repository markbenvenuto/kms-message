/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"){}
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kms_crypto.h"
#include "kms_kv_list.h"
#include "kms_message.h"
#include "kms_private.h"
#include "kms_request_str.h"

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define CHECK_FAILED         \
   do {                      \
      if (request->failed) { \
         return false;       \
      }                      \
   } while (0)

struct _kms_request_t {
   char error[512];
   bool failed;
   kms_request_str_t *region;
   kms_request_str_t *service;
   kms_request_str_t *access_key_id;
   kms_request_str_t *secret_key;
   kms_request_str_t *method;
   kms_request_str_t *path;
   kms_request_str_t *query;
   kms_request_str_t *payload;
   kms_request_str_t *datetime;
   kms_request_str_t *date;
   kms_kv_list_t *query_params;
   kms_kv_list_t *header_fields;
};


static kms_kv_list_t *
parse_query_params (kms_request_str_t *q)
{
   kms_kv_list_t *lst = kms_kv_list_new ();
   char *p = q->str;
   char *end = q->str + q->len;
   char *amp, *equals;
   kms_request_str_t *k, *v;

   do {
      equals = strchr ((const char *) p, '=');
      assert (equals);
      amp = strchr ((const char *) equals, '&');
      if (!amp) {
         amp = end;
      }

      k = kms_request_str_new_from_chars (p, equals - p);
      v = kms_request_str_new_from_chars (equals + 1, amp - equals - 1);
      kms_kv_list_add (lst, k, v);
      kms_request_str_destroy (k);
      kms_request_str_destroy (v);

      p = amp + 1;
   } while (p < end);

   return lst;
}

kms_request_t *
kms_request_new (const char *method, const char *path_and_query)
{
   const char *question_mark;
   kms_request_t *request = calloc (sizeof (kms_request_t), 1);

   request->region = kms_request_str_new ();
   request->service = kms_request_str_new ();
   request->access_key_id = kms_request_str_new ();
   request->secret_key = kms_request_str_new ();

   question_mark = strchr (path_and_query, '?');
   if (question_mark) {
      request->path = kms_request_str_new_from_chars (
         path_and_query, question_mark - path_and_query);
      request->query = kms_request_str_new_from_chars (question_mark + 1, -1);
      request->query_params = parse_query_params (request->query);
   } else {
      request->path = kms_request_str_new_from_chars (path_and_query, -1);
      request->query = kms_request_str_new ();
      request->query_params = kms_kv_list_new ();
   }

   request->failed = false;
   request->payload = kms_request_str_new ();
   request->datetime = kms_request_str_new ();
   request->date = kms_request_str_new ();
   request->method = kms_request_str_new_from_chars (method, -1);
   request->header_fields = kms_kv_list_new ();

   return request;
}

void
kms_request_destroy (kms_request_t *request)
{
   kms_request_str_destroy (request->region);
   kms_request_str_destroy (request->service);
   kms_request_str_destroy (request->access_key_id);
   kms_request_str_destroy (request->secret_key);
   kms_request_str_destroy (request->method);
   kms_request_str_destroy (request->path);
   kms_request_str_destroy (request->query);
   kms_request_str_destroy (request->payload);
   kms_request_str_destroy (request->datetime);
   kms_request_str_destroy (request->date);
   kms_kv_list_destroy (request->query_params);
   kms_kv_list_destroy (request->header_fields);
   free (request);
}

const char *
kms_request_get_error (kms_request_t *request)
{
   return request->failed ? request->error : NULL;
}

bool
kms_request_set_region (kms_request_t *request, const char *region)
{
   kms_request_str_set_chars (request->region, region);
   return true;
}

bool
kms_request_set_service (kms_request_t *request, const char *service)
{
   kms_request_str_set_chars (request->service, service);
   return true;
}

bool
kms_request_set_access_key_id (kms_request_t *request, const char *akid)
{
   kms_request_str_set_chars (request->access_key_id, akid);
   return true;
}

bool
kms_request_set_secret_key (kms_request_t *request, const char *key)
{
   kms_request_str_set_chars (request->secret_key, key);
   return true;
}

bool
kms_request_add_header_field_from_chars (kms_request_t *request,
                                         const char *field_name,
                                         const char *value)
{
   kms_request_str_t *k, *v;
   char *t;

   CHECK_FAILED;

   k = kms_request_str_new_from_chars (field_name, -1);
   v = kms_request_str_new_from_chars (value, -1);
   kms_kv_list_add (request->header_fields, k, v);

   /* get date from X-Amz-Date header like "20150830T123600Z", split on "T" */
   if (!strcasecmp (field_name, "X-Amz-Date")) {
      kms_request_str_destroy (request->date);
      if ((t = strchr (v->str, 'T'))) {
         request->date = kms_request_str_new_from_chars (v->str, t - v->str);
      } else {
         request->date = kms_request_str_dup (v);
      }

      kms_request_str_destroy (request->datetime);
      request->datetime = v;
   } else {
      kms_request_str_destroy (v);
   }

   kms_request_str_destroy (k);

   return true;
}

bool
kms_request_append_header_field_value_from_chars (kms_request_t *request,
                                                  const char *value,
                                                  size_t len)
{
   kms_request_str_t *v;

   CHECK_FAILED;

   if (request->header_fields->len == 0) {
      /* TODO: set error */
      return false;
   }

   v = request->header_fields->kvs[request->header_fields->len - 1].value;
   kms_request_str_append_chars (v, value, len);

   return true;
}

bool
kms_request_append_payload_from_chars (kms_request_t *request,
                                       const char *payload,
                                       size_t len)
{
   CHECK_FAILED;

   kms_request_str_append_chars (request->payload, payload, len);

   return true;
}

static void
append_canonical_query (kms_request_t *request, kms_request_str_t *str)
{
   size_t i;
   kms_kv_list_t *lst;

   if (!request->query_params->len) {
      return;
   }

   lst = kms_kv_list_sorted (request->query_params);

   for (i = 0; i < lst->len; i++) {
      kms_request_str_append_escaped (str, lst->kvs[i].key, true);
      kms_request_str_append_char (str, '=');
      kms_request_str_append_escaped (str, lst->kvs[i].value, true);

      if (i < lst->len - 1) {
         kms_request_str_append_char (str, '&');
      }
   }
}

static void
append_canonical_headers (kms_kv_list_t *lst, kms_request_str_t *str)
{
   size_t i;

   /* aws docs: "To create the canonical headers list, convert all header names
    * to lowercase and remove leading spaces and trailing spaces. Convert
    * sequential spaces in the header value to a single space." */
   for (i = 0; i < lst->len; i++) {
      kms_request_str_append_lowercase (str, lst->kvs[i].key);
      kms_request_str_append_char (str, ':');
      kms_request_str_append_stripped (str, lst->kvs[i].value);
      kms_request_str_append_newline (str);
   }
}

static void
append_signed_headers (kms_kv_list_t *lst, kms_request_str_t *str)
{
   size_t i;

   for (i = 0; i < lst->len; i++) {
      kms_request_str_append_lowercase (str, lst->kvs[i].key);
      if (i < lst->len - 1) {
         kms_request_str_append_char (str, ';');
      }
   }
}

kms_request_str_t *
kms_request_get_canonical (kms_request_t *request)
{
   kms_request_str_t *canonical;
   kms_kv_list_t *lst;

   if (request->failed) {
      return NULL;
   }

   /* AWS docs: "you must include the host header at a minimum" */
   assert (request->header_fields->len >= 1);
   lst = kms_kv_list_sorted (request->header_fields);

   canonical = kms_request_str_new ();
   kms_request_str_append (canonical, request->method);
   kms_request_str_append_newline (canonical);
   kms_request_str_append_escaped (canonical, request->path, false);
   kms_request_str_append_newline (canonical);
   append_canonical_query (request, canonical);
   kms_request_str_append_newline (canonical);
   append_canonical_headers (lst, canonical);
   kms_request_str_append_newline (canonical);
   append_signed_headers (lst, canonical);
   kms_request_str_append_newline (canonical);
   kms_request_str_append_hashed (canonical, request->payload);

   kms_kv_list_destroy (lst);

   return canonical;
}

kms_request_str_t *
kms_request_get_string_to_sign (kms_request_t *request)
{
   bool success = false;
   kms_request_str_t *sts;
   kms_request_str_t *creq = NULL; /* canonical request */

   if (request->failed) {
      return NULL;
   }

   sts = kms_request_str_new ();
   kms_request_str_append_chars (sts, "AWS4-HMAC-SHA256\n", -1);
   kms_request_str_append (sts, request->datetime);
   kms_request_str_append_newline (sts);

   /* credential scope, like "20150830/us-east-1/service/aws4_request" */
   kms_request_str_append (sts, request->date);
   kms_request_str_append_char (sts, '/');
   kms_request_str_append (sts, request->region);
   kms_request_str_append_char (sts, '/');
   kms_request_str_append (sts, request->service);
   kms_request_str_append_chars (sts, "/aws4_request\n", -1);

   creq = kms_request_get_canonical (request);
   if (!kms_request_str_append_hashed (sts, creq)) {
      goto done;
   }

   success = true;
done:
   kms_request_str_destroy (creq);
   if (!success) {
      kms_request_str_destroy (sts);
      sts = NULL;
   }

   return sts;
}

static bool
kms_request_hmac (unsigned char *out,
                  kms_request_str_t *key,
                  kms_request_str_t *data)
{
   return HMAC (EVP_sha256 (),
                key->str,
                (int) key->len,
                (unsigned char *) data->str,
                data->len,
                out,
                NULL) != NULL;
}

static bool
kms_request_hmac_again (unsigned char *out,
                        unsigned char *in,
                        kms_request_str_t *data)
{
   return HMAC (EVP_sha256 (),
                in,
                32,
                (unsigned char *) data->str,
                data->len,
                out,
                NULL) != NULL;
}

bool
kms_request_get_signing_key (kms_request_t *request, unsigned char *key)
{
   bool success = false;
   kms_request_str_t *aws4_plus_secret = NULL;
   kms_request_str_t *aws4_request = NULL;
   unsigned char k_date[32];
   unsigned char k_region[32];
   unsigned char k_service[32];

   /* docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    * Pseudocode for deriving a signing key
    *
    * kSecret = your secret access key
    * kDate = HMAC("AWS4" + kSecret, Date)
    * kRegion = HMAC(kDate, Region)
    * kService = HMAC(kRegion, Service)
    * kSigning = HMAC(kService, "aws4_request")
    */
   aws4_plus_secret = kms_request_str_new_from_chars ("AWS4", -1);
   kms_request_str_append (aws4_plus_secret, request->secret_key);

   aws4_request = kms_request_str_new_from_chars ("aws4_request", -1);

   if (!(kms_request_hmac (k_date, aws4_plus_secret, request->date) &&
         kms_request_hmac_again (k_region, k_date, request->region) &&
         kms_request_hmac_again (k_service, k_region, request->service) &&
         kms_request_hmac_again (key, k_service, aws4_request))) {
      goto done;
   }

   success = true;
done:
   kms_request_str_destroy (aws4_plus_secret);
   kms_request_str_destroy (aws4_request);

   return success;
}

kms_request_str_t *
kms_request_get_signature (kms_request_t *request)
{
   bool success = false;
   kms_kv_list_t *lst = NULL;
   kms_request_str_t *sig = NULL;
   kms_request_str_t *sts = NULL;
   unsigned char signing_key[32];
   unsigned char signature[32];

   if (request->failed) {
      return NULL;
   }

   sts = kms_request_get_string_to_sign (request);
   if (!sts) {
      goto done;
   }

   sig = kms_request_str_new ();
   kms_request_str_append_chars (sig, "AWS4-HMAC-SHA256 Credential=", -1);
   kms_request_str_append (sig, request->access_key_id);
   kms_request_str_append_char (sig, '/');
   kms_request_str_append (sig, request->date);
   kms_request_str_append_char (sig, '/');
   kms_request_str_append (sig, request->region);
   kms_request_str_append_char (sig, '/');
   kms_request_str_append (sig, request->service);
   kms_request_str_append_chars (sig, "/aws4_request, SignedHeaders=", -1);
   lst = kms_kv_list_sorted (request->header_fields);
   append_signed_headers (lst, sig);
   kms_request_str_append_chars (sig, ", Signature=", -1);
   if (!(kms_request_get_signing_key (request, signing_key) &&
         kms_request_hmac_again (signature, signing_key, sts))) {
      goto done;
   }

   kms_request_str_append_hex (sig, signature, sizeof (signature));
   success = true;
done:
   kms_kv_list_destroy (lst);
   kms_request_str_destroy (sts);

   if (!success) {
      kms_request_str_destroy (sig);
      sig = NULL;
   }

   return sig;
}

kms_request_str_t *
kms_request_get_signed (kms_request_t *request)
{
   bool success = false;
   kms_kv_list_t *lst = NULL;
   kms_request_str_t *signature = NULL;
   kms_request_str_t *sreq = NULL;
   size_t i;

   if (request->failed) {
      return NULL;
   }

   sreq = kms_request_str_new ();
   /* like "POST / HTTP/1.1" */
   kms_request_str_append (sreq, request->method);
   kms_request_str_append_char (sreq, ' ');
   kms_request_str_append (sreq, request->path);
   if (request->query->len) {
      kms_request_str_append_char (sreq, '?');
      kms_request_str_append (sreq, request->query);
   }

   kms_request_str_append_chars (sreq, " HTTP/1.1", -1);
   kms_request_str_append_newline (sreq);

   /* headers */
   lst = request->header_fields;
   for (i = 0; i < lst->len; i++) {
      kms_request_str_append (sreq, lst->kvs[i].key);
      kms_request_str_append_char (sreq, ':');
      kms_request_str_append (sreq, lst->kvs[i].value);
      kms_request_str_append_newline (sreq);
   }

   /* authorization header */
   signature = kms_request_get_signature (request);
   if (!signature) {
      goto done;
   }

   /* note space after ':', to match test .sreq files */
   kms_request_str_append_chars (sreq, "Authorization: ", -1);
   kms_request_str_append (sreq, signature);

   /* body */
   if (request->payload->len) {
      kms_request_str_append_newline (sreq);
      kms_request_str_append_newline (sreq);
      kms_request_str_append (sreq, request->payload);
   }

   success = true;
done:
   kms_request_str_destroy (signature);

   if (!success) {
      kms_request_str_destroy (sreq);
      sreq = NULL;
   }

   return sreq;
}
