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

#include <assert.h>

#define CHECK_FAILED         \
   do {                      \
      if (request->failed) { \
         return false;       \
      }                      \
   } while (0)

struct _kms_request_t {
   uint8_t error[512];
   bool failed;
   kms_request_str_t *method;
   kms_request_str_t *path;
   kms_request_str_t *query;
   kms_request_str_t *payload;
   kms_kv_list_t *query_params;
   kms_kv_list_t *header_fields;
};


static kms_kv_list_t *
parse_query_params (kms_request_str_t *q)
{
   kms_kv_list_t *lst = kms_kv_list_new ();
   uint8_t *p = q->str;
   uint8_t *end = q->str + q->len;
   uint8_t *amp, *equals;
   kms_request_str_t *k, *v;

   do {
      equals = (uint8_t *) strchr ((const char *) p, '=');
      assert (equals);
      amp = (uint8_t *) strchr ((const char *) equals, '&');
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
kms_request_new (const uint8_t *method, const uint8_t *path_and_query)
{
   const uint8_t *question_mark;
   kms_request_t *request = calloc (sizeof (kms_request_t), 1);

   question_mark = (uint8_t *) strchr ((const char *) path_and_query, '?');
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
   request->method = kms_request_str_new_from_chars (method, -1);
   request->header_fields = kms_kv_list_new ();

   return request;
}

void
kms_request_destroy (kms_request_t *request)
{
   kms_request_str_destroy (request->method);
   kms_request_str_destroy (request->path);
   kms_request_str_destroy (request->query);
   kms_request_str_destroy (request->payload);
   kms_kv_list_destroy (request->query_params);
   kms_kv_list_destroy (request->header_fields);
   free (request);
}

const uint8_t *
kms_request_get_error (kms_request_t *request)
{
   return request->failed ? request->error : NULL;
}

bool
kms_request_add_header_field_from_chars (kms_request_t *request,
                                         const uint8_t *field_name,
                                         const uint8_t *value)
{
   kms_request_str_t *k, *v;

   CHECK_FAILED;

   k = kms_request_str_new_from_chars (field_name, -1);
   v = kms_request_str_new_from_chars (value, -1);
   kms_kv_list_add (request->header_fields, k, v);
   kms_request_str_destroy (k);
   kms_request_str_destroy (v);

   return true;
}

bool
kms_request_append_header_field_value_from_chars (kms_request_t *request,
                                                  const uint8_t *value)
{
   kms_request_str_t *v;
   kms_request_str_t *s;

   CHECK_FAILED;

   if (request->header_fields->len == 0) {
      /* TODO: set error */
      return false;
   }

   v = request->header_fields->kvs[request->header_fields->len - 1].value;
   kms_request_str_append_char (v, ',');
   s = kms_request_str_new_from_chars (value, -1);
   kms_request_str_append_stripped (v, s);
   kms_request_str_destroy (s);

   return true;
}

bool
kms_request_append_payload_from_chars (kms_request_t *request,
                                       const uint8_t *payload)
{
   CHECK_FAILED;

   kms_request_str_append_chars (
      request->payload, payload, strlen ((char *) payload));

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
      kms_request_str_append_char (str, (uint8_t) '=');
      kms_request_str_append_escaped (str, lst->kvs[i].value, true);

      if (i < lst->len - 1) {
         kms_request_str_append_char (str, (uint8_t) '&');
      }
   }

   kms_kv_list_destroy (lst);
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
      kms_request_str_append_char (str, (uint8_t) ':');
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
         kms_request_str_append_char (str, (uint8_t) ';');
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
   /* TODO: lowercase before sorting? */
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
   kms_request_str_t *sts;
   kms_request_str_t *creq = NULL; /* canonical request */
   const kms_kv_t *amz_date_header;
   char *t;

   if (request->failed) {
      return NULL;
   }

   sts = kms_request_str_new ();
   kms_request_str_append_chars (sts, (uint8_t *) "AWS4-HMAC-SHA256\n", -1);
   amz_date_header =
      kms_kv_list_find (request->header_fields, (uint8_t *) "X-Amz-Date");
   if (!amz_date_header) {
      goto error;
   }

   kms_request_str_append (sts, amz_date_header->value);
   kms_request_str_append_newline (sts);

   /* like "20150830T123600Z" */
   if ((t = strchr ((char *) amz_date_header->value->str, 'T'))) {
      kms_request_str_append_chars (sts,
                                    amz_date_header->value->str,
                                    t - (char *) amz_date_header->value->str);
   } else {
      kms_request_str_append (sts, amz_date_header->value);
   }

   /* TODO: configurable on kms_request_t */
   kms_request_str_append_chars (
      sts, (uint8_t *) "/us-east-1/service/aws4_request\n", -1);

   creq = kms_request_get_canonical (request);
   if (!kms_request_str_append_hashed (sts, creq)) {
      goto error;
   }

   kms_request_str_destroy (creq);
   return sts;

error:
   kms_request_str_destroy (creq);
   kms_request_str_destroy (sts);
   return NULL;
}
