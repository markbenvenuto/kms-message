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

#include "kms_message.h"
#include "kms_private.h"
#include "kms_request_str.h"
#include "kms_kv_list.h"

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
   kms_kv_list_t *header_fields;
};

kms_request_t *
kms_request_new (const uint8_t *method, const uint8_t *path_and_query)
{
   const uint8_t *question_mark;
   kms_request_t *request = malloc (sizeof (kms_request_t));

   question_mark = (uint8_t *) strchr ((const char *) path_and_query, '?');
   if (question_mark) {
      request->path = kms_request_str_new_from_chars (
         path_and_query, question_mark - path_and_query);
      /* TODO: parse query string into array of names and values */
      request->query = kms_request_str_new_from_chars (question_mark + 1, -1);
   } else {
      request->path = kms_request_str_new_from_chars (path_and_query, -1);
      request->query = kms_request_str_new ();
   }

   request->failed = false;
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

static void
append_canonical_headers (kms_request_t *request, kms_request_str_t *str)
{
   size_t i;
   kms_kv_list_t *lst;

   /* AWS docs: "you must include the host header at a minimum" */
   assert (request->header_fields->len >= 1);
   lst = kms_kv_list_sorted (request->header_fields);

   for (i = 0; i < lst->len; i++) {
      kms_request_str_append_lowercase (str, lst->kvs[i].key);
      kms_request_str_append_chars (str, (const uint8_t *) ":");
      kms_request_str_append (str, lst->kvs[i].value);
      kms_request_str_append_newline (str);
   }

   kms_kv_list_destroy (lst);
}

uint8_t *
kms_request_get_canonical (kms_request_t *request)
{
   kms_request_str_t *canonical;

   if (request->failed) {
      return NULL;
   }

   canonical = kms_request_str_new ();
   kms_request_str_append (canonical, request->method);
   kms_request_str_append_newline (canonical);
   kms_request_str_append (canonical, request->path);
   kms_request_str_append_newline (canonical);
   kms_request_str_append_escaped (canonical, request->query);
   kms_request_str_append_newline (canonical);
   append_canonical_headers (request, canonical);

   return kms_request_str_detach (canonical, NULL);
}
