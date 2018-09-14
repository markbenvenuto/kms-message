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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <ctype.h>

#define CHECK_FAILED         \
   do {                      \
      if (request->failed) { \
         return false;       \
      }                      \
   } while (0)

typedef struct {
   kms_request_str_t *field_name;
   kms_request_str_t *value;
} kms_request_field_t;

struct _kms_request_t {
   uint8_t error[512];
   bool failed;
   kms_request_str_t *method;
   kms_request_str_t *path;
   kms_request_str_t *query;
   kms_request_field_t *fields;
   size_t n_fields;
   size_t fields_size;
};

static void
field_init (kms_request_field_t *field,
            const uint8_t *field_name,
            const uint8_t *value)
{
   field->field_name = kms_request_str_new_from_chars (field_name, -1);
   field->value = kms_request_str_new_from_chars (value, -1);
}

static void
field_cleanup (kms_request_field_t *field)
{
   kms_request_str_destroy (field->field_name);
   kms_request_str_destroy (field->value);
}

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
   request->n_fields = 0;
   request->fields_size = 16;
   request->fields =
      malloc (request->fields_size * sizeof (kms_request_field_t));

   return request;
}

void
kms_request_destroy (kms_request_t *request)
{
   size_t i;

   for (i = 0; i < request->n_fields; i++) {
      field_cleanup (&request->fields[i]);
   }

   free (request->fields);
   kms_request_str_destroy (request->method);
   kms_request_str_destroy (request->path);
   kms_request_str_destroy (request->query);
   free (request);
}

const uint8_t *
kms_request_get_error (kms_request_t *request)
{
   return request->failed ? request->error : NULL;
}

bool
kms_request_add_header_field (kms_request_t *request,
                              const uint8_t *field_name,
                              const uint8_t *value)
{
   CHECK_FAILED;

   if (request->n_fields == request->fields_size) {
      request->fields_size *= 2;
      request->fields = realloc (
         request->fields, request->fields_size * sizeof (kms_request_field_t));
   }

   field_init (&request->fields[request->n_fields], field_name, value);
   ++request->n_fields;

   return true;
}

static int
sort_fields_cmp (const void *a, const void *b)
{
   return strcmp (
      (const char *) (((const kms_request_field_t *) a)->field_name->str),
      (const char *) (((const kms_request_field_t *) b)->field_name->str));
}

static void
append_canonical_headers (kms_request_t *request, kms_request_str_t *str)
{
   size_t i;
   kms_request_field_t *fields;

   /* AWS docs: "you must include the host header at a minimum" */
   assert (request->n_fields >= 1);

   fields = malloc (request->n_fields * sizeof (kms_request_field_t));
   memcpy (fields, request->fields, request->n_fields * sizeof (kms_request_field_t));

   qsort (fields,
          request->n_fields,
          sizeof (kms_request_field_t *),
          sort_fields_cmp);

   for (i = 0; i < request->n_fields; i++) {
      kms_request_str_append_lowercase (str, fields[i].field_name);
      kms_request_str_append_chars (str, (const uint8_t *) ":");
      kms_request_str_append (str, fields[i].value);
      kms_request_str_append_newline (str);
   }

   free (fields);
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
