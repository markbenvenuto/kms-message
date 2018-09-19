/*
 * Copyright 2018-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
#include "kms_private.h"
#include "kms_request_str.h"

#include <assert.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

bool rfc_3986_tab[256] = {0};
bool kms_initialized = false;

static void
tables_init ()
{
   int i;

   if (kms_initialized) {
      return;
   }

   for (i = 0; i < 256; ++i) {
      rfc_3986_tab[i] =
         isalnum (i) || i == '~' || i == '-' || i == '.' || i == '_';
   }

   kms_initialized = true;
}

static uint8_t *
kms_strdupv_printf (const uint8_t *format, va_list args)
{
   va_list my_args;
   uint8_t *buf;
   ssize_t len = 32;
   ssize_t n;

   assert (format);

   buf = malloc ((size_t) len);

   while (true) {
      va_copy (my_args, args);
      n = vsnprintf (buf, len, format, my_args);
      va_end (my_args);

      if (n > -1 && n < len) {
         return buf;
      }

      if (n > -1) {
         len = n + 1;
      } else {
         len *= 2;
      }

      buf = realloc (buf, (size_t) len);
   }
}

uint8_t *
kms_strdup_printf (const uint8_t *format, ...)
{
   va_list args;
   uint8_t *ret;

   assert (format);

   va_start (args, format);
   ret = kms_strdupv_printf (format, args);
   va_end (args);

   return ret;
}

static int
sort_strs_cmp (const void *a, const void *b)
{
   return strcmp (*(const char **) a, *(const char **) b);
}

static void
kms_request_str_reserve (kms_request_str_t *str, size_t size)
{
   size_t next_size = str->len + size + 1;

   if (str->size < next_size) {
      /* next power of 2 */
      --next_size;
      next_size |= next_size >> 1U;
      next_size |= next_size >> 2U;
      next_size |= next_size >> 4U;
      next_size |= next_size >> 8U;
      next_size |= next_size >> 16U;
      ++next_size;

      str->size = next_size;
      str->str = realloc (str->str, next_size);
      /* TODO: failure? */
   }
}

kms_request_str_t *
kms_request_str_new (void)
{
   kms_request_str_t *s = malloc (sizeof (kms_request_str_t));

   s->len = 0;
   s->size = 16;
   s->str = malloc (s->size);
   s->str[0] = '\0';

   return s;
}

kms_request_str_t *
kms_request_str_new_from_chars (const uint8_t *chars, ssize_t len)
{
   kms_request_str_t *s = malloc (sizeof (kms_request_str_t));
   size_t actual_len;

   if (len >= 0) {
      actual_len = (size_t) len;
   } else {
      actual_len = strlen ((const char *) chars);
   }

   s->size = actual_len + 1;
   s->str = malloc (s->size);
   memcpy (s->str, chars, actual_len);
   s->str[actual_len] = '\0';
   s->len = actual_len;

   return s;
}

void
kms_request_str_destroy (kms_request_str_t *str)
{
   free (str->str);
   free (str);
}

kms_request_str_t *
kms_request_str_dup (kms_request_str_t *str)
{
   kms_request_str_t *dup = malloc (sizeof (kms_request_str_t));

   dup->str = (uint8_t *) strndup ((const char *) str->str, str->len);
   dup->len = str->len;
   dup->size = str->len + 1;

   return dup;
}

uint8_t *
kms_request_str_detach (kms_request_str_t *str, size_t *len)
{
   uint8_t *s = str->str;

   if (len) {
      *len = str->len;
   }

   free (str);
   return s;
}

/* TODO: remove? */
kms_request_str_t *
kms_request_str_tolower (kms_request_str_t *str)
{
   kms_request_str_t *dup = kms_request_str_dup (str);
   uint8_t *p = dup->str;

   for (; *p; ++p) {
      /* ignore UTF-8 non-ASCII chars, which have 1 in the top bit */
      if ((*p & (0x1U << 7U)) == 0) {
         *p = (uint8_t) tolower (*p);
      }
   }

   return dup;
}

void
kms_request_str_append (kms_request_str_t *str, kms_request_str_t *appended)
{
   size_t next_len = str->len + appended->len;

   kms_request_str_reserve (str, next_len);
   memcpy (str->str + str->len, appended->str, appended->len);
   str->len += appended->len;
   str->str[str->len] = '\0';
}

void
kms_request_str_append_char (kms_request_str_t *str, const uint8_t c)
{
   kms_request_str_reserve (str, 1);
   *(str->str + str->len) = c;
   ++str->len;
   str->str[str->len] = '\0';
}


void
kms_request_str_append_chars (kms_request_str_t *str,
                              const uint8_t *appended,
                              ssize_t len)
{
   if (len < 0) {
      len = strlen ((char *) appended);
   }
   kms_request_str_reserve (str, (size_t) len);
   memcpy (str->str + str->len, appended, (size_t) len);
   str->len += len;
   str->str[str->len] = '\0';
}

void
kms_request_str_append_newline (kms_request_str_t *str)
{
   kms_request_str_append_char (str, (uint8_t) '\n');
}

void
kms_request_str_append_lowercase (kms_request_str_t *str,
                                  kms_request_str_t *appended)
{
   size_t i;
   uint8_t *p;

   i = str->len;
   kms_request_str_append (str, appended);

   /* downcase the chars from the old end to the new end of str */
   for (; i < str->len; ++i) {
      p = &str->str[i];
      /* ignore UTF-8 non-ASCII chars, which have 1 in the top bit */
      if ((*p & (0x1U << 7U)) == 0) {
         *p = (uint8_t) tolower (*p);
      }
   }
}

void
kms_request_str_appendf (kms_request_str_t *str, const char *format, ...)
{
}

void
kms_request_str_append_escaped (kms_request_str_t *str,
                                kms_request_str_t *appended,
                                bool escape_slash)
{
   uint8_t *in;
   uint8_t *out;
   size_t i;

   tables_init ();

   /* might replace each input char with 3 output chars: "%AB" */
   kms_request_str_reserve (str, 3 * appended->len);
   in = appended->str;
   out = str->str + str->len;

   for (i = 0; i < appended->len; ++i) {
      if (rfc_3986_tab[*in] || (*in == '/' && !escape_slash)) {
         *out = *in;
         ++out;
         ++str->len;
      } else {
         sprintf ((char *) out, "%%%02X", *in);
         out += 3;
         str->len += 3;
      }

      ++in;
   }
}

void
kms_request_str_append_stripped (kms_request_str_t *str,
                                 kms_request_str_t *appended)
{
   const uint8_t *src = appended->str;
   const uint8_t *end = appended->str + appended->len;
   bool space = false;

   kms_request_str_reserve (str, appended->len);

   while (isspace (*src)) {
      ++src;
   }

   while (src < end) {
      if (isspace (*src)) {
         space = true;
      } else {
         /* is there a run of spaces waiting to be written as one space? */
         if (space) {
            kms_request_str_append_char (str, ' ');
            space = false;
         }

         kms_request_str_append_char (str, *src);
      }

      ++src;
   }
}

bool
kms_request_str_append_hashed (kms_request_str_t *str,
                               kms_request_str_t *appended)
{
   uint8_t hash[32];
   char *hex_chars;

   if (!kms_sha256 (appended->str, appended->len, hash)) {
      return false;
   }

   hex_chars = hexlify (hash, sizeof (hash));
   kms_request_str_append_chars (str, (uint8_t *) hex_chars, 2 * sizeof (hash));
   free (hex_chars);

   return true;
}
