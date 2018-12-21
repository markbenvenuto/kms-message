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

#include "kms_kv_list.h"
#include "kms_message/kms_message.h"
#include "kms_request_str.h"
#include "kms_port.h"

static void
kv_init (kms_kv_t *kv, kms_request_str_t *key, kms_request_str_t *value)
{
   kv->key = kms_request_str_dup (key);
   kv->value = kms_request_str_dup (value);
}

static void
kv_cleanup (kms_kv_t *kv)
{
   kms_request_str_destroy (kv->key);
   kms_request_str_destroy (kv->value);
}

kms_kv_list_t *
kms_kv_list_new (void)
{
   kms_kv_list_t *lst = malloc (sizeof (kms_kv_list_t));

   lst->size = 16;
   lst->kvs = malloc (lst->size * sizeof (kms_kv_t));
   lst->len = 0;

   return lst;
}

void
kms_kv_list_destroy (kms_kv_list_t *lst)
{
   size_t i;

   if (!lst) {
      return;
   }

   for (i = 0; i < lst->len; i++) {
      kv_cleanup (&lst->kvs[i]);
   }

   free (lst->kvs);
   free (lst);
}

void
kms_kv_list_add (kms_kv_list_t *lst,
                 kms_request_str_t *key,
                 kms_request_str_t *value)
{
   if (lst->len == lst->size) {
      lst->size *= 2;
      lst->kvs = realloc (lst->kvs, lst->size * sizeof (kms_kv_t));
   }

   kv_init (&lst->kvs[lst->len], key, value);
   ++lst->len;
}

const kms_kv_t *
kms_kv_list_find (const kms_kv_list_t *lst, const char *key)
{
   size_t i;

   for (i = 0; i < lst->len; i++) {
      if (0 == strcasecmp (lst->kvs[i].key->str, key)) {
         return &lst->kvs[i];
      }
   }

   return NULL;
}

void
kms_kv_list_del (kms_kv_list_t *lst, const char *key)
{
   size_t i;

   for (i = 0; i < lst->len; i++) {
      if (0 == strcmp (lst->kvs[i].key->str, key)) {
         kv_cleanup (&lst->kvs[i]);
         memmove (&lst->kvs[i],
                  &lst->kvs[i + 1],
                  sizeof (kms_kv_t) * (lst->len - i - 1));
         lst->len--;
      }
   }
}

kms_kv_list_t *
kms_kv_list_dup (const kms_kv_list_t *lst)
{
   kms_kv_list_t *dup;
   size_t i;

   if (lst->len == 0) {
      return kms_kv_list_new ();
   }

   dup = malloc (sizeof (kms_kv_list_t));
   dup->size = dup->len = lst->len;
   dup->kvs = malloc (lst->len * sizeof (kms_kv_t));

   for (i = 0; i < lst->len; i++) {
      kv_init (&dup->kvs[i], lst->kvs[i].key, lst->kvs[i].value);
   }

   return dup;
}


/*
https://github.com/freebsd/freebsd/blob/master/lib/libc/stdlib/merge.c

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Peter McIlroy.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This is to avoid out-of-bounds addresses in sorting the
 * last 4 elements.
 */

typedef int (*cmp_t) (const void *, const void *);
#define CMP(x, y) cmp (x, y)
#define swap(a, b)   \
   {                 \
      s = b;         \
      i = size;      \
      do {           \
         tmp = *a;   \
         *a++ = *s;  \
         *s++ = tmp; \
      } while (--i); \
      a -= size;     \
   }

static void
insertionsort (unsigned char *a, size_t n, size_t size, cmp_t cmp)
{
   unsigned char *ai, *s, *t, *u, tmp;
   int i;

   for (ai = a + size; --n >= 1; ai += size)
      for (t = ai; t > a; t -= size) {
         u = t - size;
         if (CMP (u, t) <= 0)
            break;
         swap (u, t);
      }
}

void
kms_kv_list_sort (kms_kv_list_t *lst, int (*cmp) (const void *, const void *))
{
   //#error TODO - replace with stable sort!
   //(void) qsort (lst->kvs, lst->len, sizeof (kms_kv_t), cmp);
   insertionsort (lst->kvs, lst->len, sizeof (kms_kv_t), cmp);
}
