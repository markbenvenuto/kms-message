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

#include "b64.h"
#include "kms_message/kms_message.h"
#include "kms_message_private.h"

#include <stdarg.h>
#include <stdio.h>

void
set_error (kms_request_t *request, const char *fmt, ...)
{
   va_list va;

   request->failed = true;

   va_start (va, fmt);
   (void) vsnprintf (request->error, sizeof (request->error), fmt, va);
   va_end (va);
}

void
kms_message_init (void)
{
   kms_message_b64_initialize_rmap ();
}

void
kms_message_cleanup (void)
{
   /* nothing yet */
}
