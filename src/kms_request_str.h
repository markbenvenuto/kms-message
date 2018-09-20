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

#ifndef KMS_MESSAGE_KMS_REQUEST_STR_H
#define KMS_MESSAGE_KMS_REQUEST_STR_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
   char *str;
   size_t len;
   size_t size;
} kms_request_str_t;

kms_request_str_t *
kms_request_str_new (void);
kms_request_str_t *
kms_request_str_new_from_chars (const char *chars, ssize_t len);
void
kms_request_str_destroy (kms_request_str_t *str);
bool
kms_request_str_reserve (kms_request_str_t *str, size_t size);
kms_request_str_t *
kms_request_str_dup (kms_request_str_t *str);
void
kms_request_str_set_chars (kms_request_str_t *str, const char *chars);
void
kms_request_str_append (kms_request_str_t *str, kms_request_str_t *appended);
void
kms_request_str_append_char (kms_request_str_t *str, char c);
void
kms_request_str_append_chars (kms_request_str_t *str,
                              const char *appended,
                              ssize_t len);
void
kms_request_str_append_newline (kms_request_str_t *str);
void
kms_request_str_append_lowercase (kms_request_str_t *str,
                                  kms_request_str_t *appended);
void
kms_request_str_appendf (kms_request_str_t *str, const char *format, ...);
void
kms_request_str_append_escaped (kms_request_str_t *str,
                                kms_request_str_t *appended,
                                bool escape_slash);
void
kms_request_str_append_stripped (kms_request_str_t *str,
                                 kms_request_str_t *appended);
bool
kms_request_str_append_hashed (kms_request_str_t *str,
                               kms_request_str_t *appended);
bool
kms_request_str_append_hex (kms_request_str_t *str,
                            unsigned char *data,
                            size_t len);

#endif // KMS_MESSAGE_KMS_REQUEST_STR_H
