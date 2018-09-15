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

#ifndef KMS_REQUEST_H
#define KMS_REQUEST_H

#include <stdbool.h>
#include <stdint.h>

typedef struct _kms_request_t kms_request_t;

kms_request_t *
kms_request_new (const uint8_t *method, const uint8_t *path_and_query);
void
kms_request_destroy (kms_request_t *request);
const uint8_t *
kms_request_get_error (kms_request_t *request);
bool
kms_request_add_header_field_from_chars (kms_request_t *request,
                                         const uint8_t *field_name,
                                         const uint8_t *value);
bool
kms_request_append_header_field_value_from_chars (kms_request_t *request,
                                                  const uint8_t *value);
uint8_t *
kms_request_get_canonical (kms_request_t *request);

#endif /* KMS_REQUEST_H */
