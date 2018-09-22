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

#ifndef KMS_MESSAGE_PRIVATE_H
#define KMS_MESSAGE_PRIVATE_H

#include "kms_message/kms_message.h"
#include "kms_request_str.h"
#include "kms_kv_list.h"

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
   bool auto_content_length;
};

#endif /* KMS_MESSAGE_PRIVATE_H */
