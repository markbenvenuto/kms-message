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

#include "src/kms_message.h"
#include "test_kms.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

static const char *aws_test_suite_dir = "aws-sig-v4-test-suite";


static char *
aws_test_path (const char *test_name, const char *suffix)
{
   size_t file_path_len;
   char *file_path;

   file_path_len = strlen (aws_test_suite_dir) + 2 * strlen (test_name) + 10;
   file_path = malloc (file_path_len);

   snprintf (file_path,
             file_path_len,
             "%s/%s/%s.%s",
             aws_test_suite_dir,
             test_name,
             test_name,
             suffix);

   return file_path;
}

uint8_t *
read_aws_test (const char *test_name, const char *suffix)
{
   char *file_path;
   FILE *f;
   struct stat file_stat;
   size_t f_size;
   uint8_t *buf;

   file_path = aws_test_path (test_name, suffix);
   if (0 != stat (file_path, &file_stat)) {
      perror (file_path);
      abort ();
   }

   f = fopen (file_path, "r");
   if (!f) {
      perror (file_path);
      abort ();
   }

   f_size = (size_t) file_stat.st_size;
   buf = malloc (f_size + 1);
   if (f_size != fread (buf, 1, f_size, f)) {
      perror (file_path);
      abort ();
   }

   fclose (f);
   free (file_path);

   buf[f_size] = '\0';
   return buf;
}

static kms_request_t *
read_req (const char *test_name)
{
   kms_request_t *request;
   char *file_path;
   FILE *f;
   size_t len;
   char *line = NULL;
   char *method;
   char *uri_path;
   char *field_name;
   char *field_value;
   bool r;

   file_path = aws_test_path (test_name, "req");
   f = fopen (file_path, "r");
   if (!f) {
      perror (file_path);
      abort ();
   }

   /* like "GET /path HTTP/1.1" */
   getline (&line, &len, f);
   method = strtok (line, " ");
   assert (method);
   uri_path = strtok (NULL, " ");
   assert (uri_path);
   assert (0 == strcmp (strtok (NULL, " "), "HTTP/1.1\n"));

   /* all test files use the same host */
   request = kms_request_new ((uint8_t *) method, (uint8_t *) uri_path);
   while (getline (&line, &len, f) != -1) {
      field_name = strtok (line, ": ");
      assert (field_name);
      field_value = strtok (NULL, "\n ");
      assert (field_value);
      r = kms_request_add_header_field (
         request, (uint8_t *) field_name, (uint8_t *) field_value);
      assert (r);
   }

   fclose (f);
   free (file_path);

   return request;
}

void
aws_sig_v4_test (const char *test_name)
{
   kms_request_t *request;
   uint8_t *creq_expect;
   uint8_t *creq_actual;

   request = read_req (test_name);
   /* canonical request */
   creq_expect = read_aws_test (test_name, "creq");
   creq_actual = kms_request_get_canonical (request);

   if (0 != memcmp (creq_expect, creq_actual, strlen ((char *) creq_actual))) {
      fprintf (stderr,
               "Failed.\n--- Expect ---\n%s\n--- Actual ---\n%s\n",
               creq_expect,
               creq_actual);
      abort ();
   }

   free (creq_actual);
   free (creq_expect);
   kms_request_destroy (request);
}

int
main (void)
{
   /* Amazon supplies tests, one per directory, 5 files per test, see
    * docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   /* TODO: test multibyte UTF-8 */
   DIR *dp;
   struct dirent *ent;

   dp = opendir (aws_test_suite_dir);
   if (!dp) {
      perror (aws_test_suite_dir);
      abort ();
   }

   errno = 0;

   while ((ent = readdir (dp))) {
      if (ent->d_type != DT_DIR || ent->d_name[0] == '.') {
         continue;
      }

      printf ("%s\n", ent->d_name);
      aws_sig_v4_test (ent->d_name);
   }

   if (errno) {
      perror (aws_test_suite_dir);
      abort ();
   }

   (void) closedir (dp);


   return 0;
}
