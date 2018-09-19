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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

static const char *aws_test_suite_dir = "aws-sig-v4-test-suite";

static const char *skipped_aws_tests[] = {
   /* assume no duplicate headers */
   "get-header-key-duplicate",
   "get-header-value-order",
   "normalize-path",
   "post-sts-token",
};

static bool
skip_aws_test (const char *test_name)
{
   size_t i;

   for (i = 0; i < sizeof (skipped_aws_tests) / sizeof (char *); i++) {
      if (0 == strcmp (test_name, skipped_aws_tests[i])) {
         return true;
      }
   }

   return false;
}

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
      if (strchr (line, ':')) {
         /* new header field like Host:example.com */
         field_name = strtok (line, ": ");
         assert (field_name);
         field_value = strtok (NULL, "\n");
         assert (field_value);
         r = kms_request_add_header_field_from_chars (
            request, (uint8_t *) field_name, (uint8_t *) field_value);
         assert (r);
      } else if (0 == strcmp (line, "\n")) {
         /* end of header */
         break;
      } else {
         /* continuing a multiline header from previous line */
         /* TODO: is this a test quirk or HTTP specified behavior? */
         kms_request_append_header_field_value_from_chars (request,
                                                           (uint8_t *) line);
      }
   }

   while (getline (&line, &len, f) != -1) {
      kms_request_append_payload_from_chars (request, (uint8_t *) line);
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
   size_t creq_expect_len;
   uint8_t *creq_actual;
   size_t creq_actual_len;

   request = read_req (test_name);
   /* canonical request */
   creq_expect = read_aws_test (test_name, "creq");
   creq_expect_len = strlen ((char *) creq_expect);
   creq_actual = kms_request_get_canonical (request);
   creq_actual_len = strlen ((char *) creq_actual);

   if (creq_expect_len != creq_actual_len ||
       0 != memcmp (creq_expect, creq_actual, strlen ((char *) creq_actual))) {
      fprintf (stderr,
               "Failed.\n"
               "--- Expect (%zu chars) ---\n%s\n"
               "--- Actual (%zu chars) ---\n%s\n",
               creq_expect_len,
               creq_expect,
               creq_actual_len,
               creq_actual);
      abort ();
   }

   free (creq_actual);
   free (creq_expect);
   kms_request_destroy (request);
}

int
main (int argc, char *argv[])
{
   /* Amazon supplies tests, one per directory, 5 files per test, see
    * docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   /* TODO: test multibyte UTF-8 */
   const char *help;
   DIR *dp;
   struct dirent *ent;
   bool ran_tests = false;

   help = "Usage: test_kms_request [TEST NAME]";

   if (argc > 2) {
      fprintf (stderr, "%s\n", help);
      abort ();
   }

   dp = opendir (aws_test_suite_dir);
   if (!dp) {
      perror (aws_test_suite_dir);
      abort ();
   }

   errno = 0;

   /* TODO: test the normalize-path subdir */
   while ((ent = readdir (dp))) {
      if (ent->d_type != DT_DIR || ent->d_name[0] == '.') {
         continue;
      }

      /* skip the test if it doesn't match the name passed to us */
      if (argc == 2 && 0 != strcmp (ent->d_name, argv[1])) {
         continue;
      }

      if (skip_aws_test (ent->d_name)) {
         printf ("SKIP: %s\n", ent->d_name);
         continue;
      }

      printf ("%s\n", ent->d_name);
      aws_sig_v4_test (ent->d_name);
      ran_tests = true;
   }

   if (errno) {
      perror (aws_test_suite_dir);
      abort ();
   }

   (void) closedir (dp);

   if (!ran_tests) {
      assert (argc == 2);
      fprintf (stderr, "No such test: \"%s\"\n", argv[1]);
      abort ();
   }

   return 0;
}
