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
#include "src/kms_request_str.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <src/kms_request_str.h>

const char *aws_test_suite_dir = "aws-sig-v4-test-suite";

const char *skipped_aws_tests[] = {
   /* assume no duplicate headers */
   "get-header-key-duplicate",
   "get-header-value-order",
   "normalize-path",
   "post-sts-token",
};

bool
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

char *
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

char *
read_aws_test (const char *test_name, const char *suffix)
{
   char *file_path;
   FILE *f;
   struct stat file_stat;
   size_t f_size;
   char *buf;

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

kms_request_t *
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

   request = kms_request_new (method, uri_path);
   /* from docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "service");
   kms_request_set_access_key_id (request, "AKIDEXAMPLE");
   kms_request_set_secret_key (request,
                               "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

   while (getline (&line, &len, f) != -1) {
      if (strchr (line, ':')) {
         /* new header field like Host:example.com */
         field_name = strtok (line, ": ");
         assert (field_name);
         field_value = strtok (NULL, "\n");
         assert (field_value);
         r = kms_request_add_header_field_from_chars (
            request, field_name, field_value);
         assert (r);
      } else if (0 == strcmp (line, "\n")) {
         /* end of header */
         break;
      } else {
         /* continuing a multiline header from previous line */
         /* TODO: is this a test quirk or HTTP specified behavior? */
         kms_request_append_header_field_value_from_chars (request, line);
      }
   }

   while (getline (&line, &len, f) != -1) {
      kms_request_append_payload_from_chars (request, line);
   }

   fclose (f);
   free (file_path);

   return request;
}

/* canonical request */
void
aws_sig_v4_test_compare (kms_request_t *request,
                         kms_request_str_t *(*func) (kms_request_t *),
                         const char *test_name,
                         const char *suffix)
{
   char *expect;
   size_t expect_len;
   kms_request_str_t *actual;

   /* canonical request */
   expect = read_aws_test (test_name, suffix);
   expect_len = strlen (expect);
   actual = func (request);

   if (expect_len != actual->len ||
       0 != memcmp (expect, actual->str, actual->len)) {
      fprintf (stderr,
               "%s.%s failed\n"
               "--- Expect (%zu chars) ---\n%s\n"
               "--- Actual (%zu chars) ---\n%s\n",
               test_name,
               suffix,
               expect_len,
               expect,
               actual->len,
               actual->str);
      abort ();
   }

   kms_request_str_destroy (actual);
   free (expect);
}

void
aws_sig_v4_test (const char *test_name)
{
   kms_request_t *request;

   request = read_req (test_name);
   aws_sig_v4_test_compare (
      request, kms_request_get_canonical, test_name, "creq");
   aws_sig_v4_test_compare (
      request, kms_request_get_string_to_sign, test_name, "sts");
   aws_sig_v4_test_compare (
      request, kms_request_get_signature, test_name, "authz");
   kms_request_destroy (request);
}

bool
spec_tests (const char *selected)
{
   /* Amazon supplies tests, one per directory, 5 files per test, see
    * docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   DIR *dp;
   struct dirent *ent;
   bool ran_tests = false;

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
      if (selected && 0 != strcmp (ent->d_name, selected)) {
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

   return ran_tests;
}

/* docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html */
void
example_signature_test (void)
{
   const char *expect =
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";
   kms_request_t *request;
   unsigned char signing[32];
   kms_request_str_t *sig;

   request = kms_request_new ("GET", "uri");
   kms_request_add_header_field_from_chars (
      request, "X-Amz-Date", "20150830T123600Z");
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "iam");
   kms_request_set_secret_key (request,
                               "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

   assert (kms_request_get_signing_key (request, signing));
   sig = kms_request_str_new ();
   kms_request_str_append_hex (sig, signing, sizeof (signing));
   if (strlen (expect) != sig->len ||
       0 != memcmp (expect, sig->str, sig->len)) {
      fprintf (stderr,
               "%s failed\n"
               "--- Expect ---\n%s\n"
               "--- Actual ---\n%s\n",
               __FUNCTION__,
               expect,
               sig->str);
      abort ();
   }

   kms_request_str_destroy (sig);
   kms_request_destroy (request);
}

#define RUN_TEST(_func)                                     \
   do {                                                     \
      if (selector && 0 != strcasecmp (#_func, selector)) { \
         printf ("SKIP: %s\n", #_func);                     \
      } else {                                              \
         printf ("%s\n", #_func);                           \
         _func ();                                          \
         ran_tests = true;                                  \
      }                                                     \
   } while (0)


/* TODO: test multibyte UTF-8 */
int
main (int argc, char *argv[])
{
   const char *selector = NULL;
   const char *help;
   bool ran_tests = false;

   help = "Usage: test_kms_request [TEST_NAME]";

   if (argc > 2) {
      fprintf (stderr, "%s\n", help);
      abort ();
   } else if (argc == 2) {
      selector = argv[1];
   }

   RUN_TEST (example_signature_test);

   ran_tests |= spec_tests (selector);

   if (!ran_tests) {
      assert (argc == 2);
      fprintf (stderr, "No such test: \"%s\"\n", argv[1]);
      abort ();
   }
}
