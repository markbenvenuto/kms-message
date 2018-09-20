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
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <src/kms_request_str.h>

const char *aws_test_suite_dir = "aws-sig-v4-test-suite";

const char *skipped_aws_tests[] = {
   "post-sts-token",
};

bool
skip_aws_test (kms_request_str_t *test_name)
{
   size_t i;

   for (i = 0; i < sizeof (skipped_aws_tests) / sizeof (char *); i++) {
      if (0 == strcmp (test_name->str, skipped_aws_tests[i])) {
         return true;
      }
   }

   return false;
}

kms_request_str_t *
last_segment (kms_request_str_t *str)
{
   char *p = str->str + str->len;

   while (--p > str->str) {
      if (*p == '/') {
         return kms_request_str_new_from_chars (p + 1, -1);
      }
   }

   return kms_request_str_dup (str);
}

kms_request_str_t *
aws_test_file_path (kms_request_str_t *path, const char *suffix)
{
   kms_request_str_t *test_name = last_segment (path);
   kms_request_str_t *file_path;

   file_path = kms_request_str_dup (path);
   kms_request_str_append_char (file_path, '/');
   kms_request_str_append (file_path, test_name);
   kms_request_str_append_char (file_path, '.');
   kms_request_str_append_chars (file_path, suffix, -1);
   kms_request_str_destroy (test_name);

   return file_path;
}

kms_request_str_t *
read_aws_test (kms_request_str_t *path, const char *suffix)
{
   kms_request_str_t *file_path = aws_test_file_path (path, suffix);
   FILE *f;
   struct stat file_stat;
   size_t f_size;
   kms_request_str_t *str;

   if (0 != stat (file_path->str, &file_stat)) {
      perror (file_path->str);
      abort ();
   }

   f = fopen (file_path->str, "r");
   if (!f) {
      perror (file_path->str);
      abort ();
   }

   f_size = (size_t) file_stat.st_size;
   str = kms_request_str_new ();
   kms_request_str_reserve (str, f_size);
   if (f_size != fread (str->str, 1, f_size, f)) {
      perror (file_path->str);
      abort ();
   }

   fclose (f);
   kms_request_str_destroy (file_path);

   str->len = f_size;
   str->str[f_size] = '\0';

   return str;
}

kms_request_t *
read_req (kms_request_str_t *path)
{
   kms_request_t *request;
   kms_request_str_t *file_path = aws_test_file_path (path, "req");
   FILE *f;
   size_t len;
   ssize_t line_len;
   char *line = NULL;
   kms_request_str_t *method;
   kms_request_str_t *uri_path;
   char *field_name;
   char *field_value;
   bool r;

   f = fopen (file_path->str, "r");
   if (!f) {
      perror (file_path->str);
      abort ();
   }

   /* like "GET /path HTTP/1.1" */
   line_len = getline (&line, &len, f);
   method = kms_request_str_new_from_chars (line, strchr (line, ' ') - line);
   uri_path = kms_request_str_new_from_chars (line + method->len + 1,
                                              line_len - method->len - 1 -
                                                 strlen (" HTTP/1.1\n"));

   request = kms_request_new (method, uri_path);
   /* from docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   kms_request_set_region (request, "us-east-1");
   kms_request_set_service (request, "service");
   kms_request_set_access_key_id (request, "AKIDEXAMPLE");
   kms_request_set_secret_key (request,
                               "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

   while ((line_len = getline (&line, &len, f)) != -1) {
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
      } else if (line_len > 2) {
         /* continuing a multiline header from previous line */
         /* TODO: is this a test quirk or HTTP specified behavior? */
         kms_request_append_header_field_value_from_chars (request, "\n", 1);
         /* omit this line's newline */
         kms_request_append_header_field_value_from_chars (
            request, line, (size_t) (line_len - 1));
      }
   }

   while ((line_len = getline (&line, &len, f)) != -1) {
      kms_request_append_payload_from_chars (request, line, (size_t) line_len);
   }

   fclose (f);
   kms_request_str_destroy (file_path);

   return request;
}

static ssize_t
first_non_matching (kms_request_str_t *x, kms_request_str_t *y)
{
   size_t len = x->len > y->len ? x->len : y->len;
   size_t i;

   for (i = 0; i < len; i++) {
      if (x->str[i] != y->str[i]) {
         return i;
      }
   }

   if (x->len > y->len) {
      return y->len + 1;
   }

   if (y->len > x->len) {
      return x->len + 1;
   }

   /* the strings match */
   return -1;
}

void
aws_sig_v4_test_compare (kms_request_t *request,
                         kms_request_str_t *(*func) (kms_request_t *),
                         kms_request_str_t *dir_path,
                         const char *suffix)
{
   kms_request_str_t *test_name = last_segment (dir_path);
   kms_request_str_t *expect;
   kms_request_str_t *actual;

   /* canonical request */
   expect = read_aws_test (dir_path, suffix);
   actual = func (request);

   if (expect->len != actual->len ||
       0 != memcmp (expect->str, actual->str, actual->len)) {
      fprintf (stderr,
               "%s.%s failed, mismatch starting at %zd\n"
               "--- Expect (%zu chars) ---\n%s\n"
               "--- Actual (%zu chars) ---\n%s\n",
               test_name->str,
               suffix,
               first_non_matching (expect, actual),
               expect->len,
               expect->str,
               actual->len,
               actual->str);
      abort ();
   }

   kms_request_str_destroy (test_name);
   kms_request_str_destroy (actual);
   free (expect);
}

void
aws_sig_v4_test (kms_request_str_t *dir_path)
{
   kms_request_t *request;

   request = read_req (dir_path);
   aws_sig_v4_test_compare (
      request, kms_request_get_canonical, dir_path, "creq");
   aws_sig_v4_test_compare (
      request, kms_request_get_string_to_sign, dir_path, "sts");
   aws_sig_v4_test_compare (
      request, kms_request_get_signature, dir_path, "authz");
   aws_sig_v4_test_compare (request, kms_request_get_signed, dir_path, "sreq");
   kms_request_destroy (request);
}

bool
spec_tests (kms_request_str_t *path, kms_request_str_t *selected)
{
   /* Amazon supplies tests, one per directory, 5 files per test, see
    * docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html */
   DIR *dp;
   struct dirent *ent;
   bool ran_tests = false;
   kms_request_str_t *test_name = last_segment (path);
   kms_request_str_t *ent_name = NULL;
   kms_request_str_t *sub = NULL;
   kms_request_str_t *dotreq = kms_request_str_new_from_chars (".req", -1);

   dp = opendir (path->str);
   if (!dp) {
      perror (path->str);
      abort ();
   }

   if (skip_aws_test (test_name) && !selected) {
      printf ("SKIP: %s\n", test_name->str);
      goto done;
   }

   while ((ent = readdir (dp))) {
      kms_request_str_destroy (ent_name);
      ent_name = kms_request_str_new_from_chars (ent->d_name, ent->d_namlen);
      if (ent->d_name[0] == '.') {
         continue;
      }

      if (ent->d_type & DT_DIR) {
         sub = kms_request_str_dup (path);
         kms_request_str_append_char (sub, '/');
         kms_request_str_append (sub, ent_name);
         ran_tests |= spec_tests (sub, selected);
         kms_request_str_destroy (sub);
      }

      if (!(ent->d_type & DT_REG) ||
          !kms_request_str_ends_with (ent_name, dotreq)) {
         continue;
      }

      /* "ent" is a "test.req" request file, this is a test directory */
      /* skip the test if it doesn't match the name passed to us */
      if (selected && 0 != strcmp (test_name->str, selected->str)) {
         continue;
      }

      printf ("%s\n", path->str);
      aws_sig_v4_test (path);
      ran_tests = true;
   }

done:
   kms_request_str_destroy (test_name);
   kms_request_str_destroy (ent_name);
   (void) closedir (dp);

   return ran_tests;
}

/* docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html */
void
example_signature_test (void)
{
   const char *expect =
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";
   kms_request_str_t *method = kms_request_str_new_from_chars ("GET", -1);
   kms_request_str_t *uri_path = kms_request_str_new_from_chars ("uri", -1);
   kms_request_t *request;
   unsigned char signing[32];
   kms_request_str_t *sig;

   request = kms_request_new (method, uri_path);
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

   kms_request_str_destroy (method);
   kms_request_str_destroy (uri_path);
   kms_request_str_destroy (sig);
   kms_request_destroy (request);
}

void
path_normalization_test (void)
{
   const char *tests[][2] = {
      {"", "/"},
      {"/", "/"},
      {"/..", "/"},
      {"./..", "/"},
      {"../..", "/"},
      {"/../..", "/"},
      {"a", "a"},
      {"a/", "a/"},
      {"a//", "a/"},
      {"a///", "a/"},
      {"/a", "/a"},
      {"//a", "/a"},
      {"///a", "/a"},
      {"/a/", "/a/"},
      {"/a/..", "/"},
      {"/a/../..", "/"},
      {"/a/b/../..", "/"},
      {"/a/b/c/../..", "/a"},
      {"/a/b/../../d", "/d"},
      {"/a/b/c/../../d", "/a/d"},
      {"/a/b", "/a/b"},
      {"a/..", "/"},
      {"a/../..", "/"},
      {"a/b/../..", "/"},
      {"a/b/c/../..", "a"},
      {"a/b/../../d", "d"},
      {"a/b/c/../../d", "a/d"},
      {"a/b", "a/b"},
      {"/a//b", "/a/b"},
      {"/a///b", "/a/b"},
      {"/a////b", "/a/b"},
      {"//", "/"},
      {"//a///", "/a/"},
   };

   const char **test;
   size_t i;
   kms_request_str_t *in, *out, *norm;

   for (i = 0; i < sizeof (tests) / (2 * sizeof (const char *)); i++) {
      test = tests[i];
      in = kms_request_str_new_from_chars (test[0], -1);
      out = kms_request_str_new_from_chars (test[1], -1);
      norm = kms_request_str_path_normalized (in);
      if (0 != strcmp (out->str, norm->str)) {
         fprintf (stderr,
                  "Path normalization test failed:\n"
                  "Input:  %s\n"
                  "Expect: %s\n"
                  "Actual: %s\n",
                  in->str,
                  out->str,
                  norm->str);
         abort ();
      }

      kms_request_str_destroy (in);
      kms_request_str_destroy (out);
      kms_request_str_destroy (norm);
   }
}


#define RUN_TEST(_func)                                           \
   do {                                                           \
      if (!selector || 0 == strcasecmp (#_func, selector->str)) { \
         printf ("%s\n", #_func);                                 \
         _func ();                                                \
         ran_tests = true;                                        \
      }                                                           \
   } while (0)


/* TODO: test multibyte UTF-8 */
int
main (int argc, char *argv[])
{
   const char *help;
   kms_request_str_t *dir_path = NULL;
   kms_request_str_t *selector = NULL;
   bool ran_tests = false;

   help = "Usage: test_kms_request [TEST_NAME]";

   if (argc > 2) {
      fprintf (stderr, "%s\n", help);
      abort ();
   } else if (argc == 2) {
      selector = kms_request_str_new_from_chars (argv[1], -1);
   }

   RUN_TEST (example_signature_test);
   RUN_TEST (path_normalization_test);

   dir_path = kms_request_str_new_from_chars (aws_test_suite_dir, -1);
   ran_tests |= spec_tests (dir_path, selector);

   if (!ran_tests) {
      assert (argc == 2);
      fprintf (stderr, "No such test: \"%s\"\n", argv[1]);
      abort ();
   }

   kms_request_str_destroy (selector);
   kms_request_str_destroy (dir_path);
}
