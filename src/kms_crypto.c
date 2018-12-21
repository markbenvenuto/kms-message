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

#ifdef _WIN32


// tell windows.h not to include a bunch of headers we don't need:
#define WIN32_LEAN_AND_MEAN

// Tell windows.h not to define any NT status codes, so that we can
// get the definitions from ntstatus.h, which has a more complete list.
#define WIN32_NO_STATUS

#include <windows.h>

#undef WIN32_NO_STATUS

// Obtain a definition for the ntstatus type.
#include <winternl.h>

// Add back in the status definitions so that macro expansions for
// things like STILL_ACTIVE and WAIT_OBJECT_O can be resolved (they
// expand to STATUS_ codes).
#include <ntstatus.h>

#include <bcrypt.h>

BCRYPT_ALG_HANDLE _algoSHA256;
BCRYPT_ALG_HANDLE _algoSHA256Hmac;

int
kms_crypto_init ()
{
   if (BCryptOpenAlgorithmProvider (
          &_algoSHA256, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) !=
       STATUS_SUCCESS) {
      return 1;
   }

   if (BCryptOpenAlgorithmProvider (&_algoSHA256Hmac,
                                    BCRYPT_SHA256_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) !=
       STATUS_SUCCESS) {
      return 2;
   }


   return 0;
}

void
kms_crypto_cleanup ()
{
   /* TODO */
}

bool
kms_sha256 (const char *input, size_t len, unsigned char *hash_out)
{
   BCRYPT_HASH_HANDLE hHash;

   NTSTATUS status =
      BCryptCreateHash (_algoSHA256, &hHash, NULL, 0, NULL, 0, 0);
   if (status != STATUS_SUCCESS) {
      return status;
   }
   status = BCryptHashData (hHash, (PUCHAR) (input), len, 0);
   if (status != STATUS_SUCCESS) {
      goto cleanup;
   }

   // Hardcode output length
   status = BCryptFinishHash (hHash, hash_out, 256 / 8, 0);
   if (status != STATUS_SUCCESS) {
      goto cleanup;
   }
cleanup:
   BCryptDestroyHash (hHash);

   return status == STATUS_SUCCESS ? 1 : 0;
}

bool
kms_sha256_hmac (const char *key_input,
                 size_t key_len,
                 const char *input,
                 size_t len,
                 unsigned char *hash_out)
{
   BCRYPT_HASH_HANDLE hHash;

   NTSTATUS status = BCryptCreateHash (
      _algoSHA256Hmac, &hHash, NULL, 0, (PUCHAR) key_input, key_len, 0);
   if (status != STATUS_SUCCESS) {
      return status;
   }
   status = BCryptHashData (hHash, (PUCHAR) (input), len, 0);
   if (status != STATUS_SUCCESS) {
      goto cleanup;
   }

   // Hardcode output length
   status = BCryptFinishHash (hHash, hash_out, 256 / 8, 0);
   if (status != STATUS_SUCCESS) {
      goto cleanup;
   }
cleanup:
   BCryptDestroyHash (hHash);

   return status == STATUS_SUCCESS ? 1 : 0;
}


#else
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
   (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
EVP_MD_CTX *
EVP_MD_CTX_new (void)
{
   return calloc (sizeof (EVP_MD_CTX), 1);
}

void
EVP_MD_CTX_free (EVP_MD_CTX *ctx)
{
   EVP_MD_CTX_cleanup (ctx);
   free (ctx);
}
#endif

int
kms_crypto_init ()
{
   return 0;
}

void
kms_crypto_cleanup ()
{
}


bool
kms_sha256 (const char *input, size_t len, unsigned char *hash_out)
{
   EVP_MD_CTX *digest_ctxp = EVP_MD_CTX_new ();
   bool rval = false;

   if (1 != EVP_DigestInit_ex (digest_ctxp, EVP_sha256 (), NULL)) {
      goto cleanup;
   }

   if (1 != EVP_DigestUpdate (digest_ctxp, input, len)) {
      goto cleanup;
   }

   rval = (1 == EVP_DigestFinal_ex (digest_ctxp, hash_out, NULL));

cleanup:
   EVP_MD_CTX_free (digest_ctxp);

   return rval;
}

bool
kms_sha256_hmac (const char *key_input,
                 size_t key_len,
                 const char *input,
                 size_t len,
                 unsigned char *hash_out)
{
   return HMAC (EVP_sha256 (),
                key_input,
                key_len,
                (unsigned char *) input,
                len,
                hash_out,
                NULL) != NULL;
}


#endif