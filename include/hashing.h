#ifndef HASHING_H
#define HASHING_H

#include <cassert>
#include <openssl/sha.h>

// Function to compute SHA256 hash and return the last k bits as a uint64_t
uint64_t computeHash(const uint64_t x, const uint32_t salt,
                     const unsigned int k) {
  assert(k >= 64);
  // Compute SHA256 hash of the data
  unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, &salt, sizeof(salt));
  SHA256_Update(&sha256, &x, sizeof(x));
  SHA256_Final(hash, &sha256);

  // Convert the last k bits of the hash to a uint64_t
  // This is inefficient - copies ONE BIT AT A TIME
  /*
  uint64_t result = 0;
  for (int i = 0; i < k; i++) {
      result <<= 1;
      result |= (hash[i / 8] >> (7 - (i % 8))) & 1;
  }
  */
  // This is a bit more dangerous but I know what I'm doing
  assert(SHA256_DIGEST_LENGTH * 8 >= sizeof(uint64_t));
  uint64_t *result_ptr = (uint64_t *)hash;
  *result_ptr &= -1;

  return *result_ptr;
}

#endif