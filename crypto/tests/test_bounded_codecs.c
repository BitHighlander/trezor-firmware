/* Standalone regression executable; link base32/base58 and trezorcrypto.
 * Build base58.c with -DBASE58_MAX_BINARY_SIZE=132 for the bounded case. */
#if !defined(BASE58_MAX_BINARY_SIZE) || BASE58_MAX_BINARY_SIZE != 132
#error "Build this test and base58.c with BASE58_MAX_BINARY_SIZE=132"
#endif
#ifdef NDEBUG
#error "This regression requires assertions enabled"
#endif
#include <assert.h>
#include <string.h>
#include "base32.h"
#include "base58.h"
int main(void) {
  uint8_t input[132], output[132];
  char encoded[220];
  for (unsigned i = 0; i < sizeof(input); ++i) input[i] = i + 1;
  for (unsigned n = 1; n <= sizeof(input); ++n) {
    size_t size = sizeof(encoded);
    assert(b58enc(encoded, &size, input, n));
    size = n;
    assert(b58tobin(output, &size, encoded));
    assert(size == n && memcmp(input, output, n) == 0);
  }
  for (int n = 1; n <= 128; ++n) {
    assert(base58_encode_check(input, n, HASHER_SHA2D, encoded, sizeof(encoded)));
    assert(base58_decode_check(encoded, HASHER_SHA2D, output, n) == n);
    assert(memcmp(input, output, n) == 0);
  }
  size_t size = sizeof(encoded);
  assert(!b58enc(encoded, &size, input, 133));
  size = 133;
  assert(!b58tobin(output, &size, "1"));
  assert(!base58_encode_check(input, -1, HASHER_SHA2D, encoded, sizeof(encoded)));
  assert(!base58_decode_check(encoded, HASHER_SHA2D, output, -1));
  const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  assert(base32_encode((const uint8_t *)"foobar", 6, encoded, sizeof(encoded), alphabet));
  assert(strcmp(encoded, "MZXW6YTBOI") == 0);
  assert(base32_decode(encoded, 10, output, sizeof(output), alphabet));
  assert(memcmp(output, "foobar", 6) == 0);
  return 0;
}
