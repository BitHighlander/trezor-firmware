/*
 * Stuck-RNG regression harness for the RedPallas signing nonce.
 *
 * random_buffer() is stubbed to a constant here, simulating a hardware RNG
 * that has failed in the one way the STM32 random32() health check cannot
 * catch: it never returns two consecutive equal words because it never
 * returns anything that varies at all.
 *
 * A nonce taken straight from the RNG would then be identical for every
 * signature the device ever produces. Two RedPallas signatures sharing a
 * nonce reveal rsk algebraically, and because the host supplies alpha, the
 * Orchard spend authorization key ask follows. The hedged derivation must
 * keep nonces distinct across messages even when the RNG contributes
 * nothing.
 *
 * Revert redpallas_sign_with_rsk() to raw random_buffer() output and
 * DISTINCT MESSAGES below fails.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "redpallas.h"

/* Strong definition overriding trezor-crypto's weak random_buffer(). */
static uint8_t stub_fill = 0xA5;

void random_buffer(uint8_t *buf, size_t len) { memset(buf, stub_fill, len); }

static int failures = 0;

static void check(int condition, const char *what) {
  if (!condition) {
    printf("FAIL: %s\n", what);
    failures++;
  }
}

int main(void) {
  /* Arbitrary fixed secrets; the values do not matter, only that they are
   * reused across every signature below. */
  uint8_t ask[32], alpha[32], rk[32];
  uint8_t sighash_a[32], sighash_b[32];
  uint8_t sig_a1[64], sig_a2[64], sig_b[64], sig_a_other_rng[64];

  memset(ask, 0x11, sizeof(ask));
  memset(alpha, 0x22, sizeof(alpha));
  memset(sighash_a, 0xAA, sizeof(sighash_a));
  memset(sighash_b, 0xBB, sizeof(sighash_b));

  check(redpallas_derive_rk(ask, alpha, rk) == 0, "derive rk");

  check(redpallas_sign_digest(ask, alpha, sighash_a, sig_a1) == 0, "sign a1");
  check(redpallas_sign_digest(ask, alpha, sighash_a, sig_a2) == 0, "sign a2");
  check(redpallas_sign_digest(ask, alpha, sighash_b, sig_b) == 0, "sign b");

  /* Every signature must still verify. */
  check(redpallas_verify_digest(rk, sighash_a, sig_a1) == 0, "verify a1");
  check(redpallas_verify_digest(rk, sighash_a, sig_a2) == 0, "verify a2");
  check(redpallas_verify_digest(rk, sighash_b, sig_b) == 0, "verify b");

  /* DISTINCT MESSAGES: the whole point. With a dead RNG the nonce is a
   * deterministic function of (rsk, rk, sighash), so a different message
   * must still produce a different nonce commitment R. Raw random_buffer()
   * would make these identical, which is the key-recovery condition. */
  check(memcmp(sig_a1, sig_b, 32) != 0, "distinct messages give distinct R");

  /* Same message, same key, dead RNG: degrades to deterministic signing.
   * Identical output is correct and leaks nothing. */
  check(memcmp(sig_a1, sig_a2, 64) == 0,
        "dead RNG signs one message identically");

  /* A healthy RNG must still reach the nonce: changing only the RNG output
   * has to change the signature, or the derivation ignores its entropy. */
  stub_fill = 0x5A;
  check(redpallas_sign_digest(ask, alpha, sighash_a, sig_a_other_rng) == 0,
        "sign a with other rng");
  check(memcmp(sig_a1, sig_a_other_rng, 32) != 0, "rng entropy reaches nonce");
  check(redpallas_verify_digest(rk, sighash_a, sig_a_other_rng) == 0,
        "verify a other rng");

  if (failures) {
    printf("RedPallas nonce harness: %d FAILURE(S)\n", failures);
    return 1;
  }
  printf("RedPallas hedged-nonce harness: PASS\n");
  return 0;
}
