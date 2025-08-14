//
//  kasia_hkdf.c
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 29/06/2025.
//
// kasia_hkdf.c
#include "kase_hkdf.h"
#include <string.h>

// --- Minimal SHA-256 implementation header ---
// Required: sha256_init, sha256_update, sha256_final, SHA256_CTX
#include "kase_sha256.h"

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t blocksize = 64;
    uint8_t key_block[64] = {0};
    uint8_t o_key_pad[64];
    uint8_t i_key_pad[64];
    SHA256_CTX ctx;

    if (key_len > blocksize) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < blocksize; i++) {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    uint8_t inner_hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, i_key_pad, blocksize);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, o_key_pad, blocksize);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out);
}

int kase_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *salt, size_t salt_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    uint8_t t[32];
    size_t t_len = 0;
    size_t pos = 0;
    uint8_t counter = 1;

    while (pos < okm_len) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        if (t_len > 0)
            sha256_update(&ctx, t, t_len);
        sha256_update(&ctx, info, info_len);
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, t);

        size_t cplen = (okm_len - pos < 32) ? (okm_len - pos) : 32;
        memcpy(okm + pos, t, cplen);
        pos += cplen;
        t_len = 32;
        counter++;
    }
    return 0;
}
