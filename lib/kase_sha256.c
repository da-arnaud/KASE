//
//  kasia_sha256.c
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 30/06/2025.
//

#include "kase_sha256.h"

void sha256_init(SHA256_CTX *ctx) {
    sha256_Init(ctx);  // Init with default state and count = 0
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    sha256_Update(ctx, data, len);
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    sha256_Final(ctx, hash);
}
