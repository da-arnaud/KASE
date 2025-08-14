//
//  kasia_sha256.h
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 29/06/2025.
//

#ifndef KASE_SHA256_H
#define KASE_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include "sha2.h"

#ifdef __cplusplus
extern "C" {
#endif


void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
#ifdef __cplusplus
}
#endif

#endif // KASIA_SHA256_H

