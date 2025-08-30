//
//  bip340.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 26/08/2025.
//

#include "bip340.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha2.h"
#include "rfc6979.h"
#include "bignum.h"
#include <string.h>

// Hash taggé BIP-340
void bip340_tagged_hash(const char *tag, const uint8_t *msg, size_t msglen, uint8_t *hash) {
    uint8_t tag_hash[32];
    sha256_Raw((const uint8_t*)tag, strlen(tag), tag_hash);
    
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, tag_hash, 32);  // SHA256(tag)
    sha256_Update(&ctx, tag_hash, 32);  // SHA256(tag) again
    sha256_Update(&ctx, msg, msglen);   // message
    sha256_Final(&ctx, hash);
}

// Version simplifiée
static int lift_x(const uint8_t *x32, curve_point *point) {
    bignum256 x, y2;
    
    // Load x coordinate
    bn_read_be(x32, &x);
    
    // Compute y² = x³ + 7 (mod p)
    bn_copy(&x, &y2);
    bn_multiply(&x, &y2, &secp256k1.prime);  // x²
    bn_multiply(&x, &y2, &secp256k1.prime);  // x³
    bn_addmod(&y2, &secp256k1.b, &secp256k1.prime); // x³ + 7
    
    // Compute square root
    bn_sqrt(&y2, &secp256k1.prime);  // y2 devient sqrt(y2)
    
    // Choose even y (BIP-340 requirement)
    if (bn_is_odd(&y2)) {
        bn_subtract(&secp256k1.prime, &y2, &y2);
    }
    
    // Set point
    bn_copy(&x, &point->x);
    bn_copy(&y2, &point->y);
    
    return 1;
}
// Generate x-only pubkey from private key
int bip340_pubkey_create(uint8_t *pubkey32, const uint8_t *seckey32) {
    curve_point point;
    bignum256 k;
    
    // Load private key
    bn_read_be(seckey32, &k);
    
    // Check if private key is valid
    if (bn_is_zero(&k) || !bn_is_less(&k, &secp256k1.order)) {
        return 0;
    }
    
    // Compute P = k*G
    scalar_multiply(&secp256k1, &k, &point);
    
    // If y is odd, negate private key
    if (bn_is_odd(&point.y)) {
        bn_subtract(&secp256k1.order, &k, &k);
        scalar_multiply(&secp256k1, &k, &point);
    }
    
    // Output x coordinate only
    bn_write_be(&point.x, pubkey32);
    
    return 1;
}

// BIP-340 Schnorr Signature
int bip340_sign(uint8_t *sig64, const uint8_t *msg32, const uint8_t *seckey32, const uint8_t *aux32) {
    bignum256 d, k, r, e, s;
    curve_point R, P;
    uint8_t hash_input[96]; // P || R || m
    uint8_t challenge[32];
    uint8_t nonce_hash[32];
    uint8_t pubkey[32];
    
    // Load private key
    bn_read_be(seckey32, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, &secp256k1.order)) {
        return 0;
    }
    
    // Generate public key P = d*G
    scalar_multiply(&secp256k1, &d, &P);
    
    // If P.y is odd, negate d
    if (bn_is_odd(&P.y)) {
        bn_subtract(&secp256k1.order, &d, &d);
        scalar_multiply(&secp256k1, &d, &P);
    }
    
    // Store P.x as pubkey
    bn_write_be(&P.x, pubkey);
    
    // Generate nonce: k = hash(d || aux || m) mod n
    memcpy(hash_input, seckey32, 32);
    if (aux32) {
        memcpy(hash_input + 32, aux32, 32);
    } else {
        memset(hash_input + 32, 0, 32);
    }
    memcpy(hash_input + 64, msg32, 32);
    
    bip340_tagged_hash("BIP0340/nonce", hash_input, 96, nonce_hash);
    bn_read_be(nonce_hash, &k);
    bn_mod(&k, &secp256k1.order);
    
    // If k = 0, fail
    if (bn_is_zero(&k)) {
        return 0;
    }
    
    // R = k*G
    scalar_multiply(&secp256k1, &k, &R);
    
    // If R.y is odd, negate k
    if (bn_is_odd(&R.y)) {
        bn_subtract(&secp256k1.order, &k, &k);
        scalar_multiply(&secp256k1, &k, &R);
    }
    
    // r = R.x
    bn_copy(&R.x, &r);
    
    // Challenge: e = hash(r || P || m) mod n
    bn_write_be(&r, hash_input);        // r (32 bytes)
    memcpy(hash_input + 32, pubkey, 32); // P.x (32 bytes)
    memcpy(hash_input + 64, msg32, 32);  // m (32 bytes)
    
    bip340_tagged_hash("BIP0340/challenge", hash_input, 96, challenge);
    bn_read_be(challenge, &e);
    bn_mod(&e, &secp256k1.order);
    
    // s = k + e*d mod n
    bn_multiply(&e, &d, &secp256k1.order);  // e*d
    bn_addmod(&k, &e, &secp256k1.order);   // k + e*d
    bn_copy(&e, &s);  // s = k + e*d
    
    // Output signature: r || s
    bn_write_be(&r, sig64);      // First 32 bytes: r
    bn_write_be(&s, sig64 + 32); // Last 32 bytes: s
    
    return 1;
}

// BIP-340 Schnorr Verification
bool bip340_verify(const uint8_t *sig64, const uint8_t *msg32, const uint8_t *pubkey32) {
    bignum256 r, s, e;
    curve_point P, R1, R2;
    uint8_t hash_input[96];
    uint8_t challenge[32];
    
    // Parse signature: r || s
    bn_read_be(sig64, &r);
    bn_read_be(sig64 + 32, &s);
    
    // Check r and s are in range [0, p-1] and [0, n-1]
    if (!bn_is_less(&r, &secp256k1.prime) || !bn_is_less(&s, &secp256k1.order)) {
        return false;
    }
    
    // Lift x coordinate to get point P
    if (!lift_x(pubkey32, &P)) {
        return false;
    }
    
    // Challenge: e = hash(r || P || m) mod n
    bn_write_be(&r, hash_input);          // r (32 bytes)
    memcpy(hash_input + 32, pubkey32, 32); // P.x (32 bytes)
    memcpy(hash_input + 64, msg32, 32);   // m (32 bytes)
    
    bip340_tagged_hash("BIP0340/challenge", hash_input, 96, challenge);
    bn_read_be(challenge, &e);
    bn_mod(&e, &secp256k1.order);
    
    // R1 = s*G
    scalar_multiply(&secp256k1, &s, &R1);
    
    // R2 = e*P
    scalar_multiply(&secp256k1, &e, &R2);
    
    // R = R1 - R2 = s*G - e*P
    point_subtract(&secp256k1, &R2, &R1); // R1 = R1 - R2
    
    // Check if R.y is even
    if (bn_is_odd(&R1.y)) {
        return false;
    }
    
    // Check if R.x == r
    return bn_is_equal(&R1.x, &r);
}
