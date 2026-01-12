//
//  kase_secp_ref.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 16/09/2025.
//


#include "kase_secp_ref.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

static secp256k1_context* g_ctx = NULL;

void kase_secp_ref_init(void) {
    if (!g_ctx) g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

int kase_schnorr_verify_digest(const uint8_t sig64[64],
                               const uint8_t msg32[32],
                               const uint8_t pubkey_xonly32[32]) {
    kase_secp_ref_init();
    secp256k1_xonly_pubkey pk;
    if (!secp256k1_xonly_pubkey_parse(g_ctx, &pk, pubkey_xonly32)) return 0;
    return secp256k1_schnorrsig_verify(g_ctx, sig64, msg32, 32, &pk);
}

int kase_schnorr_sign_digest(uint8_t sig64_out[64],
                             const uint8_t msg32[32],
                             const uint8_t seckey32[32]) {
    kase_secp_ref_init();
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_ctx, &kp, seckey32)) return 0;
    return secp256k1_schnorrsig_sign32(g_ctx, sig64_out, msg32, &kp, NULL);
}
