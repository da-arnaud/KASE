//
//  kase_secp_ref.h
//  KASE-Tester
//
//  Created by Daniel Arnaud on 16/09/2025.
//

#pragma once
#include <stdint.h>

// Initialise le contexte libsecp une seule fois
void kase_secp_ref_init(void);

// Vérifie une signature BIP340 sur un digest 32B avec une pubkey x-only 32B
int kase_schnorr_verify_digest(const uint8_t sig64[64],
                               const uint8_t msg32[32],
                               const uint8_t pubkey_xonly32[32]);

// Signe un digest 32B avec une seckey 32B (BIP340)
int kase_schnorr_sign_digest(uint8_t sig64_out[64],
                             const uint8_t msg32[32],
                             const uint8_t seckey32[32]);
