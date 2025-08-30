//
//  bip340.h
//  KASE-Tester
//
//  Created by Daniel Arnaud on 26/08/2025.
//

#ifndef __BIP340_H__
#define __BIP340_H__

#include <stdint.h>
#include <stdbool.h>

// BIP-340 Schnorr Signatures

// Générer une clé publique x-only (32 bytes) depuis une clé privée
int bip340_pubkey_create(uint8_t *pubkey32, const uint8_t *seckey32);

// Signer un message avec BIP-340
int bip340_sign(uint8_t *sig64, const uint8_t *msg32, const uint8_t *seckey32, const uint8_t *aux32);

// Vérifier une signature BIP-340
bool bip340_verify(const uint8_t *sig64, const uint8_t *msg32, const uint8_t *pubkey32);

// Hash taggé pour BIP-340
void bip340_tagged_hash(const char *tag, const uint8_t *msg, size_t msglen, uint8_t *hash);

#endif
