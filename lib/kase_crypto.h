
// kasia_crypto.h
// Header for Kasia wallet crypto interface

#ifndef KASIA_CRYPTO_H
#define KASIA_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "kase_types.h"

#ifdef __cplusplus
extern "C" {
#endif



// BIP39: Convert mnemonic phrase to 64-byte seed
int kase_bip39_to_seed(const char* mnemonic, const char* passphrase, uint8_t* seed_out);

// BIP32: Derive secp256k1 private/public key from seed (m/44'/111'/0'/0/0)
int kase_bip32_derive_key(const uint8_t* seed, size_t seed_len,
                           uint8_t* privkey_out, uint8_t* pubkey_out);

// Kaspa Address: Compute kaspa address (base58) from compressed public key
int kase_pubkey_to_kaspa_address(const uint8_t* pubkey, char* address_out, size_t max_len, kase_network_type_t network);

#ifdef __cplusplus
}
#endif

#endif // KASIA_CRYPTO_H
