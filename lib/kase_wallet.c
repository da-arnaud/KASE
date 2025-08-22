
// kasia_wallet.c
// Minimal implementation of wallet recovery from BIP39 seed

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "kase_wallet.h"
#include "kase_bip39.h"

// External dependencies you must provide or link to:
// - BIP39 wordlist + mnemonic decoding
// - BIP32 key derivation for secp256k1 (hardened path)
// - Kaspa-style address encoding (base58 or bech32, depending)

// Global variable for current network
kase_network_type_t g_kase_network = KASE_NETWORK_TESTNET; // Default testnet

int kase_set_network(kase_network_type_t network) {
    g_kase_network = network;
    return KASE_OK;
}

kase_network_type_t kase_get_network(void) {
    return g_kase_network;
}


int kase_recover_wallet_from_seed(const char* mnemonic,
                                   const char* optional_passphrase,
                                   kase_wallet_t* out) {
    if (!mnemonic || !out) return KASE_ERR_INVALID;

    uint8_t seed[64]; // 512 bits
    size_t seed_len = 64;

    // Step 1: Convert mnemonic to seed (BIP39)
    if (kase_bip39_to_seed(mnemonic, optional_passphrase, seed) != 0)
        return KASE_ERR_INVALID;

    // Step 2: Derive master key from seed (BIP32)
    uint8_t privkey[32], pubkey[33];
    if (kase_bip32_derive_key(seed, seed_len, privkey, pubkey) != 0)
        return KASE_ERR_KEYGEN;

    // Step 3: Derive Kaspa address from public key
    char address[128];
    if (kase_pubkey_to_kaspa_address(pubkey, address, sizeof(address)) != 0)
        return KASE_ERR_ENCODE;

    // Fill output structure
    memcpy(out->priv_key, privkey, 32);
    memcpy(out->pub_key, pubkey, 33);
    strncpy(out->kaspa_address, address, sizeof(out->kaspa_address) - 1);
    out->kaspa_address[sizeof(out->kaspa_address) - 1] = '\0';

    return KASE_OK;
}


int kase_generate_wallet(kase_wallet_t* out) {
    if (!out) return KASE_ERR_INVALID;

    // Step 1: Générer une phrase mnémonique (BIP39)
    char mnemonic[256];
    if (kase_bip39_generate_mnemonic(mnemonic, sizeof(mnemonic)) != 0)
        return KASE_ERR_KEYGEN;

    // Step 2: Convertir en seed (sans passphrase)
    uint8_t seed[64];
    if (kase_bip39_to_seed(mnemonic, "", seed) != 0)
        return KASE_ERR_INVALID;

    // Step 3: Dériver les clés (BIP32)
    uint8_t privkey[32], pubkey[33];
    if (kase_bip32_derive_key(seed, 64, privkey, pubkey) != 0)
        return KASE_ERR_KEYGEN;

    // Step 4: Générer l'adresse Kaspa
    char address[128];
    if (kase_pubkey_to_kaspa_address(pubkey, address, sizeof(address)) != 0)
        return KASE_ERR_ENCODE;
    


    // Step 5: Remplir la structure complète
    memcpy(out->priv_key, privkey, 32);
    memcpy(out->pub_key, pubkey, 33);
    strncpy(out->kaspa_address, address, sizeof(out->kaspa_address) - 1);
    out->kaspa_address[sizeof(out->kaspa_address) - 1] = '\0';
    strncpy(out->mnemonic, mnemonic, sizeof(out->mnemonic) - 1);
    out->mnemonic[sizeof(out->mnemonic) - 1] = '\0';

    return KASE_OK;
}
