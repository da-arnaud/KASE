
// kasia_wallet.c
// Minimal implementation of wallet recovery from BIP39 seed

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "kase_wallet.h"
#include "kase_bip39.h"
#include "bip340.h"
#include "kase_bech32_kaspa.h"

// *** DEBIUG ***
#include "blake2b.h"
#include "sha2.h"

// External dependencies you must provide or link to:
// - BIP39 wordlist + mnemonic decoding
// - BIP32 key derivation for secp256k1 (hardened path)
// - Kaspa-style address encoding (base58 or bech32, depending)

// Global variable for current network
kase_network_type_t g_kase_network = KASE_NETWORK_TESTNET_10; // Default testnet

int kase_set_network(kase_network_type_t network) {
    g_kase_network = network;
    return KASE_OK;
}

kase_network_type_t kase_get_network(void) {
    return g_kase_network;
}


int kase_recover_wallet_from_seed(const char* mnemonic,
                                   const char* optional_passphrase,
                                   kase_wallet_t* out,
                                   kase_network_type_t network) {
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
    
    printf("🔑 DEBUG privkey (32 bytes): ");
        for(int i = 0; i < 32; i++) {
            printf("%02x", privkey[i]);
        }
        printf("\n");
    
    uint8_t working_pubkey[] = {0x03,0xd1,0xdb,0xc9,0x8f,0x47,0xe1,0x21,0xa0,0x4b,0xc6,0x98,0x81,0x8c,0x22,0x80,0xdc,0x13,0xfc,0x01,0x07,0x3d,0xee,0x3b,0x69,0xd3,0x20,0xa2,0xc7,0xe5,0xaa,0x93};

    // Test 1: Votre hash SHA256 (celui qui fonctionne)
    uint8_t sha256_hash[32];
    sha256_Raw(working_pubkey, 33, sha256_hash);
    printf("🎯 HASH SHA256 (working): ");
    for(int i = 0; i < 32; i++) printf("%02x", sha256_hash[i]);
    printf("\n");

    // Test 2: Blake2b (si Kaspa utilise ça)
    uint8_t blake2b_hash[32];
    blake2b(working_pubkey, 33, blake2b_hash, 32);
    printf("🔍 HASH BLAKE2B (test): ");
    for(int i = 0; i < 32; i++) printf("%02x", blake2b_hash[i]);
    printf("\n");

    // Test 3: Décoder votre adresse working
    uint8_t decoded_hash[32];
    char decoded_prefix[16];
    if (kaspa_decode_address("kaspatest:qqpark7f3ar7zgdqf0rf3qvvy2qdcyluqyrnmm3md8fjpgk8uk4fx62qxzpyh", decoded_hash, decoded_prefix) == KASE_OK) {
        printf("📤 HASH DECODED: ");
        for(int i = 0; i < 32; i++) printf("%02x", decoded_hash[i]);
        printf("\n");
    }
    
    
    // Step 3: Derive Kaspa address from public key
    char address[128];
    if (kase_pubkey_to_kaspa_address(pubkey, address, sizeof(address), network) != 0)
        return KASE_ERR_ENCODE;

    // Fill output structure
    memcpy(out->priv_key, privkey, 32);
    memcpy(out->pub_key, pubkey, 33);
    strncpy(out->kaspa_address, address, sizeof(out->kaspa_address) - 1);
    out->kaspa_address[sizeof(out->kaspa_address) - 1] = '\0';

    return KASE_OK;
}


int kase_generate_wallet1(kase_wallet_t* out, kase_network_type_t network) {
    if (!out) return KASE_ERR_INVALID;

    // Step 1: Générer une phrase mnémonique (BIP39)
    char mnemonic[256];
    if (kase_bip39_generate_mnemonic(mnemonic, sizeof(mnemonic)) != 0)
        return KASE_ERR_KEYGEN;

    // Step 2: Convertir en seed (sans passphrase)
    uint8_t seed[64];
    if (kase_bip39_to_seed(mnemonic, "", seed) != 0)
        return KASE_ERR_INVALID;

    // Step 3: Dériver les clés secp256k1 (BIP32)
    uint8_t secp_privkey[32], secp_pubkey[33];
    if (kase_bip32_derive_key(seed, 64, secp_privkey, secp_pubkey) != 0)
        return KASE_ERR_KEYGEN;

    // Step 4: NOUVEAU - Convertir en Schnorr avec correction BIP340
    uint8_t schnorr_pubkey[32];
    uint8_t corrected_privkey[32];
    memcpy(corrected_privkey, secp_privkey, 32);
    
    if (bip340_pubkey_create(schnorr_pubkey, corrected_privkey) != 1)
        return KASE_ERR_KEYGEN;
    
    // 🔍 DEBUG: Afficher la clé Schnorr générée
        printf("Generated Schnorr pubkey: "); // *** DEBUG ***
        for(int i = 0; i < 32; i++) printf("%02x", schnorr_pubkey[i]);
        printf("\n");

    // Step 5: Générer l'adresse Kaspa à partir de Schnorr
    char address[128];
    if (kaspa_pubkey_to_address(schnorr_pubkey, address, sizeof(address), network) != 0)
        return KASE_ERR_ENCODE;
    
    printf("Generated address: %s\n", address);  // *** DEBUG ***

    // Step 6: Remplir la structure avec les bonnes valeurs
    memcpy(out->priv_key, corrected_privkey, 32);  // ← Clé privée CORRIGÉE
    memcpy(out->pub_key, schnorr_pubkey, 32);      // ← Clé publique Schnorr 32 bytes
    strncpy(out->kaspa_address, address, sizeof(out->kaspa_address) - 1);
    out->kaspa_address[sizeof(out->kaspa_address) - 1] = '\0';
    strncpy(out->mnemonic, mnemonic, sizeof(out->mnemonic) - 1);
    out->mnemonic[sizeof(out->mnemonic) - 1] = '\0';

    return KASE_OK;
}

int kase_generate_wallet(kase_wallet_t* out, kase_network_type_t network) {
    if (!out) return KASE_ERR_INVALID;
    
    // Step 1: Générer une phrase mnémonique (BIP39)
    char mnemonic[256];
    if (kase_bip39_generate_mnemonic(mnemonic, sizeof(mnemonic)) != 0)
        return KASE_ERR_KEYGEN;
    int result = kase_generate_wallet_with_mnemonic(mnemonic, NULL, out, network);
    return result;
}

int kase_generate_wallet_with_mnemonic(const char* mnemonic,
                                       const char* optional_passphrase,
                                       kase_wallet_t* out,
                                       kase_network_type_t network) {
    if (!out) return KASE_ERR_INVALID;

    const char* passphrase = (optional_passphrase && strlen(optional_passphrase) > 0)
                            ? optional_passphrase
                            : "";
    
    // Step 2: Convertir en seed (sans passphrase)
    uint8_t seed[64];
    if (kase_bip39_to_seed(mnemonic, passphrase, seed) != 0)
        return KASE_ERR_INVALID;

    // Step 3: Dériver les clés secp256k1 (BIP32)
    uint8_t secp_privkey[32], secp_pubkey[33];
    if (kase_bip32_derive_key(seed, 64, secp_privkey, secp_pubkey) != 0)
        return KASE_ERR_KEYGEN;

    // Step 4: NOUVEAU - Convertir en Schnorr avec correction BIP340
    uint8_t schnorr_pubkey[32];
    uint8_t corrected_privkey[32];
    memcpy(corrected_privkey, secp_privkey, 32);
    
    if (bip340_pubkey_create(schnorr_pubkey, corrected_privkey) != 1)
        return KASE_ERR_KEYGEN;
    
    // 🔍 DEBUG: Afficher la clé Schnorr générée
        printf("Generated Schnorr pubkey: "); // *** DEBUG ***
        for(int i = 0; i < 32; i++) printf("%02x", schnorr_pubkey[i]);
        printf("\n");

    // Step 5: Générer l'adresse Kaspa à partir de Schnorr
    char address[128];
    if (kaspa_pubkey_to_address(schnorr_pubkey, address, sizeof(address), network) != 0)
        return KASE_ERR_ENCODE;
    
    printf("Generated address: %s\n", address);  // *** DEBUG ***

    // Step 6: Remplir la structure avec les bonnes valeurs
    memcpy(out->priv_key, corrected_privkey, 32);  // ← Clé privée CORRIGÉE
    memcpy(out->pub_key, schnorr_pubkey, 32);      // ← Clé publique Schnorr 32 bytes
    strncpy(out->kaspa_address, address, sizeof(out->kaspa_address) - 1);
    out->kaspa_address[sizeof(out->kaspa_address) - 1] = '\0';
    strncpy(out->mnemonic, mnemonic, sizeof(out->mnemonic) - 1);
    out->mnemonic[sizeof(out->mnemonic) - 1] = '\0';

    return KASE_OK;
}
