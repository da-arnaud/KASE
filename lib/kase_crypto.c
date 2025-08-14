
// kasia_crypto_impl.c
// Real implementations using trezor-crypto

#include <string.h>
#include <stdio.h>
#include "kasia_wallet.h"

// Include trezor-crypto headers
#include "bip39.h"
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"
#include "sha2.h"
#include "base58.h"

int kasia_bip39_to_seed(const char* mnemonic, const char* passphrase, uint8_t* seed_out) {
    if (!mnemonic || !seed_out) return KASIA_ERR_INVALID;

    mnemonic_to_seed(mnemonic, passphrase ? passphrase : "", seed_out, NULL);
    return KASIA_OK;
}

int kasia_bip32_derive_key(const uint8_t* seed, size_t seed_len,
                           uint8_t* privkey_out, uint8_t* pubkey_out) {
    if (!seed || seed_len != 64 || !privkey_out || !pubkey_out)
        return KASIA_ERR_INVALID;

    HDNode node;
    if (hdnode_from_seed(seed, seed_len, SECP256K1_NAME, &node) == 0)
        return KASIA_ERR_KEYGEN;

    // Derivation path: m/44'/111'/0'/0/0  (111 = Kaspa BIP44 coin type)
    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 972);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_fill_public_key(&node);

    memcpy(privkey_out, node.private_key, 32);
    memcpy(pubkey_out, node.public_key, 33); // compressed

    return KASIA_OK;
}

int kasia_pubkey_to_kaspa_address(const uint8_t* pubkey, char* address_out, size_t max_len) {
    if (!pubkey || !address_out || max_len < 64) return KASIA_ERR_INVALID;

    uint8_t hash160[20];
    uint8_t sha256[32];
    sha256_Raw(pubkey, 33, sha256);
    ripemd160(sha256, 32, hash160);

    // Prefix for Kaspa mainnet: 0x08
    uint8_t addr_bin[21];
    addr_bin[0] = 0x08;
    memcpy(addr_bin + 1, hash160, 20);

    int len = base58_encode_check(addr_bin, 21, HASHER_SHA2D, address_out, max_len);
    if (len == 0)
        return KASIA_ERR_ENCODE;
    
    if (len < max_len) {
        address_out[len] = '\0';  // <-- Ajoute ce garde-fou
    } else {
        address_out[max_len - 1] = '\0'; // En cas de dépassement
    }

    return KASIA_OK;
}
