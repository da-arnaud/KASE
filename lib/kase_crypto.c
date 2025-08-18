
// kasia_crypto_impl.c
// Real implementations using trezor-crypto

#include <string.h>
#include <stdio.h>
#include "kase_wallet.h"

// Include trezor-crypto headers
#include "bip39.h"
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"
#include "sha2.h"
#include "base58.h"
#include "segwit_addr.h"
#include "kase_bech32_kaspa.h"

int kase_bip39_to_seed(const char* mnemonic, const char* passphrase, uint8_t* seed_out) {
    if (!mnemonic || !seed_out) return KASE_ERR_INVALID;

    mnemonic_to_seed(mnemonic, passphrase ? passphrase : "", seed_out, NULL);
    return KASE_OK;
}

int kase_bip32_derive_key(const uint8_t* seed, size_t seed_len,
                           uint8_t* privkey_out, uint8_t* pubkey_out) {
    if (!seed || seed_len != 64 || !privkey_out || !pubkey_out)
        return KASE_ERR_INVALID;

    HDNode node;
    if (hdnode_from_seed(seed, seed_len, SECP256K1_NAME, &node) == 0)
        return KASE_ERR_KEYGEN;

    // Derivation path: m/44'/111'/0'/0/0  (111 = Kaspa BIP44 coin type)
    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 972);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_private_ckd(&node, 0);
    hdnode_fill_public_key(&node);

    memcpy(privkey_out, node.private_key, 32);
    memcpy(pubkey_out, node.public_key, 33); // compressed

    return KASE_OK;
}

int kase_pubkey_to_kaspa_address(const uint8_t* pubkey, char* address_out, size_t max_len) {
    if (!pubkey || !address_out || max_len < 64) return KASE_ERR_INVALID;

    // 1. Hash SHA256 de la clé publique
        uint8_t sha256[32];
        sha256_Raw(pubkey, 33, sha256);
    //ripemd160(sha256, 32, hash160);

    // 2. Utiliser la nouvelle fonction Kaspa native
        int result = kaspa_encode_address(sha256, "kaspa", address_out);
    
    if (result != KASE_OK) {
            return KASE_ERR_ENCODE;
        }
        
        
    
    const char* test_addr = "kaspa:qpat6sx6ucnskjm32nheac4e8rexur8accv2f4cmqsvvgr9zv0uujesjzvgl5"; // Une vraie adresse
    uint8_t decoded[64];
    size_t decoded_len;
    char hrp[10];
    bech32_encoding enc;

    //bech32_encoding bech32_decode(char* hrp, uint8_t *data, size_t *data_len, const char *input)
    if (bech32_decode(hrp, decoded, &decoded_len, test_addr)) {
        printf("Vraie adresse décodée (%zu bytes): ", decoded_len);
        for(size_t i = 0; i < decoded_len; i++) printf("%02x", decoded[i]);
        printf("\n");
    }
    else
        printf("Somethign went wrong");

        return KASE_OK;
}
