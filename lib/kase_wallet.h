
// kase_wallet.h

#ifndef KASE_WALLET_H
#define KASE_WALLET_H

#define KASE_OK 0
#define KASE_ERR_KEYGEN -1
#define KASE_ERR_CRYPTO -2
#define KASE_ERR_ENCODE -3
#define KASE_ERR_DECODE -4
#define KASE_ERR_INVALID -5

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "kase_crypto.h"

// Network types
typedef enum {
    KASE_NETWORK_MAINNET = 0,
    KASE_NETWORK_TESTNET = 1
} kase_network_type_t;

typedef struct {
    uint8_t priv_key[32];
    uint8_t pub_key[33]; // compressed
    char kaspa_address[128]; // bech32 or base58
    char mnemonic[256]; // phrase mnémonique BIP39
} kase_wallet_t;

// Global network variables
extern kase_network_type_t g_kase_network;

// Switch network functions
int kase_set_network(kase_network_type_t network);
kase_network_type_t kase_get_network(void);

/**
 * Recover wallet from mnemonic (BIP39 + BIP32)
 */
int kase_recover_wallet_from_seed(const char* mnemonic,
                                   const char* optional_passphrase,
                                   kase_wallet_t* out);


int kase_generate_wallet(kase_wallet_t* out);
/**
 */
#ifdef __cplusplus
}
#endif

#endif
