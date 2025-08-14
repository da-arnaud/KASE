
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

typedef struct {
    uint8_t priv_key[32];
    uint8_t pub_key[33]; // compressed
    char kaspa_address[128]; // bech32 or base58
} kase_wallet_t;

/**
 * Recover wallet from mnemonic (BIP39 + BIP32)
 */
int kase_recover_wallet_from_seed(const char* mnemonic,
                                   const char* optional_passphrase,
                                   kase_wallet_t* out);

/**
 */
#ifdef __cplusplus
}
#endif

#endif
