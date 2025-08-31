//
//  kase_types.h
//  KASE-Tester
//
//  Created by Daniel Arnaud on 23/08/2025.
//

#ifndef KASE_TYPES_H
#define KASE_TYPES_H

#include <stdint.h>
#include <stddef.h>

// Types communs partagés
typedef enum {
    KASE_NETWORK_MAINNET = 0,
    KASE_NETWORK_TESTNET_10 = 1,
    KASE_NETWORK_TESTNET_11 = 2
} kase_network_type_t;

// Codes d'erreur communs
#define KASE_OK 0
#define KASE_ERR_KEYGEN -1
#define KASE_ERR_CRYPTO -2
#define KASE_ERR_ENCODE -3
#define KASE_ERR_DECODE -4
#define KASE_ERR_INVALID -5
#define KASE_ERR_ENCRYPT -6
#define KASE_ERR_DECRYPT -7
#define KASE_ERR_SERIALIZE -8
#define KASE_ERR_DESERIALIZE -9



typedef struct {
    uint8_t priv_key[32];
    uint8_t pub_key[32]; // compressed
    char kaspa_address[128]; // bech32 or base58
    char mnemonic[256]; // phrase mnémonique BIP39
} kase_wallet_t;


#endif // KASE_TYPES_H

