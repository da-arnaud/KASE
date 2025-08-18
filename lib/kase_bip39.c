//
//  kase_bip39.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 17/08/2025.


#include "kase_bip39.h"
#include <string.h>
#include "rand.h"  // pour random_buffer()
#include "bip39.h" // pour mnemonic_from_data()
#include "kase_wallet.h"
#include "memzero.h"

int kase_bip39_generate_mnemonic(char* out, size_t out_len) {
    if (!out || out_len < 256) return KASE_ERR_INVALID;
    
    // Générer 16 bytes (128 bits) d'entropie pour 12 mots
    // ou 32 bytes (256 bits) pour 24 mots
    uint8_t entropy[32];  // 32 bytes = 24 mots
    
    // Générer l'entropie aléatoire
    random_buffer(entropy, 32);  // Fonction du fichier rand.h/c
    
    // Convertir en mnémonique via la fonction existante
    const char* mnemonic = mnemonic_from_data(entropy, 32);
    
    if (!mnemonic) {
        return KASE_ERR_KEYGEN;
    }
    
    // Copier le résultat
    strncpy(out, mnemonic, out_len - 1);
    out[out_len - 1] = '\0';
    
    // Nettoyer l'entropie
    memzero(entropy, sizeof(entropy));
    return KASE_OK;
}
