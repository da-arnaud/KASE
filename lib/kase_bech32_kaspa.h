//
//  kase_bech32_kaspa.h
//  KASE-Tester
//
//  Created by Daniel Arnaud on 17/08/2025.
//

#ifndef kase_bech32_kaspa_h
#define kase_bech32_kaspa_h

#include <stdio.h>

// Charset Kaspa (différent du bech32 standard)
static const char KASPA_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Table de décodage (index 0-122 pour ASCII)
static const uint8_t KASPA_REV_CHARSET[123] = {
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    15, 100, 10, 17, 21, 20, 26, 30, 7, 5, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
    100, 29, 100, 24, 13, 25, 9, 8, 23, 100, 18, 22, 31, 27, 19, 100,
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2
};

// Convert 8bit array to 5bit array avec padding à droite
size_t kaspa_conv8to5(const uint8_t* input, size_t input_len, uint8_t* output);

//Calcul de checksum avec préfixe
uint64_t kaspa_checksum(const uint8_t* payload_5bit, size_t payload_len, const char* prefix);

// Conversion checksum en 5-bit
size_t kaspa_checksum_to_5bit(uint64_t checksum, uint8_t* output);

// Fonction encodage adresse
int kaspa_encode_address(const uint8_t* pubkey_hash, const char* prefix, char* address_out);

// Fonction de décodage d'adresse Kaspa
int kaspa_decode_address(const char* address, uint8_t* pubkey_hash_out, char* prefix_out);

#endif /* kase_bech32_kaspa_h */
