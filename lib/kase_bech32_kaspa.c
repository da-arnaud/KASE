//
//  kase_bech32_kaspa.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 17/08/2025.
//

#include "kase_bech32_kaspa.h"
#include <string.h>
#include <stdlib.h>
#include "kase_protocol.h"

// Convert 8bit array to 5bit array avec padding à droite
size_t kaspa_conv8to5(const uint8_t* input, size_t input_len, uint8_t* output) {
    size_t padding = (input_len % 5 == 0) ? 0 : 1;
    size_t output_len = input_len * 8 / 5 + padding;
    
    size_t current_idx = 0;
    uint16_t buff = 0;
    int bits = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        buff = (buff << 8) | input[i];
        bits += 8;
        
        while (bits >= 5) {
            bits -= 5;
            output[current_idx] = (buff >> bits) & 0x1F;
            current_idx++;
        }
    }
    
    if (bits > 0) {
        output[current_idx] = (buff << (5 - bits)) & 0x1F;
        current_idx++;
    }
    
    return current_idx;
}

uint64_t kaspa_polymod(const uint8_t* values, size_t len) {
    uint64_t c = 1;
    
    for (size_t i = 0; i < len; i++) {
        uint64_t c0 = c >> 35;
        c = ((c & 0x07FFFFFFFF) << 5) ^ values[i];
        
        if (c0 & 0x01) c ^= 0x98F2BC8E61ULL;
        if (c0 & 0x02) c ^= 0x79B76D99E2ULL;
        if (c0 & 0x04) c ^= 0xF33E5FB3C4ULL;
        if (c0 & 0x08) c ^= 0xAE2EABE2A8ULL;
        if (c0 & 0x10) c ^= 0x1E4F43E470ULL;
    }
    
    return c ^ 1;
}


//Calcul de checksum avec préfixe
uint64_t kaspa_checksum(const uint8_t* payload_5bit, size_t payload_len, const char* prefix) {
    // Préparer le préfixe en 5-bit (chaque char & 0x1F)
    size_t prefix_len = strlen(prefix);
    uint8_t* full_data = malloc(prefix_len + 1 + payload_len + 8);
    size_t idx = 0;
    
    // 1. Ajouter préfixe en 5-bit
    for (size_t i = 0; i < prefix_len; i++) {
        full_data[idx++] = prefix[i] & 0x1F;
    }
    
    // 2. Séparateur (0)
    full_data[idx++] = 0;
    
    // 3. Payload 5-bit
    memcpy(full_data + idx, payload_5bit, payload_len);
    idx += payload_len;
    
    // 4. 8 zéros pour checksum
    memset(full_data + idx, 0, 8);
    idx += 8;
    
    // 5. Calcul polymod
    uint64_t checksum = kaspa_polymod(full_data, idx);
    
    free(full_data);
    return checksum;
}

// Conversion checksum en 5-bit
size_t kaspa_checksum_to_5bit(uint64_t checksum, uint8_t* output) {
    // Prendre les 5 derniers bytes du checksum (40 bits)
    uint8_t checksum_bytes[5];
    for (int i = 4; i >= 0; i--) {
        checksum_bytes[4-i] = (checksum >> (i * 8)) & 0xFF;
    }
    
    // Convertir ces 5 bytes en 5-bit
    return kaspa_conv8to5(checksum_bytes, 5, output);
}

// Fonction encodage adresse
int kaspa_encode_address(const uint8_t* pubkey_hash, const char* prefix, char* address_out) {
    // 1. Préparer données: version(0) + hash(32)
    uint8_t addr_data[33];
    addr_data[0] = 0x00;  // Version::PubKey
    memcpy(addr_data + 1, pubkey_hash, 32);
    
    // 2. Conversion 8→5 bits
    uint8_t payload_5bit[64];  // Largement suffisant
    size_t payload_len = kaspa_conv8to5(addr_data, 33, payload_5bit);
    
    // 3. Calcul checksum
    uint64_t checksum = kaspa_checksum(payload_5bit, payload_len, prefix);
    
    // 4. Checksum en 5-bit
    uint8_t checksum_5bit[16];
    size_t checksum_len = kaspa_checksum_to_5bit(checksum, checksum_5bit);
    
    // 5. Assemblage final: payload + checksum
    uint8_t final_5bit[80];
    memcpy(final_5bit, payload_5bit, payload_len);
    memcpy(final_5bit + payload_len, checksum_5bit, checksum_len);
    size_t total_len = payload_len + checksum_len;
    
    // 6. Encodage avec charset Kaspa
    sprintf(address_out, "%s:", prefix);
    char* addr_part = address_out + strlen(address_out);
    
    for (size_t i = 0; i < total_len; i++) {
        addr_part[i] = KASPA_CHARSET[final_5bit[i]];
    }
    addr_part[total_len] = '\0';
    
    return KASE_OK;
}
