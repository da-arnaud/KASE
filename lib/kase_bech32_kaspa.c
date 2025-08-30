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

// Convert 5bit array to 8bit array (inverse de kaspa_conv8to5)
size_t kaspa_conv5to8(const uint8_t* input, size_t input_len, uint8_t* output) {
    uint32_t acc = 0;
    int bits = 0;
    size_t output_len = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        acc = (acc << 5) | input[i];
        bits += 5;
        
        while (bits >= 8) {
            bits -= 8;
            output[output_len++] = (acc >> bits) & 0xFF;
        }
    }
    
    // Ignore padding bits
    return output_len;
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

// Fonction de décodage d'adresse Kaspa
int kaspa_decode_address(const char* address, uint8_t* pubkey_hash_out, char* prefix_out) {
    if (!address || !pubkey_hash_out) return KASE_ERR_INVALID;
    
    // 1. Séparer préfixe et partie données
    char* colon = strchr(address, ':');
    if (!colon) return KASE_ERR_DECODE;
    
    size_t prefix_len = colon - address;
    if (prefix_len >= 32) return KASE_ERR_DECODE;
    
    // Extraire préfixe
    if (prefix_out) {
        memcpy(prefix_out, address, prefix_len);
        prefix_out[prefix_len] = '\0';
    }
    
    // 2. Décoder la partie après ':'
    const char* data_part = colon + 1;
    size_t data_len = strlen(data_part);
    
    // 3. Convertir caractères en 5-bit using KASPA_REV_CHARSET
    uint8_t data_5bit[80];
    for (size_t i = 0; i < data_len; i++) {
        char c = data_part[i];
        if (c >= 123 || KASPA_REV_CHARSET[(int)c] == 100) {
            return KASE_ERR_DECODE;
        }
        data_5bit[i] = KASPA_REV_CHARSET[(int)c];
    }
    
    // 4. Séparer payload et checksum (derniers 8 chars = checksum)
    if (data_len < 8) return KASE_ERR_DECODE;
    size_t payload_len = data_len - 8;
    
    // 5. Vérifier checksum
    uint8_t payload_5bit[72];
    memcpy(payload_5bit, data_5bit, payload_len);
    
    uint64_t expected_checksum = kaspa_checksum(payload_5bit, payload_len,
                                               prefix_out ? prefix_out : "kaspatest");
    
    // Extraire checksum des 8 derniers chars
    uint8_t checksum_5bit[8];
    memcpy(checksum_5bit, data_5bit + payload_len, 8);
    
    // Convertir checksum 5bit en uint64_t pour comparaison
    uint64_t received_checksum = 0;
    for (int i = 0; i < 8; i++) {
        received_checksum = (received_checksum << 5) | checksum_5bit[i];
    }
    
    if (received_checksum != (expected_checksum & 0xFFFFFFFFFF)) {
        return KASE_ERR_DECODE;
    }
    
    // 6. Convertir payload 5bit → 8bit
    uint8_t decoded_data[64];
    size_t decoded_len = kaspa_conv5to8(payload_5bit, payload_len, decoded_data);
    
    // 7. Extraire hash (ignorer version byte)
    if (decoded_len < 33 || decoded_data[0] != 0x00) {
        return KASE_ERR_DECODE;
    }
    
    // Copier les 32 bytes du hash
    memcpy(pubkey_hash_out, decoded_data + 1, 32);
    
    return KASE_OK;
}
