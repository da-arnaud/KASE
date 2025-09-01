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
#include "blake2b.h"
#include "segwit_addr.h"

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
            //output[current_idx] = (buff >> bits) & 0x1F;
            output[current_idx] = (buff >> bits);
            buff &= (1 << bits) - 1;
            current_idx++;
        }
    }
    
    if (bits > 0) {
        //output[current_idx] = (buff << (5 - bits)) & 0x1F;
        output[current_idx] = (buff << (5 - bits)); 
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
    printf("DEBUG prefix 5bit: "); //*** DEBUG ***
    for (size_t i = 0; i < prefix_len; i++) {
        full_data[idx] = prefix[i] & 0x1F;
        //full_data[idx] = (uint8_t)(prefix[i]) >> 2;
        printf("%02x", full_data[idx]);
        idx++;
    }
    printf("\n");
    
    // 2. Séparateur (0)
    full_data[idx++] = 0;
    printf("DEBUG separator: 00\n");  //*** DEBUG ***
    
    // 3. Payload 5-bit
    printf("DEBUG payload_5bit: ");
    memcpy(full_data + idx, payload_5bit, payload_len);
    
    for(size_t i = 0; i < payload_len; i++) {   //*** DEBUG ***
            printf("%02x", full_data[idx + i]);
        }
        printf("\n");
    
    idx += payload_len;
    
    // 4. 8 zéros pour checksum
    memset(full_data + idx, 0, 8);
    printf("DEBUG zeros: 00000000000000000000\n");
    idx += 8;
    
    // 5. Calcul polymod
    printf("DEBUG total data for polymod (%zu bytes): ", idx);  // *** DEBUG ***
    for(size_t i = 0; i < idx; i++) {
            printf("%02x", full_data[i]);
        }
        printf("\n");
    uint64_t checksum = kaspa_polymod(full_data, idx);
    
    printf("DEBUG raw checksum: %016lx\n", checksum);
    
    free(full_data);
    return checksum;
}

// Conversion checksum en 5-bit
size_t kaspa_checksum_to_5bit(uint64_t checksum, uint8_t* output) {
    // Prendre bytes 3-7 du checksum (comme Rust: [3..])
        uint8_t checksum_bytes[5];
        for (int i = 0; i < 5; i++) {
            checksum_bytes[i] = (checksum >> ((4-i) * 8)) & 0xFF;
        }
    
    // Convertir ces 5 bytes en 5-bit
    return kaspa_conv8to5(checksum_bytes, 5, output);
}

// Fonction encodage adresse
int kaspa_encode_address(const uint8_t* pubkey_hash, const char* prefix, char* address_out) {
    
    printf("CHARSET CHECK: %s\n", KASPA_CHARSET);
    printf("CHARSET LENGTH: %zu\n", strlen(KASPA_CHARSET));

    // Vérifier que ton charset est exactement celui-ci
    const char* expected = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    if (strcmp(KASPA_CHARSET, expected) == 0) {
        printf("✅ CHARSET CORRECT\n");
    } else {
        printf("❌ CHARSET INCORRECT!\n");
        printf("Expected: %s\n", expected);
        printf("Got:      %s\n", KASPA_CHARSET);
    }
    printf("=====================================\n\n");
    
    // 1. Préparer données: version(0) + hash(32)
    uint8_t addr_data[33];
    addr_data[0] = 0x00;  // Version::PubKey
    memcpy(addr_data + 1, pubkey_hash, 32);
    
    // *** DEBUG ***
    printf("Step 1 - addr_data (33 bytes): ");
        for(int i = 0; i < 33; i++) printf("%02x", addr_data[i]);
    printf("\n");
    
    // 2. Conversion 8→5 bits
    uint8_t payload_5bit[64];  // Largement suffisant
    size_t payload_len = kaspa_conv8to5(addr_data, 33, payload_5bit);
    
    // *** DEBUG ***
    printf("Step 2 - payload_5bit (%zu bytes): ", payload_len);
    for(size_t i = 0; i < payload_len; i++) {
        printf("%02x", payload_5bit[i]);
        if (payload_5bit[i] > 31) {
            printf("(ERROR>31!)");
        }
    }
    printf("\n");
    
    
    // 3. Calcul checksum
    uint64_t checksum = kaspa_checksum(payload_5bit, payload_len, prefix);
    
    // 4. Checksum en 5-bit
    uint8_t checksum_5bit[16];
    size_t checksum_len = kaspa_checksum_to_5bit(checksum, checksum_5bit);
    
    // *** DEBUG ***
    printf("Step 4 - checksum_5bit (%zu bytes): ", checksum_len);
        for(size_t i = 0; i < checksum_len; i++) printf("%02x", checksum_5bit[i]);
        printf("\n");
    
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

// Helper pour conversion bits (si pas déjà présent)
int bech32_convertbits(uint8_t* out, size_t* outlen, int outbits,
                       const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    *outlen = 0;
    
    for (size_t i = 0; i < inlen; ++i) {
        val = (val << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return KASE_ERR_ENCODE;
    }
    
    return KASE_OK;
}


int kaspa_pubkey_to_address(const uint8_t* pubkey, char* address, size_t address_size, kase_network_type_t network) {
    if (!pubkey || !address || address_size < 128) {
        return KASE_ERR_INVALID;
    }
    /*
    // 1. Hash DIRECT de la clé publique (pas de script)
    uint8_t pubkey_hash[32];
    if (blake2b(pubkey, 32, pubkey_hash, 32) != 0) {
        return KASE_ERR_CRYPTO;
    } */
    
    // 2. Encoder avec le format Kaspa natif
    const char* hrp = (network == KASE_NETWORK_MAINNET) ? "kaspa" : "kaspatest";
    //return kaspa_encode_address(pubkey_hash, hrp, address);
    return kaspa_encode_address(pubkey, hrp, address);
}


int kaspa_pubkey_to_script_address(const uint8_t* pubkey, char* address, size_t address_size, kase_network_type_t network) {
    if (!pubkey || !address || address_size < 128) {
        return KASE_ERR_INVALID;
    }
    
    // 1. Créer le script P2PK: OP_DATA32 + pubkey + OP_CHECKSIG
    uint8_t script[34];
    script[0] = 0x20;  // OP_DATA32
    memcpy(script + 1, pubkey, 32);
    script[33] = 0xac; // OP_CHECKSIG
    
    
    // 2. Calculer le hash du script (BLAKE2b 256-bit)
    uint8_t script_hash[32];
    if (blake2b(script, 34, script_hash, 32) != 0) {
        return KASE_ERR_CRYPTO;
    }
    
    // 3. Ajouter le préfixe de version
    uint8_t versioned_hash[33];
    versioned_hash[0] = 0x00; // Testnet
    memcpy(versioned_hash + 1, script_hash, 32);
    
    // 4. Convertir en format 5-bit pour Bech32m
    uint8_t data[53];
    size_t data_len;
    if (bech32_convertbits(data, &data_len, 5, versioned_hash, 33, 8, 1) != KASE_OK) {
        return KASE_ERR_ENCODE;  // ← Erreur d'encodage
    }
    
    // 5. Encoder avec Bech32m  A CORRIGER
    const char* hrp = (network == KASE_NETWORK_MAINNET) ? "kaspa" : "kaspatest";
    //if (bech32_encode(address, hrp, data, data_len, BECH32_ENCODING_BECH32M) == 0) {
    if (kaspa_encode_address(script_hash, hrp, address) != KASE_OK) {
        return KASE_ERR_ENCODE;  // ← Erreur d'encodage
    }
    
    return KASE_OK;  // ← Succès
}
