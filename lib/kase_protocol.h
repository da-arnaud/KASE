//
//  kasia_protocol.h
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 29/06/2025.
//

#ifndef kase_protocol_h
#define kase_protocol_h

#ifndef KASE_PROTOCOL_H
#define KASE_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "kase_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// --- Core types ---

typedef struct {
    uint8_t privkey[32];
    uint8_t pubkey[33]; // compressed
} kase_keypair_t;

typedef struct {
    uint8_t key[32]; // derived symmetric key
} kase_shared_key_t;

typedef struct {
    uint8_t nonce[12];
    uint8_t* ciphertext;
    size_t ciphertext_len;
} kase_encrypted_message_t;

typedef struct {
    uint64_t timestamp;
    char sender_address[128];
    char* message_text;
} kase_plaintext_message_t;

// --- API ---

int kase_generate_keypair(kase_keypair_t* out);
int kase_derive_shared_key(const uint8_t* privkey, const uint8_t* peer_pubkey, const uint8_t* salt, size_t salt_len, kase_shared_key_t* out_key);

int kase_encrypt_message(const kase_shared_key_t* key, const kase_plaintext_message_t* input, kase_encrypted_message_t* output);
int kase_decrypt_message(const kase_shared_key_t* key, const kase_encrypted_message_t* input, kase_plaintext_message_t* output);

// Utilitaires
void kase_free_encrypted(kase_encrypted_message_t* msg);
void kase_free_plaintext(kase_plaintext_message_t* msg);

#ifdef __cplusplus
}
#endif

#endif // KASIA_PROTOCOL_H


#endif /* kasia_protocol_h */
