//
//  kase_protocol.c
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 29/06/2025.
//

#include "kase_protocol.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Placeholder for crypto backend
#include "chacha20poly1305.h"
#include "secp256k1.h"


int kase_generate_keypair(kase_keypair_t* out) {
    if (!out) return KASE_ERR_INVALID;

    // TODO: call secp256k1 key generation here
    memset(out, 0, sizeof(kase_keypair_t));
    return KASE_OK;
}

int kase_derive_shared_key(const uint8_t* privkey, const uint8_t* peer_pubkey, const uint8_t* salt, size_t salt_len, kase_shared_key_t* out_key) {
    if (!privkey || !peer_pubkey || !salt || !out_key) return KASE_ERR_INVALID;

    // TODO: derive ECDH shared key and run HKDF
    memset(out_key, 0, sizeof(kase_shared_key_t));
    return KASE_OK;
}

int kase_encrypt_message(const kase_shared_key_t* key, const kase_plaintext_message_t* input, kase_encrypted_message_t* output) {
    if (!key || !input || !output) return KASE_ERR_INVALID;

    // TODO: serialize and encrypt using chacha20poly1305
    memset(output, 0, sizeof(kase_encrypted_message_t));
    return KASE_OK;
}

int kase_decrypt_message(const kase_shared_key_t* key, const kase_encrypted_message_t* input, kase_plaintext_message_t* output) {
    if (!key || !input || !output) return KASE_ERR_INVALID;

    // TODO: decrypt and parse JSON message
    memset(output, 0, sizeof(kase_plaintext_message_t));
    return KASE_OK;
}

void kase_free_encrypted(kase_encrypted_message_t* msg) {
    if (msg && msg->ciphertext) {
        free(msg->ciphertext);
        msg->ciphertext = NULL;
    }
}

void kase_free_plaintext(kase_plaintext_message_t* msg) {
    if (msg && msg->message_text) {
        free(msg->message_text);
        msg->message_text = NULL;
    }
}
