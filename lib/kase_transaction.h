//
//  kase_transaction.h
//  KASE-Tester
//
//  Created by Daniel Arnaud on 18/08/2025.
//

#ifndef KASE_TRANSACTION_H
#define KASE_TRANSACTION_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <curl/curl.h>  // For http requests
#include <json-c/json.h> // For JSON parser

#ifdef __cplusplus
extern "C" {
#endif

// Struct for HTTP response
typedef struct {
    char* data;
    size_t size;
} http_response_t;

// Structures pour les transactions Kaspa
typedef struct {
    char transaction_id[65];    // Hash de la transaction précédente (hex)
    uint32_t output_index;      // Index de l'output
    uint64_t amount;            // Montant en sompi (1 KAS = 100,000,000 sompi)
    char script_public_key[513]; // Script de l'UTXO
    char signature_script[513];  // Script de signature (nouveau champ)
} kase_utxo_t;

typedef struct {
    char address[128];          // Adresse de destination
    uint64_t amount;            // Montant en sompi
} kase_output_t;

typedef struct {
    kase_utxo_t* inputs;        // Array des UTXOs d'entrée
    size_t input_count;
    kase_output_t* outputs;     // Array des sorties
    size_t output_count;
    uint64_t fee;               // Frais de transaction en sompi
    char transaction_id[65];    // ID de la transaction (calculé)
} kase_transaction_t;

typedef struct {
    int success;
    char error[256];
    char transaction_id[65];
} kase_transaction_result_t;

// Constante Kaspa
#define KASPA_SIG_HASH_ALL 0x01

// Structures for KASPA transaction

typedef struct {
    uint8_t transaction_id[32];
    uint32_t index;
} kaspa_outpoint_t;

typedef struct {
    kaspa_outpoint_t previous_outpoint;
    uint8_t *signature_script;
    size_t signature_script_len;
    uint64_t sequence;
    uint8_t sig_op_count;
} kaspa_input_t;

typedef struct {
    uint64_t value;
    uint16_t script_version;
    uint8_t *script_public_key;
    size_t script_public_key_len;
} kaspa_output_t;

typedef struct {
    uint64_t amount;
    uint16_t script_version;
    uint8_t *script_public_key;
    size_t script_public_key_len;
    uint64_t block_daa_score;
    bool is_coinbase;
} kaspa_utxo_entry_t;

// Structure COMPLÈTE de transaction Kaspa
typedef struct {
    uint16_t version;
    kaspa_input_t *inputs;
    size_t inputs_count;
    kaspa_output_t *outputs;
    size_t outputs_count;
    uint64_t lock_time;
    uint8_t subnetwork_id[20];
    uint64_t gas;
    uint8_t *payload;
    size_t payload_len;
} kaspa_transaction_t;

int kaspa_calc_sighash(const kaspa_transaction_t *tx,
                      int input_index,
                      const kaspa_utxo_entry_t *utxo,
                       uint8_t *sighash);

// Fonction d'initialisation sécurisée
/*
static inline void kase_transaction_result_init(kase_transaction_result_t* result) {
    if (result) {
        memset(result, 0, sizeof(kase_transaction_result_t));
    }
}
 */

static inline void kase_transaction_result_init(kase_transaction_result_t* result) {
    if (result) {
        result->success = 0;
        memset(result->error, 0, sizeof(result->error));
        memset(result->transaction_id, 0, sizeof(result->transaction_id));
    }
}

static int http_post_request(const char* url, const char* json_data, http_response_t* response);
static size_t write_callback(void* contents, size_t size, size_t nmemb, http_response_t* response);

// Fonctions principales
int kase_get_utxos(const char* address, kase_utxo_t** utxos, size_t* count);
int kase_get_balance(const char* address, uint64_t* balance);
int kase_create_transaction(const char* from_address,
                           const char* to_address,
                           uint64_t amount_sompi,
                           const uint8_t* private_key,
                           kase_transaction_result_t* result);
int kase_broadcast_transaction(const kase_transaction_t* tx, const uint8_t* private_key,  const char* sender_address);

int kaspa_sign_transaction(const uint8_t *private_key,
                          const kase_transaction_t *tx,
                          int input_index,
                          const kase_utxo_t *utxo,
                          const uint8_t *script,
                          size_t script_len,
                          uint8_t *signature_script,
                          size_t *sig_script_len);



// Utilitaires
uint64_t kase_kas_to_sompi(double kas);
double kase_sompi_to_kas(uint64_t sompi);

static int address_to_script_pubkey(const char* address, char* script_hex, size_t script_hex_size);

#ifdef __cplusplus
}
#endif

#endif
