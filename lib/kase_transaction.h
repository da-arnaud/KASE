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
    char script_public_key[128]; // Script de l'UTXO
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
int kase_broadcast_transaction(const kase_transaction_t* tx);

// Utilitaires
uint64_t kase_kas_to_sompi(double kas);
double kase_sompi_to_kas(uint64_t sompi);

#ifdef __cplusplus
}
#endif

#endif
