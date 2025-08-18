//
//  kase_transaction.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 18/08/2025.
//

#include "kase_transaction.h"
#include "kase_wallet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Conversion KAS <-> Sompi
uint64_t kase_kas_to_sompi(double kas) {
    return (uint64_t)(kas * 100000000.0); // 1 KAS = 100M sompi
}

double kase_sompi_to_kas(uint64_t sompi) {
    return (double)sompi / 100000000.0;
}

// Pour l'instant, simulation des UTXOs (à remplacer par vraie API)
int kase_get_utxos(const char* address, kase_utxo_t** utxos, size_t* count) {
    if (!address || !utxos || !count) return KASE_ERR_INVALID;
    
    // TODO: Remplacer par vraie requête réseau vers node Kaspa
    // Pour l'instant, simulation d'un UTXO fictif
    *count = 1;
    *utxos = malloc(sizeof(kase_utxo_t));
    if (!*utxos) return KASE_ERR_INVALID;
    
    strcpy((*utxos)[0].transaction_id, "dummy_tx_id_12345");
    (*utxos)[0].output_index = 0;
    (*utxos)[0].amount = kase_kas_to_sompi(10.0); // 10 KAS fictifs
    strcpy((*utxos)[0].script_public_key, "dummy_script");
    
    return KASE_OK;
}

int kase_get_balance(const char* address, uint64_t* balance) {
    if (!address || !balance) return KASE_ERR_INVALID;
    
    kase_utxo_t* utxos;
    size_t count;
    
    if (kase_get_utxos(address, &utxos, &count) != KASE_OK) {
        return KASE_ERR_INVALID;
    }
    
    *balance = 0;
    for (size_t i = 0; i < count; i++) {
        *balance += utxos[i].amount;
    }
    
    free(utxos);
    return KASE_OK;
}

int kase_create_transaction(const char* from_address,
                           const char* to_address,
                           uint64_t amount_sompi,
                           const uint8_t* private_key,
                           kase_transaction_result_t* result) {
    
    if (!from_address || !to_address || !private_key || !result) {
        if (result) {
            result->success = 0;
            strcpy(result->error, "Paramètres invalides");
        }
        return KASE_ERR_INVALID;
    }
    
    // 1. Récupérer les UTXOs
    kase_utxo_t* utxos;
    size_t utxo_count;
    
    if (kase_get_utxos(from_address, &utxos, &utxo_count) != KASE_OK) {
        result->success = 0;
        strcpy(result->error, "Impossible de récupérer les UTXOs");
        return KASE_ERR_INVALID;
    }
    
    // 2. Calculer le total disponible
    uint64_t total_available = 0;
    for (size_t i = 0; i < utxo_count; i++) {
        total_available += utxos[i].amount;
    }
    
    // 3. Vérifier si on a assez de fonds
    uint64_t fee = 1000; // Frais fixes pour l'instant (0.00001 KAS)
    if (total_available < amount_sompi + fee) {
        result->success = 0;
        snprintf(result->error, sizeof(result->error),
                "Fonds insuffisants. Disponible: %.8f KAS, Requis: %.8f KAS",
                kase_sompi_to_kas(total_available),
                kase_sompi_to_kas(amount_sompi + fee));
        free(utxos);
        return KASE_ERR_INVALID;
    }
    
    // 4. Créer la transaction
    kase_transaction_t tx;
    tx.inputs = utxos;
    tx.input_count = utxo_count;
    
    // Outputs: destination + change si nécessaire
    size_t output_count = 1;
    uint64_t change = total_available - amount_sompi - fee;
    if (change > 0) output_count = 2;
    
    tx.outputs = malloc(output_count * sizeof(kase_output_t));
    tx.output_count = output_count;
    tx.fee = fee;
    
    // Output principal
    strcpy(tx.outputs[0].address, to_address);
    tx.outputs[0].amount = amount_sompi;
    
    // Change si nécessaire
    if (change > 0) {
        strcpy(tx.outputs[1].address, from_address);
        tx.outputs[1].amount = change;
    }
    
    // 5. Signer la transaction (simplifié pour l'instant)
    // TODO: Vraie signature cryptographique
    snprintf(tx.transaction_id, sizeof(tx.transaction_id),
             "tx_%llu_%llu", (unsigned long long)amount_sompi, (unsigned long long)fee);
    
    // 6. Broadcaster (simulation)
    if (kase_broadcast_transaction(&tx) == KASE_OK) {
        result->success = 1;
        strcpy(result->transaction_id, tx.transaction_id);
        result->error[0] = '\0';
    } else {
        result->success = 0;
        strcpy(result->error, "Échec du broadcast");
    }
    
    free(tx.outputs);
    free(utxos);
    return KASE_OK;
}

int kase_broadcast_transaction(const kase_transaction_t* tx) {
    if (!tx) return KASE_ERR_INVALID;
    
    // TODO: Vraie implémentation réseau
    printf("📡 Broadcasting transaction %s\n", tx->transaction_id);
    printf("   Inputs: %zu\n", tx->input_count);
    printf("   Outputs: %zu\n", tx->output_count);
    printf("   Fee: %.8f KAS\n", kase_sompi_to_kas(tx->fee));
    
    // Simulation: toujours succès
    return KASE_OK;
}
