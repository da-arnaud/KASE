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

static const char* KASPA_MAINNET_RPC = "https://api.kaspa.org";
static const char* KASPA_TESTNET_RPC = "https://api-testnet.kaspa.org";

// Conversion KAS <-> Sompi
uint64_t kase_kas_to_sompi(double kas) {
    return (uint64_t)(kas * 100000000.0); // 1 KAS = 100M sompi
}

double kase_sompi_to_kas(uint64_t sompi) {
    return (double)sompi / 100000000.0;
}

// Utility function to get teh endpoint
static const char* get_kaspa_rpc_endpoint(void) {
    return (g_kase_network == KASE_NETWORK_TESTNET) ?
           KASPA_TESTNET_RPC : KASPA_MAINNET_RPC;
}

// Fonction utilitaire pour copie sécurisée de chaînes
static void safe_string_copy(char* dest, const char* src, size_t dest_size) {
    if (dest && src && dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

// Pour l'instant, simulation des UTXOs (à remplacer par vraie API)
int kase_get_utxos(const char* address, kase_utxo_t** utxos, size_t* count) {
    if (!address || !utxos || !count) return KASE_ERR_INVALID;
    
    const char* endpoint = get_kaspa_rpc_endpoint();
    printf("🌐 Récupération UTXOs depuis: %s (réseau: %s)\n",
           endpoint,
           (g_kase_network == KASE_NETWORK_TESTNET) ? "TESTNET" : "MAINNET");
    
    // Construire l'URL complète
    char url[512];
    snprintf(url, sizeof(url) - 1, "%s/v1/addresses/%s/utxos", endpoint, address);
    url[sizeof(url) - 1] = '\0';
    
    // Préparer la réponse HTTP
    http_response_t response = {0};
    
    // Faire la requête GET (utiliser curl_easy_setopt avec CURLOPT_HTTPGET)
    CURL* curl = curl_easy_init();
    if (!curl) return KASE_ERR_INVALID;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || !response.data) {
        printf("❌ Erreur requête UTXOs: %s\n", curl_easy_strerror(res));
        free(response.data);
        return KASE_ERR_INVALID;
    }
    
    // Parser la réponse JSON
    json_object* root = json_tokener_parse(response.data);
    free(response.data);
    
    if (!root) {
        printf("❌ Erreur parsing JSON UTXOs\n");
        return KASE_ERR_INVALID;
    }
    
    // Extraire le tableau des UTXOs
    json_object* utxos_array;
    if (!json_object_object_get_ex(root, "utxos", &utxos_array)) {
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    int array_length = json_object_array_length(utxos_array);
    *count = array_length;
    
    if (array_length == 0) {
        *utxos = NULL;
        json_object_put(root);
        return KASE_OK;
    }
    
    *utxos = malloc(array_length * sizeof(kase_utxo_t));
    if (!*utxos) {
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    // Parser chaque UTXO
    for (int i = 0; i < array_length; i++) {
        json_object* utxo_obj = json_object_array_get_idx(utxos_array, i);
        memset(&(*utxos)[i], 0, sizeof(kase_utxo_t));
        
        // Transaction ID
        json_object* tx_id_obj;
        if (json_object_object_get_ex(utxo_obj, "transactionId", &tx_id_obj)) {
            const char* tx_id = json_object_get_string(tx_id_obj);
            safe_string_copy((*utxos)[i].transaction_id, tx_id, sizeof((*utxos)[i].transaction_id));
        }
        
        // Output index
        json_object* index_obj;
        if (json_object_object_get_ex(utxo_obj, "index", &index_obj)) {
            (*utxos)[i].output_index = json_object_get_int(index_obj);
        }
        
        // Amount
        json_object* amount_obj;
        if (json_object_object_get_ex(utxo_obj, "amount", &amount_obj)) {
            (*utxos)[i].amount = json_object_get_int64(amount_obj);
        }
        
        // Script public key
        json_object* script_obj;
        if (json_object_object_get_ex(utxo_obj, "scriptPublicKey", &script_obj)) {
            const char* script = json_object_get_string(script_obj);
            safe_string_copy((*utxos)[i].script_public_key, script, sizeof((*utxos)[i].script_public_key));
        }
    }
    
    json_object_put(root);
    printf("✅ Récupéré %d UTXOs\n", array_length);
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
    
    // Initialisation sécurisée du résultat
    
    if (result) {
        kase_transaction_result_init(result);
    }
     
    
    if (!from_address || !to_address || !private_key || !result) {
        if (result) {
            result->success = 0;
            safe_string_copy(result->error, "Paramètres invalides", sizeof(result->error));
        }
        return KASE_ERR_INVALID;
    }
    
    // 1. Récupérer les UTXOs
    kase_utxo_t* utxos;
    size_t utxo_count;
    
    if (kase_get_utxos(from_address, &utxos, &utxo_count) != KASE_OK) {
        result->success = 0;
        safe_string_copy(result->error, "Impossible de récupérer les UTXOs", sizeof(result->error));
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
        snprintf(result->error, sizeof(result->error) - 1,
                "Fonds insuffisants. Disponible: %.8f KAS, Requis: %.8f KAS",
                kase_sompi_to_kas(total_available),
                kase_sompi_to_kas(amount_sompi + fee));
        result->error[sizeof(result->error) - 1] = '\0';
        free(utxos);
        return KASE_ERR_INVALID;
    }
    
    // 4. Créer la transaction
    kase_transaction_t tx;
    memset(&tx, 0, sizeof(tx)); // Initialisation sécurisée
    
    tx.inputs = utxos;
    tx.input_count = utxo_count;
    
    // Outputs: destination + change si nécessaire
    size_t output_count = 1;
    uint64_t change = total_available - amount_sompi - fee;
    if (change > 0) output_count = 2;
    
    tx.outputs = malloc(output_count * sizeof(kase_output_t));
    if (!tx.outputs) {
        result->success = 0;
        safe_string_copy(result->error, "Erreur allocation mémoire", sizeof(result->error));
        free(utxos);
        return KASE_ERR_INVALID;
    }
    
    // Initialisation sécurisée des outputs
    memset(tx.outputs, 0, output_count * sizeof(kase_output_t));
    
    tx.output_count = output_count;
    tx.fee = fee;
    
    // Output principal
    safe_string_copy(tx.outputs[0].address, to_address, sizeof(tx.outputs[0].address));
    tx.outputs[0].amount = amount_sompi;
    
    // Change si nécessaire
    if (change > 0) {
        safe_string_copy(tx.outputs[1].address, from_address, sizeof(tx.outputs[1].address));
        tx.outputs[1].amount = change;
    }
    
    // 5. Générer un ID de transaction (simplifié pour l'instant)
    char temp_id[65];
    snprintf(temp_id, sizeof(temp_id) - 1,
             "tx_%llu_%llu", (unsigned long long)amount_sompi, (unsigned long long)fee);
    temp_id[sizeof(temp_id) - 1] = '\0';
    
    safe_string_copy(tx.transaction_id, temp_id, sizeof(tx.transaction_id));
    
    // 6. Broadcaster (simulation)
    if (kase_broadcast_transaction(&tx) == KASE_OK) {
        result->success = 1;
        safe_string_copy(result->transaction_id, tx.transaction_id, sizeof(result->transaction_id));
        result->error[0] = '\0';
    } else {
        result->success = 0;
        safe_string_copy(result->error, "Échec du broadcast", sizeof(result->error));
    }
    
    free(tx.outputs);
    free(utxos);
    return KASE_OK;
}

int kase_broadcast_transaction(const kase_transaction_t* tx) {
    if (!tx) return KASE_ERR_INVALID;
    
    const char* endpoint = get_kaspa_rpc_endpoint();
    printf("📡 Broadcasting vers: %s\n", endpoint);
    
    // Construire l'URL
    char url[512];
    snprintf(url, sizeof(url) - 1, "%s/v1/transactions", endpoint);
    url[sizeof(url) - 1] = '\0';
    
    // Construire le JSON de la transaction
    json_object* tx_json = json_object_new_object();
    
    // Inputs array
    json_object* inputs_array = json_object_new_array();
    for (size_t i = 0; i < tx->input_count; i++) {
        json_object* input_obj = json_object_new_object();
        
        json_object_object_add(input_obj, "transactionId",
                              json_object_new_string(tx->inputs[i].transaction_id));
        json_object_object_add(input_obj, "index",
                              json_object_new_int(tx->inputs[i].output_index));
        json_object_object_add(input_obj, "amount",
                              json_object_new_int64(tx->inputs[i].amount));
        json_object_object_add(input_obj, "scriptPublicKey",
                              json_object_new_string(tx->inputs[i].script_public_key));
        
        json_object_array_add(inputs_array, input_obj);
    }
    json_object_object_add(tx_json, "inputs", inputs_array);
    
    // Outputs array
    json_object* outputs_array = json_object_new_array();
    for (size_t i = 0; i < tx->output_count; i++) {
        json_object* output_obj = json_object_new_object();
        
        json_object_object_add(output_obj, "address",
                              json_object_new_string(tx->outputs[i].address));
        json_object_object_add(output_obj, "amount",
                              json_object_new_int64(tx->outputs[i].amount));
        
        json_object_array_add(outputs_array, output_obj);
    }
    json_object_object_add(tx_json, "outputs", outputs_array);
    
    // Fee
    json_object_object_add(tx_json, "fee", json_object_new_int64(tx->fee));
    
    const char* json_string = json_object_to_json_string(tx_json);
    
    // Envoyer la requête
    http_response_t response = {0};
    int result = http_post_request(url, json_string, &response);
    
    json_object_put(tx_json);
    
    if (result == 0 && response.data) {
        printf("✅ Transaction broadcastée avec succès\n");
        printf("   Réponse: %s\n", response.data);
        free(response.data);
        return KASE_OK;
    } else {
        printf("❌ Erreur broadcast transaction\n");
        if (response.data) {
            printf("   Erreur: %s\n", response.data);
            free(response.data);
        }
        return KASE_ERR_INVALID;
    }
}

// Fonction utilitaire pour requêtes HTTP POST

// Callback pour curl - écrire les données reçues
static size_t write_callback(void* contents, size_t size, size_t nmemb, http_response_t* response) {
    size_t total_size = size * nmemb;
    char* new_data = realloc(response->data, response->size + total_size + 1);
    
    if (!new_data) return 0;
    
    response->data = new_data;
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = '\0';
    
    return total_size;
}

static int http_post_request(const char* url, const char* json_data, http_response_t* response) {
    CURL* curl;
    CURLcode res;
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK) ? 0 : -1;
}
