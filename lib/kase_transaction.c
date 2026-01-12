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
#include "crypto/sha2.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/hasher.h"
#include "kase_bech32_kaspa.h"
#include "blake2b.h"
#include "bip340.h"

#ifndef KASE_SIGDBG
#define KASE_SIGDBG 1
#endif

// === CONFIGURATION BROADCAST ===
#define USE_RPC_BROADCAST 1  // 1 = RPC, 0 = REST

#if USE_RPC_BROADCAST
// === ENDPOINTS RPC ===
static const char* KASPA_MAINNET_RPC = "http://api.kaspa.org:16110";
static const char* KASPA_TESTNET_RPC_10 = "http://api-tn10.kaspa.org:16210";
//static const char* KASPA_TESTNET_RPC_10 = "http://54.37.157.14:18210";
static const char* KASPA_TESTNET_RPC_11 = "http://api-tn11.kaspa.org:16210";
#else
// === ENDPOINTS REST ===
static const char* KASPA_MAINNET_RPC = "https://api.kaspa.org";
static const char* KASPA_TESTNET_RPC_10 = "https://api-tn10.kaspa.org";
//static const char* KASPA_TESTNET_RPC_10 = "http://http://54.37.157.14";
static const char* KASPA_TESTNET_RPC_11 = "https://api-tn11.kaspa.org";
#endif

// Conversion KAS <-> Sompi
uint64_t kase_kas_to_sompi(double kas) {
    return (uint64_t)(kas * 100000000.0); // 1 KAS = 100M sompi
}

double kase_sompi_to_kas(uint64_t sompi) {
    return (double)sompi / 100000000.0;
}

// ============================================================================
// CALCUL DYNAMIQUE DES FRAIS DE TRANSACTION
// ============================================================================

// Tailles approximatives des composants d'une transaction Kaspa P2PK
#define KASPA_TX_HEADER_SIZE 50          // Version, locktime, subnetwork, gas, payload
#define KASPA_TX_INPUT_SIZE 180          // Outpoint (36) + signature script (~66) + sequence (8) + sig_op_count (1) + overhead
#define KASPA_TX_OUTPUT_SIZE 50          // Value (8) + script_public_key (~34) + overhead
#define KASPA_FEE_PER_BYTE 10            // 10 sompi par byte (ajustable selon le réseau)
#define KASPA_MIN_FEE 2036               // Minimum absolu requis par le réseau

/**
 * Estime la taille d'une transaction en bytes
 * @param num_inputs Nombre d'inputs
 * @param num_outputs Nombre d'outputs
 * @return Taille estimée en bytes
 */
static size_t kaspa_estimate_tx_size(size_t num_inputs, size_t num_outputs) {
    return KASPA_TX_HEADER_SIZE +
           (num_inputs * KASPA_TX_INPUT_SIZE) +
           (num_outputs * KASPA_TX_OUTPUT_SIZE);
}

/**
 * Calcule les frais appropriés pour une transaction
 * @param num_inputs Nombre d'inputs
 * @param num_outputs Nombre d'outputs
 * @return Frais en sompi
 */
static uint64_t kaspa_calculate_fee(size_t num_inputs, size_t num_outputs) {
    size_t tx_size = kaspa_estimate_tx_size(num_inputs, num_outputs);
    uint64_t fee = tx_size * KASPA_FEE_PER_BYTE;

    // Garantir le minimum absolu
    if (fee < KASPA_MIN_FEE) {
        fee = KASPA_MIN_FEE;
    }

    return fee;
}

// Utility function to get the endpoint
static const char* get_kaspa_endpoint(void) {
    switch (g_kase_network) {
        case KASE_NETWORK_MAINNET:
            return KASPA_MAINNET_RPC;
        case KASE_NETWORK_TESTNET_10:
            return KASPA_TESTNET_RPC_10;
        case KASE_NETWORK_TESTNET_11:
            return KASPA_TESTNET_RPC_11;
        default:
            return KASPA_MAINNET_RPC; // Fallback sécurisé
    }
}

static const char* get_network_display_name(void) {
    switch (g_kase_network) {
        case KASE_NETWORK_MAINNET: return "MAINNET";
        case KASE_NETWORK_TESTNET_10: return "TESTNET-10";
        case KASE_NETWORK_TESTNET_11: return "TESTNET-11";
        default: return "UNKNOWN";
    }
}

// Fonction utilitaire pour copie sécurisée de chaînes
static void safe_string_copy(char* dest, const char* src, size_t dest_size) {
    if (dest && src && dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

// Utilitaires de sérialisation little-endian
static void write_u16_le(uint8_t *buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

static void write_u64_le(uint8_t *buf, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        buf[i] = (val >> (i * 8)) & 0xFF;
    }
}

static void dbg_hex(const char* label, const uint8_t* d, size_t len, size_t preview) {
#if KASE_SIGDBG
    printf("%s", label);
    size_t n = (preview && preview < len) ? preview : len;
    for (size_t i = 0; i < n; i++) printf("%02x", d[i]);
    if (n < len) printf("...");
    printf("\n");
#else
    (void)label; (void)d; (void)len; (void)preview;
#endif
}

// Pour l’INPUT signé (SigHash items 7–9)
static void hash_current_input_spk(blake2b_state* h, uint16_t ver,
                                   const uint8_t* spk, size_t len) {
    uint8_t vb[2]; write_u16_le(vb, ver);         // 7. ScriptPubKeyVersion (uint16 LE)
    blake2b_Update(h, vb, 2);

    uint8_t lb[8]; write_u64_le(lb, (uint64_t)len); // 8. ScriptPubKey.length (uint64 LE)
    blake2b_Update(h, lb, 8);

    blake2b_Update(h, spk, len);                  // 9. ScriptPubKey (bytes du script SEULS)
}

// Pour outputsHash (ScriptPublicKey = Version + Script var-bytes)
static void hash_output_spk1(blake2b_state* h, uint16_t ver,
                            const uint8_t* spk, size_t len) {
    uint8_t vb[2]; write_u16_le(vb, ver);           // Version (uint16 LE)
    blake2b_Update(h, vb, 2);
    write_var_bytes(h, spk, len);                   // Script (varint + data) – une seule fois
}

static void hash_output_spk(blake2b_state* h, uint16_t ver,
                            const uint8_t* spk, size_t len) {
    uint8_t vb[2]; write_u16_le(vb, ver);           // Version (u16 LE)
    blake2b_Update(h, vb, 2);

    uint8_t lb[8]; write_u64_le(lb, (uint64_t)len); // Length (u64 LE)
    blake2b_Update(h, lb, 8);

#if KASE_SIGDBG
    printf("       hash_output_spk: version(u16 LE)=");
    for (int k = 0; k < 2; k++) printf("%02x", vb[k]);
    printf(", length(u64 LE)=");
    for (int k = 0; k < 8; k++) printf("%02x", lb[k]);
    printf(" (%zu bytes)\n", len);
#endif

    blake2b_Update(h, spk, len);                    // Script (varint + data) – une seule fois
}

void bytes_to_hex(const uint8_t* bytes, size_t len, char* hex_str, size_t hex_str_size) {
    if (hex_str_size < len * 2 + 1) return;
    
    for (size_t i = 0; i < len; i++) {
        snprintf(hex_str + i * 2, 3, "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

void hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex_str + i * 2, "%2hhx", &bytes[i]);
    }
}

int kase_get_utxos_RPC(const char* address, kase_utxo_t** utxos, size_t* count) {
    if (!address || !utxos || !count) return KASE_ERR_INVALID;
    printf("kase_get_utxos_RPC");
    // ========== TOUJOURS UTILISER RPC POUR CETTE FONCTION ==========
    const char* endpoint;
    switch (g_kase_network) {
        case KASE_NETWORK_MAINNET:
            endpoint = "http://api.kaspa.org:16110";
            break;
        case KASE_NETWORK_TESTNET_10:
            endpoint = "http://api-tn10.kaspa.org:16210";
            break;
        case KASE_NETWORK_TESTNET_11:
            endpoint = "http://api-tn11.kaspa.org:16210";
            break;
        default:
            endpoint = "http://api.kaspa.org:16110";
    }

    printf("🌐 [RPC] Récupération UTXOs par RPC depuis: %s (réseau: %s)\n",
           endpoint, get_network_display_name());
    
    // Construire la requête RPC JSON
    json_object* request = json_object_new_object();
    json_object* method = json_object_new_string("getUtxosByAddressesRequest");
    json_object* id = json_object_new_int(1);
    json_object* params = json_object_new_object();
    
    // Créer le tableau d'adresses
    json_object* addresses_array = json_object_new_array();
    json_object* addr_obj = json_object_new_string(address);
    json_object_array_add(addresses_array, addr_obj);
    
    json_object_object_add(params, "addresses", addresses_array);
    json_object_object_add(request, "method", method);
    json_object_object_add(request, "id", id);
    json_object_object_add(request, "params", params);
    
    // Convertir en string
    const char* json_string = json_object_to_json_string(request);
    
    printf("📤 Requête RPC: %s\n", json_string);
    
    // Préparer la réponse HTTP
    http_response_t response = {0};
    
    // Faire la requête POST
    CURL* curl = curl_easy_init();
    if (!curl) {
        json_object_put(request);
        return KASE_ERR_INVALID;
    }
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    json_object_put(request);
    
    if (res != CURLE_OK || !response.data) {
        printf("❌ Erreur requête UTXOs RPC: %s\n", curl_easy_strerror(res));
        free(response.data);
        return KASE_ERR_INVALID;
    }
    
    printf("📥 Réponse RPC: %s\n", response.data);
    
    // Parser la réponse JSON-RPC
    json_object* root = json_tokener_parse(response.data);
    free(response.data);
    
    if (!root) {
        printf("❌ Erreur parsing JSON RPC\n");
        return KASE_ERR_INVALID;
    }
    
    // Vérifier les erreurs RPC
    json_object* error_obj;
    if (json_object_object_get_ex(root, "error", &error_obj) && error_obj) {
        printf("❌ Erreur RPC: %s\n", json_object_to_json_string(error_obj));
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    // Extraire le résultat
    json_object* result_obj;
    if (!json_object_object_get_ex(root, "result", &result_obj)) {
        printf("❌ Pas de 'result' dans la réponse RPC\n");
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    // Extraire les entries
    json_object* entries_obj;
    if (!json_object_object_get_ex(result_obj, "entries", &entries_obj)) {
        printf("❌ Pas de 'entries' dans le résultat\n");
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    // Vérifier que c'est bien un array
    if (!json_object_is_type(entries_obj, json_type_array)) {
        printf("❌ 'entries' n'est pas un array\n");
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    int array_length = json_object_array_length(entries_obj);
    *count = array_length;
    
    printf("📊 Trouvé %d UTXOs\n", array_length);
    
    if (array_length == 0) {
        *utxos = NULL;
        json_object_put(root);
        return KASE_OK;
    }
    
    *utxos = malloc(array_length * sizeof(kase_utxo_t));
    if (!*utxos) {
        json_object_put(root);
        printf("❌ Erreur allocation mémoire UTXOs\n");
        return KASE_ERR_INVALID;
    }
    
    // Parser chaque UTXO
    for (int i = 0; i < array_length; i++) {
        json_object* utxo_obj = json_object_array_get_idx(entries_obj, i);
        memset(&(*utxos)[i], 0, sizeof(kase_utxo_t));
        
        // Extraire address (optionnel, pour vérification)
        json_object* address_obj;
        if (json_object_object_get_ex(utxo_obj, "address", &address_obj)) {
            // On peut vérifier que c'est bien notre adresse
        }
        
        // Extraire outpoint
        json_object* outpoint_obj;
        if (json_object_object_get_ex(utxo_obj, "outpoint", &outpoint_obj)) {
            // Transaction ID
            json_object* tx_id_obj;
            if (json_object_object_get_ex(outpoint_obj, "transactionId", &tx_id_obj)) {
                const char* tx_id = json_object_get_string(tx_id_obj);
                safe_string_copy((*utxos)[i].transaction_id, tx_id, sizeof((*utxos)[i].transaction_id));
            }
            
            // Output index
            json_object* index_obj;
            if (json_object_object_get_ex(outpoint_obj, "index", &index_obj)) {
                (*utxos)[i].output_index = json_object_get_int(index_obj);
            }
        }
        
        // Extraire utxoEntry
        json_object* utxo_entry_obj;
        if (json_object_object_get_ex(utxo_obj, "utxoEntry", &utxo_entry_obj)) {
            // Amount (string vers uint64_t)
            json_object* amount_obj;
            if (json_object_object_get_ex(utxo_entry_obj, "amount", &amount_obj)) {
                const char* amount_str = json_object_get_string(amount_obj);
                (*utxos)[i].amount = strtoull(amount_str, NULL, 10);
            }
            
            // Script public key
            json_object* script_pk_obj;
            if (json_object_object_get_ex(utxo_entry_obj, "scriptPublicKey", &script_pk_obj)) {
                json_object* script_obj;
                if (json_object_object_get_ex(script_pk_obj, "scriptPublicKey", &script_obj)) {
                    const char* script = json_object_get_string(script_obj);
                    safe_string_copy((*utxos)[i].script_public_key, script, sizeof((*utxos)[i].script_public_key));
                }
            }
        }
        
        printf("💰 UTXO %d: %llu sompi (tx: %.8s...)\n",
               i, (*utxos)[i].amount, (*utxos)[i].transaction_id);
    }
    
    json_object_put(root);
    printf("✅ Récupéré %d UTXOs via RPC\n", array_length);
    return KASE_OK;
}



int kase_get_utxos(const char* address, kase_utxo_t** utxos, size_t* count) {
    if (!address || !utxos || !count) return KASE_ERR_INVALID;

    // ========== TOUJOURS UTILISER REST POUR CETTE FONCTION ==========
    const char* endpoint;
    switch (g_kase_network) {
        case KASE_NETWORK_MAINNET:
            endpoint = "https://api.kaspa.org";
            break;
        case KASE_NETWORK_TESTNET_10:
            endpoint = "https://api-tn10.kaspa.org";
            break;
        case KASE_NETWORK_TESTNET_11:
            endpoint = "https://api-tn11.kaspa.org";
            break;
        default:
            endpoint = "https://api.kaspa.org";
    }

    printf("🌐 [REST] Récupération UTXOs depuis: %s (réseau: %s)\n",
           endpoint, get_network_display_name());
    
    // Construire l'URL complète
    char url[512];
    snprintf(url, sizeof(url) - 1, "%s/addresses/%s/utxos", endpoint, address);
    url[sizeof(url) - 1] = '\0';
    
    printf("🔗 URL complète: %s\n", url);
    
    // Préparer la réponse HTTP
    http_response_t response = {0};
    
    // Faire la requête GET
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
    
    // Parser la réponse JSON - root est directement l'array
    json_object* root = json_tokener_parse(response.data);
    free(response.data);
    
    if (!root) {
        printf("❌ Erreur parsing JSON UTXOs\n");
        return KASE_ERR_INVALID;
    }
    
    // Vérifier que c'est bien un array
    if (!json_object_is_type(root, json_type_array)) {
        printf("❌ JSON racine n'est pas un array\n");
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    int array_length = json_object_array_length(root);
    *count = array_length;
    
    printf("📊 Trouvé %d UTXOs\n", array_length);
    
    if (array_length == 0) {
        *utxos = NULL;
        json_object_put(root);
        return KASE_OK;
    }
    
    *utxos = malloc(array_length * sizeof(kase_utxo_t));
    if (!*utxos) {
        json_object_put(root);
        printf("❌ Erreur allocation mémoire UTXOs\n");
        return KASE_ERR_INVALID;
    }
    
    // Parser chaque UTXO
    for (int i = 0; i < array_length; i++) {
        json_object* utxo_obj = json_object_array_get_idx(root, i);
        memset(&(*utxos)[i], 0, sizeof(kase_utxo_t));
        
        // Extraire outpoint
        json_object* outpoint_obj;
        if (json_object_object_get_ex(utxo_obj, "outpoint", &outpoint_obj)) {
            // Transaction ID
            json_object* tx_id_obj;
            if (json_object_object_get_ex(outpoint_obj, "transactionId", &tx_id_obj)) {
                const char* tx_id = json_object_get_string(tx_id_obj);
                safe_string_copy((*utxos)[i].transaction_id, tx_id, sizeof((*utxos)[i].transaction_id));
            }
            
            // Output index
            json_object* index_obj;
            if (json_object_object_get_ex(outpoint_obj, "index", &index_obj)) {
                (*utxos)[i].output_index = json_object_get_int(index_obj);
            }
        }
        
        // Extraire utxoEntry
        json_object* utxo_entry_obj;
        if (json_object_object_get_ex(utxo_obj, "utxoEntry", &utxo_entry_obj)) {
            // Amount (string vers uint64_t)
            json_object* amount_obj;
            if (json_object_object_get_ex(utxo_entry_obj, "amount", &amount_obj)) {
                const char* amount_str = json_object_get_string(amount_obj);
                (*utxos)[i].amount = strtoull(amount_str, NULL, 10);
            }
            
            // Script public key (imbriqué)
            json_object* script_pk_obj;
            if (json_object_object_get_ex(utxo_entry_obj, "scriptPublicKey", &script_pk_obj)) {
                json_object* script_obj;
                if (json_object_object_get_ex(script_pk_obj, "scriptPublicKey", &script_obj)) {
                    const char* script = json_object_get_string(script_obj);
                    safe_string_copy((*utxos)[i].script_public_key, script, sizeof((*utxos)[i].script_public_key));
                }
            }
        }
        
        printf("💰 UTXO %d: %llu sompi (tx: %.8s...)\n",
               i, (*utxos)[i].amount, (*utxos)[i].transaction_id);
    }
    
    json_object_put(root);
    printf("✅ Récupéré %d UTXOs\n", array_length);
    return KASE_OK;
}

int kase_get_balance(const char* address, uint64_t* balance) {
    if (!address || !balance) return KASE_ERR_INVALID;
    
    kase_utxo_t* utxos;
    size_t count;
    
    printf("address in kase_get_balance: %s \n", address);
#if USE_RPC_BROADCAST
    if (kase_get_utxos_RPC(address, &utxos, &count) != KASE_OK) {
        printf("❌ Erreur parsing JSON UTXOs,error calling kase_get_utxos\n");
        return KASE_ERR_INVALID;
    }
#else
    if (kase_get_utxos(address, &utxos, &count) != KASE_OK) {
        printf("❌ Erreur parsing JSON UTXOs,error calling kase_get_utxos\n");
        return KASE_ERR_INVALID;
    }
#endif
    *balance = 0;
    for (size_t i = 0; i < count; i++) {
        *balance += utxos[i].amount;
    }
    
    free(utxos);
    return KASE_OK;
}
///// SIGN
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
    printf("kase_create_transaction - Etape 1\n");
    kase_utxo_t* utxos;
    size_t utxo_count;
    if (kase_get_utxos(from_address, &utxos, &utxo_count) != KASE_OK) {
        result->success = 0;
        safe_string_copy(result->error, "Impossible de récupérer les UTXOs", sizeof(result->error));
        return KASE_ERR_INVALID;
    }
    
    // 2. Calculer le total disponible
    printf("kase_create_transaction - Etape 2\n");
    uint64_t total_available = 0;
    for (size_t i = 0; i < utxo_count; i++) {
        total_available += utxos[i].amount;
    }
    
    // 3. Vérifier si on a assez de fonds et calculer les frais
    printf("kase_create_transaction - Etape 3\n");

    // Déterminer le nombre d'outputs potentiels (1 ou 2 selon s'il y a du change)
    // On estime d'abord avec 2 outputs (pire cas) pour avoir un calcul de frais conservateur
    uint64_t estimated_fee = kaspa_calculate_fee(utxo_count, 2);

    printf("   UTXOs sélectionnés: %zu\n", utxo_count);
    printf("   Taille estimée: %zu bytes\n", kaspa_estimate_tx_size(utxo_count, 2));
    printf("   Frais calculés: %llu sompi (%.8f KAS)\n",
           (unsigned long long)estimated_fee, kase_sompi_to_kas(estimated_fee));

    // Vérifier si on a assez pour payer le montant + frais
    if (total_available < amount_sompi + estimated_fee) {
        result->success = 0;
        snprintf(result->error, sizeof(result->error) - 1,
                "Fonds insuffisants. Disponible: %.8f KAS, Requis: %.8f KAS (montant: %.8f + frais: %.8f)",
                kase_sompi_to_kas(total_available),
                kase_sompi_to_kas(amount_sompi + estimated_fee),
                kase_sompi_to_kas(amount_sompi),
                kase_sompi_to_kas(estimated_fee));
        result->error[sizeof(result->error) - 1] = '\0';
        free(utxos);
        return KASE_ERR_INVALID;
    }

    // Calculer le change
    uint64_t change = total_available - amount_sompi - estimated_fee;

    // Déterminer le nombre réel d'outputs
    size_t output_count = (change > 0) ? 2 : 1;

    // Recalculer les frais avec le nombre exact d'outputs
    uint64_t fee = kaspa_calculate_fee(utxo_count, output_count);

    // Si les frais ont diminué avec moins d'outputs, ajuster le change
    if (fee < estimated_fee && change > 0) {
        change += (estimated_fee - fee);
    }

    printf("   Outputs: %zu (destination%s)\n", output_count, (change > 0) ? " + change" : "");
    printf("   Frais finaux: %llu sompi (%.8f KAS)\n",
           (unsigned long long)fee, kase_sompi_to_kas(fee));
    if (change > 0) {
        printf("   Change: %llu sompi (%.8f KAS)\n",
               (unsigned long long)change, kase_sompi_to_kas(change));
    }

    // 4. Créer la transaction
    printf("kase_create_transaction - Etape 4\n");
    kase_transaction_t tx;
    memset(&tx, 0, sizeof(tx)); // Initialisation sécurisée

    tx.inputs = utxos;
    tx.input_count = utxo_count;
    
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
    printf("kase_create_transaction - Etape 5\n");
    char temp_id[65];
    snprintf(temp_id, sizeof(temp_id) - 1,
             "tx_%llu_%llu", (unsigned long long)amount_sompi, (unsigned long long)fee);
    temp_id[sizeof(temp_id) - 1] = '\0';
    
    safe_string_copy(tx.transaction_id, temp_id, sizeof(tx.transaction_id));
    
    // 6. Broadcaster (simulation)
    printf("kase_create_transaction - Etape 6\n");
    if (kase_broadcast_transaction(&tx, private_key, from_address) == KASE_OK) {
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

static int kase_broadcast_tx_with_rest(const kase_transaction_t* signed_tx) {
    const char* endpoint = get_kaspa_endpoint();
    printf("📡 Broadcasting to REST: %s\n", endpoint);
    
    // Build URL
    char url[512];
    snprintf(url, sizeof(url) - 1, "%s/transactions", endpoint);
    url[sizeof(url) - 1] = '\0';
    
    printf("🔗 Complete broadcast URL: %s\n", url);
    
    // [TOUT LE CODE JSON REST ACTUEL RESTE IDENTIQUE]
    // Build transaction JSON
    json_object* root_json = json_object_new_object();
    json_object* tx_json = json_object_new_object();
    
    // Version field
    json_object_object_add(tx_json, "version", json_object_new_int(0));

    // ========== INPUTS ARRAY ==========
    json_object* inputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx->input_count; i++) {
        json_object* input_obj = json_object_new_object();

        // Previous outpoint
        json_object* outpoint_obj = json_object_new_object();
        json_object_object_add(outpoint_obj, "transactionId",
            json_object_new_string(signed_tx->inputs[i].transaction_id));
        json_object_object_add(outpoint_obj, "index",
            json_object_new_int(signed_tx->inputs[i].output_index));
        json_object_object_add(input_obj, "previousOutpoint", outpoint_obj);

        // Signature script (hex string contenant la signature Schnorr)
        json_object_object_add(input_obj, "signatureScript",
            json_object_new_string(signed_tx->inputs[i].signature_script));

        // Sequence et SigOpCount
        json_object_object_add(input_obj, "sequence", json_object_new_int64(1));
        json_object_object_add(input_obj, "sigOpCount", json_object_new_int(1));

        json_object_array_add(inputs_array, input_obj);
    }
    json_object_object_add(tx_json, "inputs", inputs_array);

    // ========== OUTPUTS ARRAY ==========
    json_object* outputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx->output_count; i++) {
        json_object* output_obj = json_object_new_object();

        // Amount (en string pour éviter problèmes de précision uint64)
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu", signed_tx->outputs[i].amount);
        json_object_object_add(output_obj, "amount", json_object_new_string(amount_str));

        // Script public key object
        json_object* spk_obj = json_object_new_object();
        json_object_object_add(spk_obj, "version", json_object_new_int(0));

        // Générer le script hex depuis l'adresse
        char script_hex[72];
        if (address_to_script_pubkey(signed_tx->outputs[i].address, script_hex, sizeof(script_hex)) == KASE_OK) {
            json_object_object_add(spk_obj, "scriptPublicKey", json_object_new_string(script_hex));
        } else {
            printf("⚠️ Warning: Failed to generate script for output %zu\n", i);
            json_object_object_add(spk_obj, "scriptPublicKey", json_object_new_string(""));
        }

        json_object_object_add(output_obj, "scriptPublicKey", spk_obj);
        json_object_array_add(outputs_array, output_obj);
    }
    json_object_object_add(tx_json, "outputs", outputs_array);

    // ========== METADATA FIELDS ==========
    json_object_object_add(tx_json, "lockTime", json_object_new_int64(0));
    json_object_object_add(tx_json, "subnetworkId",
        json_object_new_string("0000000000000000000000000000000000000000"));
    json_object_object_add(tx_json, "gas", json_object_new_int64(0));
    json_object_object_add(tx_json, "payload", json_object_new_string(""));

    // Add transaction to root
    json_object_object_add(root_json, "transaction", tx_json);

    const char* json_string = json_object_to_json_string(root_json);
    printf("📄 Signed Transaction JSON: %s\n", json_string);
    
    // Send request
    http_response_t response = {0};
    int result = http_post_request(url, json_string, &response);
    
    json_object_put(root_json);
    
    if (result == 0 && response.data) {
        printf("✅ Transaction broadcast successfully via REST\n");
        printf("   Response: %s\n", response.data);
        free(response.data);
        return KASE_OK;
    } else {
        printf("❌ Error broadcasting transaction via REST\n");
        if (response.data) {
            printf("   Error: %s\n", response.data);
            free(response.data);
        }
        return KASE_ERR_INVALID;
    }
}

static int kase_broadcast_tx_with_rpc(const kase_transaction_t* signed_tx) {
    const char* endpoint = get_kaspa_endpoint();
    printf("📡 Broadcasting to RPC: %s\n", endpoint);
    
    // Construire la requête RPC JSON
    json_object* request = json_object_new_object();
    json_object* method = json_object_new_string("submitTransactionRequest");
    json_object* id = json_object_new_int(1);
    json_object* params = json_object_new_object();
    
    // Transaction object (même structure que REST mais dans params)
    json_object* tx_json = json_object_new_object();

    // Version field
    json_object_object_add(tx_json, "version", json_object_new_int(0));

    // ========== INPUTS ARRAY ==========
    json_object* inputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx->input_count; i++) {
        json_object* input_obj = json_object_new_object();

        // Previous outpoint
        json_object* outpoint_obj = json_object_new_object();
        json_object_object_add(outpoint_obj, "transactionId",
            json_object_new_string(signed_tx->inputs[i].transaction_id));
        json_object_object_add(outpoint_obj, "index",
            json_object_new_int(signed_tx->inputs[i].output_index));
        json_object_object_add(input_obj, "previousOutpoint", outpoint_obj);

        // Signature script (hex string contenant la signature Schnorr)
        json_object_object_add(input_obj, "signatureScript",
            json_object_new_string(signed_tx->inputs[i].signature_script));

        // Sequence et SigOpCount
        json_object_object_add(input_obj, "sequence", json_object_new_int64(1));
        json_object_object_add(input_obj, "sigOpCount", json_object_new_int(1));

        json_object_array_add(inputs_array, input_obj);
    }
    json_object_object_add(tx_json, "inputs", inputs_array);

    // ========== OUTPUTS ARRAY ==========
    json_object* outputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx->output_count; i++) {
        json_object* output_obj = json_object_new_object();

        // Amount (en string pour éviter problèmes de précision uint64)
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu", signed_tx->outputs[i].amount);
        json_object_object_add(output_obj, "amount", json_object_new_string(amount_str));

        // Script public key object
        json_object* spk_obj = json_object_new_object();
        json_object_object_add(spk_obj, "version", json_object_new_int(0));

        // Générer le script hex depuis l'adresse
        char script_hex[72];
        if (address_to_script_pubkey(signed_tx->outputs[i].address, script_hex, sizeof(script_hex)) == KASE_OK) {
            json_object_object_add(spk_obj, "scriptPublicKey", json_object_new_string(script_hex));
        } else {
            printf("⚠️ Warning: Failed to generate script for output %zu\n", i);
            json_object_object_add(spk_obj, "scriptPublicKey", json_object_new_string(""));
        }

        json_object_object_add(output_obj, "scriptPublicKey", spk_obj);
        json_object_array_add(outputs_array, output_obj);
    }
    json_object_object_add(tx_json, "outputs", outputs_array);

    // ========== METADATA FIELDS ==========
    json_object_object_add(tx_json, "lockTime", json_object_new_int64(0));
    json_object_object_add(tx_json, "subnetworkId",
        json_object_new_string("0000000000000000000000000000000000000000"));
    json_object_object_add(tx_json, "gas", json_object_new_int64(0));
    json_object_object_add(tx_json, "payload", json_object_new_string(""));

    json_object_object_add(params, "transaction", tx_json);
    json_object_object_add(request, "method", method);
    json_object_object_add(request, "id", id);
    json_object_object_add(request, "params", params);
    
    // Convertir en string
    const char* json_string = json_object_to_json_string(request);
    printf("📤 RPC Request: %s\n", json_string);
    
    // Faire la requête POST
    http_response_t response = {0};
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        json_object_put(request);
        return KASE_ERR_INVALID;
    }
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // ========== TIMEOUTS DE SÉCURITÉ (RPC) ==========
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);         // 30 secondes max
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);  // 10 secondes connexion
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);         // Éviter les signaux

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    json_object_put(request);

    if (res != CURLE_OK || !response.data) {
        printf("❌ Error broadcasting transaction via RPC: %s (code: %d)\n", curl_easy_strerror(res), res);
        if (res == CURLE_OPERATION_TIMEDOUT) {
            printf("   ⏱️  Le serveur RPC n'a pas répondu à temps\n");
        } else if (res == CURLE_COULDNT_CONNECT) {
            printf("   🔌 Impossible de se connecter au serveur RPC\n");
        }
        free(response.data);
        return KASE_ERR_INVALID;
    }
    
    printf("📥 RPC Response: %s\n", response.data);
    
    // Parser la réponse JSON-RPC
    json_object* root = json_tokener_parse(response.data);
    free(response.data);
    
    if (!root) {
        printf("❌ Error parsing RPC response\n");
        return KASE_ERR_INVALID;
    }
    
    // Vérifier les erreurs RPC
    json_object* error_obj;
    if (json_object_object_get_ex(root, "error", &error_obj) && error_obj) {
        printf("❌ RPC Error: %s\n", json_object_to_json_string(error_obj));
        json_object_put(root);
        return KASE_ERR_INVALID;
    }
    
    // Vérifier le résultat
    json_object* result_obj;
    if (json_object_object_get_ex(root, "result", &result_obj)) {
        printf("✅ Transaction broadcast successfully via RPC\n");
        printf("   Result: %s\n", json_object_to_json_string(result_obj));
    }
    
    json_object_put(root);
    return KASE_OK;
}

int kase_broadcast_transaction(const kase_transaction_t* tx, const uint8_t* private_key, const char* sender_address) {
    if (!tx || !private_key || !sender_address) return KASE_ERR_INVALID;

    // 1. RÉCUPÉRER LES VRAIS UTXOs (choix REST ou RPC selon le flag)
    printf("🔐 Step 1: Getting real UTXOs for address: %s\n", sender_address);

    kase_utxo_t* utxos = NULL;
    size_t utxo_count = 0;

#if USE_RPC_BROADCAST
    // Mode RPC: for now never use kase_get_utxos_RPC() but kase_get_utxos. Getting UTXOs on the TESTNET only works with REST
    printf("   📡 Mode: RPC (getUtxosByAddressesRequest)\n");
    int utxo_result = kase_get_utxos_RPC(sender_address, &utxos, &utxo_count);
#else
    // Mode REST: utiliser kase_get_utxos()
    printf("   📡 Mode: REST (GET /addresses/.../utxos)\n");
    int utxo_result = kase_get_utxos(sender_address, &utxos, &utxo_count);
#endif
#warning NEED TO CHECK AVAILABILITY OF RPC UTXOs FETCHING ON MAINNET

    if (utxo_result != KASE_OK || !utxos || utxo_count == 0) {
        printf("❌ Failed to get UTXOs for address: %s\n", sender_address);
        if (utxos) free(utxos);
        return KASE_ERR_INVALID;
    }
    
    printf("✅ Found %zu UTXOs for signing\n", utxo_count);
    
    // 2. SIGNER LA TRANSACTION AVEC LES VRAIS UTXOs
    printf("🔐 Step 2: Signing transaction...\n");
    
    // Créer une copie modifiable de la transaction
    kase_transaction_t signed_tx = *tx;
    
    // Pour chaque input, trouver son UTXO correspondant et signer
    for (size_t i = 0; i < signed_tx.input_count; i++) {
        printf("🔐 Signing input %zu/%zu...\n", i+1, signed_tx.input_count);
        
        // TROUVER L'UTXO CORRESPONDANT À CET INPUT
        kase_utxo_t* matching_utxo = NULL;
        for (size_t j = 0; j < utxo_count; j++) {
            if (strcmp(utxos[j].transaction_id, signed_tx.inputs[i].transaction_id) == 0 &&
                utxos[j].output_index == signed_tx.inputs[i].output_index) {
                matching_utxo = &utxos[j];
                break;
            }
        }
        
        if (!matching_utxo) {
            printf("❌ No matching UTXO found for input %zu (tx: %s, index: %d)\n",
                   i, signed_tx.inputs[i].transaction_id, signed_tx.inputs[i].output_index);
            free(utxos);
            return KASE_ERR_INVALID;
        }
        
        printf("💰 Using UTXO: %llu sompi (tx: %.8s..., index: %d)\n",
               matching_utxo->amount, matching_utxo->transaction_id, matching_utxo->output_index);
        
        // Convertir la transaction kase_transaction_t vers kaspa_transaction_t pour la signature
        kaspa_transaction_t kaspa_tx = {0};
        kaspa_tx.version = 0;
        kaspa_tx.inputs_count = signed_tx.input_count;
        kaspa_tx.outputs_count = signed_tx.output_count;
        kaspa_tx.lock_time = 0;
        kaspa_tx.gas = 0;
        kaspa_tx.payload_len = 0;
        memset(kaspa_tx.subnetwork_id, 0, 20);
        kaspa_tx.payload = NULL;
        
        // Convertir les inputs
        kaspa_tx.inputs = malloc(kaspa_tx.inputs_count * sizeof(kaspa_input_t));
        for (size_t j = 0; j < kaspa_tx.inputs_count; j++) {
            // Convertir transaction_id string vers bytes
            for (int k = 0; k < 32; k++) {
                sscanf(signed_tx.inputs[j].transaction_id + (k * 2), "%2hhx",
                       &kaspa_tx.inputs[j].previous_outpoint.transaction_id[k]);
            }
            kaspa_tx.inputs[j].previous_outpoint.index = signed_tx.inputs[j].output_index;
            kaspa_tx.inputs[j].sequence = 1;
            kaspa_tx.inputs[j].sig_op_count = 1;
        }
        
        // Convertir les outputs
        kaspa_tx.outputs = malloc(kaspa_tx.outputs_count * sizeof(kaspa_output_t));
        for (size_t j = 0; j < kaspa_tx.outputs_count; j++) {
            kaspa_tx.outputs[j].value = signed_tx.outputs[j].amount;
            kaspa_tx.outputs[j].script_version = 0;

            // Générer le script depuis l'adresse
            char script_hex[72];
            if (address_to_script_pubkey(signed_tx.outputs[j].address, script_hex, sizeof(script_hex)) == KASE_OK) {
                size_t script_len = strlen(script_hex) / 2;
                kaspa_tx.outputs[j].script_public_key = malloc(script_len);
                kaspa_tx.outputs[j].script_public_key_len = script_len;
                hex_to_bytes(script_hex, kaspa_tx.outputs[j].script_public_key, script_len);

                // ========== DEBUG PHASE 2 - Affichage du script de l'output de destination ==========
                printf("\n🔍 DEBUG PHASE 2 - Affichage du script de l'output %zu:\n", j);
                printf("   Destination address: %s\n", signed_tx.outputs[j].address);
                printf("   Amount: %llu sompi\n", signed_tx.outputs[j].amount);
                printf("   Script (hex string): %s\n", script_hex);
                printf("   Script (bytes):      ");
                for (size_t k = 0; k < script_len; k++) {
                    printf("%02x", kaspa_tx.outputs[j].script_public_key[k]);
                }
                printf("\n");
                printf("   Script length: %zu bytes\n", script_len);
                // ======================================================================================
            }
        }
        
        // Créer l'UTXO entry pour la signature AVEC LES VRAIES DONNÉES
        kaspa_utxo_entry_t utxo_entry = {0};
        utxo_entry.amount = matching_utxo->amount;  // ✅ VRAI MONTANT
        utxo_entry.script_version = 0;
        
        // Convertir le script hex en bytes AVEC LE VRAI SCRIPT
        size_t script_len = strlen(matching_utxo->script_public_key) / 2;
        utxo_entry.script_public_key = malloc(script_len);
        utxo_entry.script_public_key_len = script_len;
        hex_to_bytes(matching_utxo->script_public_key, utxo_entry.script_public_key, script_len);

        // ========== DEBUG PHASE 2 - Affichage du script UTXO ==========
        printf("\n🔍 DEBUG PHASE 2 - Affichage du script UTXO:\n");
        printf("   Script UTXO (hex string): %s\n", matching_utxo->script_public_key);
        printf("   Script UTXO (bytes):      ");
        for (size_t k = 0; k < script_len; k++) {
            printf("%02x", utxo_entry.script_public_key[k]);
        }
        printf("\n");
        printf("   Script length: %zu bytes\n", script_len);
        if (script_len >= 1) printf("   Byte 0 (opcode): 0x%02x (expected 0x20 for P2PK)\n", utxo_entry.script_public_key[0]);
        if (script_len >= 34) printf("   Byte 33 (opcode): 0x%02x (expected 0xac for OP_CHECKSIG)\n", utxo_entry.script_public_key[33]);
        printf("   UTXO amount: %llu sompi\n", utxo_entry.amount);
        // ================================================================

        // Calculer le SigHash
        uint8_t sighash[32];
        if (kaspa_calc_sighash(&kaspa_tx, i, &utxo_entry, sighash) != 0) {
            printf("❌ Failed to calculate sighash for input %zu\n", i);
            // Cleanup
            free(kaspa_tx.inputs);
            for (size_t k = 0; k < kaspa_tx.outputs_count; k++) {
                if (kaspa_tx.outputs[k].script_public_key) free(kaspa_tx.outputs[k].script_public_key);
            }
            free(kaspa_tx.outputs);
            free(utxo_entry.script_public_key);
            free(utxos);
            return KASE_ERR_INVALID;
        }
        
        
        // Debug du sighash calculé ***BEBUG***
        printf("   Calculated sighash: ");
        for (int k = 0; k < 32; k++) printf("%02x", sighash[k]);
        printf("\n");

        

        
        
        // 🚀 DÉRIVER LA CLÉ PUBLIQUE SCHNORR (BIP340)
        uint8_t public_key_schnorr[32];
        if (bip340_pubkey_create(public_key_schnorr, private_key) != 1) {
            printf("❌ Failed to derive Schnorr public key for input %zu\n", i);

            // Cleanup
            free(kaspa_tx.inputs);
            for (size_t k = 0; k < kaspa_tx.outputs_count; k++) {
                if (kaspa_tx.outputs[k].script_public_key) free(kaspa_tx.outputs[k].script_public_key);
            }
            free(kaspa_tx.outputs);
            free(utxo_entry.script_public_key);
            free(utxos);
            return KASE_ERR_INVALID;
        }
        uint8_t pubkey2[32];
        bip340_pubkey_create(pubkey2, private_key);
        if (memcmp(pubkey2, public_key_schnorr, 32) != 0) {
            fprintf(stderr, "Pubkey mismatch: pubkey2 != public_key_schnorr\n");
            return KASE_ERR_INVALID;
        }

        // ========== DEBUG PHASE 2 - Affichage de la clé publique dérivée ==========
        printf("\n🔍 DEBUG PHASE 2 - Affichage de la clé publique dérivée:\n");
        printf("   Private key (32 bytes): ");
        for (int k = 0; k < 32; k++) printf("%02x", private_key[k]);
        printf("\n");
        printf("   Derived Schnorr pubkey (x-only, 32 bytes): ");
        for (int k = 0; k < 32; k++) printf("%02x", public_key_schnorr[k]);
        printf("\n");
        // ===========================================================================

        // ========== DEBUG PHASE 2 - Vérification de la structure du script P2PK ==========
        printf("\n🔍 DEBUG PHASE 2 - Vérification de la structure du script P2PK:\n");
        if (utxo_entry.script_public_key_len != 34) {
            printf("   ❌ ERREUR: Script length = %zu bytes (expected 34)\n", utxo_entry.script_public_key_len);
        } else {
            printf("   ✅ Script length = 34 bytes (correct)\n");
        }

        if (utxo_entry.script_public_key[0] != 0x20) {
            printf("   ❌ ERREUR: Byte 0 = 0x%02x (expected 0x20)\n", utxo_entry.script_public_key[0]);
        } else {
            printf("   ✅ Byte 0 = 0x20 (OP_DATA_32, correct)\n");
        }

        if (utxo_entry.script_public_key[33] != 0xac) {
            printf("   ❌ ERREUR: Byte 33 = 0x%02x (expected 0xac)\n", utxo_entry.script_public_key[33]);
        } else {
            printf("   ✅ Byte 33 = 0xac (OP_CHECKSIG, correct)\n");
        }
        // ==================================================================================

        if (utxo_entry.script_public_key_len != 34 ||
            utxo_entry.script_public_key[0] != 0x20 ||
            utxo_entry.script_public_key[33] != 0xac) {
            fprintf(stderr, "❌ Prevout non-P2PK v0 (len=%zu)\n", utxo_entry.script_public_key_len);
            return KASE_ERR_INVALID;
        }

        // ========== DEBUG PHASE 2 - Extraction et comparaison des clés publiques ==========
        printf("\n🔍 DEBUG PHASE 2 - Extraction et comparaison des clés publiques:\n");
        printf("   Pubkey from UTXO script (bytes 1-32): ");
        for (int k = 0; k < 32; k++) {
            printf("%02x", utxo_entry.script_public_key[1 + k]);
        }
        printf("\n");

        printf("   Pubkey derived from privkey:          ");
        for (int k = 0; k < 32; k++) {
            printf("%02x", public_key_schnorr[k]);
        }
        printf("\n");

        // Compare x-only pubkey
        if (memcmp(utxo_entry.script_public_key + 1, public_key_schnorr, 32) != 0) {
            printf("   ❌ MISMATCH: Les clés publiques NE CORRESPONDENT PAS!\n");
            printf("   ❌ C'EST LE BUG! La clé privée utilisée ne correspond pas au script UTXO!\n");
            fprintf(stderr, "Mismatch pubkey: derived != prevout\n");
            return KASE_ERR_INVALID;
        } else {
            printf("   ✅ MATCH: Les clés publiques CORRESPONDENT parfaitement!\n");
        }
        // ==================================================================================
            
        
        
        
        // Signer avec BIP340
        uint8_t signature[64];
        if (bip340_sign(signature, sighash, private_key, NULL) != 1) {
            printf("❌ Failed to sign input %zu\n", i);
            // *** DEBUG ***
            printf("   SIGHASH: "); for (int i=0;i<32;i++) printf("%02x", sighash[i]); printf("\n");
            printf("   PUB (derived): "); for (int i=0;i<32;i++) printf("%02x", public_key_schnorr[i]); printf("\n");
            uint8_t utxo_pubkey32[32]; memcpy(utxo_pubkey32, utxo_entry.script_public_key + 1, 32);
            printf("   PUB (UTXO):    "); for (int i=0;i<32;i++) printf("%02x", utxo_pubkey32[i]); printf("\n");
            printf("   SIG (64): "); for (int i=0;i<64;i++) printf("%02x", signature[i]); printf("\n");
            
            // Vérifs séparées pour savoir *où* ça casse
            if (!bip340_verify(signature, sighash, public_key_schnorr)) {
                fprintf(stderr, "Local verify FAILED with derived pubkey\n");
                return KASE_ERR_INVALID;
            }
            if (!bip340_verify(signature, sighash, utxo_pubkey32)) {
                fprintf(stderr, "Local verify FAILED with UTXO pubkey\n");
                return KASE_ERR_INVALID;
            }
            // *** END DEBUG ***
            // Cleanup
            free(kaspa_tx.inputs);
            for (size_t k = 0; k < kaspa_tx.outputs_count; k++) {
                if (kaspa_tx.outputs[k].script_public_key) free(kaspa_tx.outputs[k].script_public_key);
            }
            free(kaspa_tx.outputs);
            free(utxo_entry.script_public_key);
            free(utxos);
            return KASE_ERR_INVALID;
        }
        
        
        //*** DEBUG COMP SECP256k1 ***
        
        uint8_t sig_ref[64];
        int ref_ok = kase_schnorr_sign_digest(sig_ref, sighash, private_key); // aux_rand32 = NULL => zéro
        #if KASE_SIGDBG
        printf("   libsecp sign: %s\n", ref_ok ? "OK" : "FAIL");
        #endif

        if (ref_ok) {
        #if KASE_SIGDBG
            printf("   custom sig : "); for (int k=0;k<64;k++) printf("%02x", signature[k]); printf("\n");
            printf("   secp256k1  : "); for (int k=0;k<64;k++) printf("%02x", sig_ref[k]);  printf("\n");
        #endif
            if (memcmp(signature, sig_ref, 64) != 0) {
                fprintf(stderr, "⚠️  Mismatch custom vs secp256k1 (signatures différentes)\n");
        #if KASE_SIGDBG
                for (int k=0;k<64;k++){ if(signature[k]!=sig_ref[k]){
                    printf("   first diff at byte %d: %02x != %02x\n", k, signature[k], sig_ref[k]); break;
                }}
        #endif
            }

            int v_custom = kase_schnorr_verify_digest(signature, sighash, public_key_schnorr);
            int v_ref    = kase_schnorr_verify_digest(sig_ref,   sighash, public_key_schnorr);
        #if KASE_SIGDBG
            printf("   verify(custom,secp)= %s\n", v_custom? "OK":"FAIL");
            printf("   verify(ref,secp)   = %s\n", v_ref?    "OK":"FAIL");
        #endif
        }

        // Choix de la signature utilisée pour le script (switchable par macro)
        const uint8_t* sig_for_script = signature;  // par défaut: signature maison
        #if KASE_USE_SECP_SIG
        sig_for_script = ref_ok ? sig_ref : signature;
        #endif
        
        
        
        //***  FIN DEBUG COMP SECP256k1 ***
        
        
        if (!bip340_verify(signature, sighash, public_key_schnorr)) {
            fprintf(stderr, "Local Schnorr verify failed (digest or key mismatch)\n");
            return KASE_ERR_INVALID;
        }
        
        uint8_t utxo_pubkey32[32];
        memcpy(utxo_pubkey32, utxo_entry.script_public_key + 1, 32); // 0x20 <32B> 0xac
        if (!bip340_verify(signature, sighash, utxo_pubkey32)) {
            fprintf(stderr, "Local verify failed with UTXO pubkey\n");
            return KASE_ERR_INVALID;
        }
        
        // Debug de la signature générée  ***BEBUG***
        printf("   Generated signature: ");
        for (int k = 0; k < 64; k++) printf("%02x", signature[k]);
        printf("\n");
        
        // 🎯 SIGNATURE SCRIPT KASPA CORRECT - SEULEMENT SIGNATURE !
        /*
        uint8_t sig_script[98];  // 1 + 64 + 1 + 32 + 1 = 99 bytes
        size_t sig_len = 0;

        // Format Kaspa: OP_DATA64 + signature(64) + OP_DATA32 + pubkey(32) + sighash_type(1)
        sig_script[sig_len++] = 0x40; // OP_DATA64 = 64 bytes (signature)
        memcpy(sig_script + sig_len, signature, 64);
        sig_len += 64;

        sig_script[sig_len++] = 0x20; // OP_DATA32 = 32 bytes (pubkey)
        memcpy(sig_script + sig_len, public_key_schnorr, 32);  // ← Utiliser derived_pubkey !
        sig_len += 32;

        sig_script[sig_len++] = KASPA_SIG_HASH_ALL; // 0x01
        */
        // Pour Kaspa P2PK Schnorr BIP340 : OP_DATA_65 + (signature + sighash_type)
        // Le sighash_type EST inclus dans le signature script !
        uint8_t sig_script[66];  // 1 + 65 = 66 bytes
        size_t sig_len = 0;

        // Format Kaspa P2PK Schnorr : OP_DATA_65 + signature(64) + sighash_type(1)
        sig_script[sig_len++] = 0x41; // OP_DATA_65 : "les 65 prochains bytes sont des données"
        memcpy(sig_script + sig_len, sig_for_script, 64);
        sig_len += 64;
        sig_script[sig_len++] = KASPA_SIG_HASH_ALL; // 0x01
        
        // Vérifiez l'endianness de votre signature
        printf("🔍 DEBUG _ DEBUG Signature bytes order:\n");
        for (int i = 0; i < 64; i++) {
            printf("%02x", signature[i]);
            if (i % 8 == 7) printf(" ");
        }
        printf("\n");
        
        /*
        uint8_t sig_script[66];  // 1 + 64 + 1 = 66 bytes
        size_t sig_len = 0;

        // Format: OP_DATA65 + signature(64) + sighash_type(1)
        sig_script[sig_len++] = 0x41; // OP_DATA65 = 65 bytes
        memcpy(sig_script + sig_len, signature, 64);
        sig_len += 64;
        sig_script[sig_len++] = KASPA_SIG_HASH_ALL; // 0x01
         */

        // PAS DE PUBKEY dans signature_script !
        // La pubkey est dans le script_public_key des UTXOs !
        // 2. Push clé publique (32 bytes)
       // sig_script[sig_len++] = 0x20; // OP_PUSHDATA 32 bytes
       // memcpy(sig_script + sig_len, public_key_schnorr, 32);
        //sig_len += 32;

        // Debug de la clé publique  ***BEBUG***
        printf("   Public key: ");
        for (int k = 0; k < 32; k++) printf("%02x", public_key_schnorr[k]);
        printf("\n");
        
        
        // Total : 1 + 64 + 1 + 1 + 32 = 99 bytes

        // Convertir en hex
        bytes_to_hex(sig_script, sig_len, signed_tx.inputs[i].signature_script,
                     sizeof(signed_tx.inputs[i].signature_script));
        
        // 🔍 DEBUG CRITIQUE
        printf("🚨 DEBUG ENCODING:\n");
        printf("   sig_len: %zu\n", sig_len);
        printf("   Buffer size: %zu\n", sizeof(signed_tx.inputs[i].signature_script));
        printf("   Raw bytes: ");
        for (size_t k = 0; k < sig_len; k++) printf("%02x", sig_script[k]);
        printf("\n");
        printf("   Encoded hex: %s\n", signed_tx.inputs[i].signature_script);
        printf("   Encoded len: %zu\n", strlen(signed_tx.inputs[i].signature_script));

        printf("✅ Input %zu signed successfully (sig_script_len: %zu bytes)\n", i, sig_len);
        
        // Cleanup pour cette itération
        free(kaspa_tx.inputs);
        for (size_t k = 0; k < kaspa_tx.outputs_count; k++) {
            if (kaspa_tx.outputs[k].script_public_key) free(kaspa_tx.outputs[k].script_public_key);
        }
        free(kaspa_tx.outputs);
        free(utxo_entry.script_public_key);
    }
    
    // Libérer les UTXOs une fois la signature terminée
    free(utxos);
    
    // 3. BROADCASTER LA TRANSACTION SIGNÉE
    printf("📡 Step 3: Broadcasting signed transaction...\n");
    
#if USE_RPC_BROADCAST
    return kase_broadcast_tx_with_rpc(&signed_tx);
#else
    return kase_broadcast_tx_with_rest(&signed_tx);
#endif
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

    // ========== TIMEOUTS DE SÉCURITÉ (REST) ==========
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);         // 30 secondes max
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);  // 10 secondes connexion
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);         // Éviter les signaux

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        printf("❌ CURL Error in http_post_request: %s (code: %d)\n", curl_easy_strerror(res), res);
        if (res == CURLE_OPERATION_TIMEDOUT) {
            printf("   ⏱️  Le serveur n'a pas répondu à temps\n");
        } else if (res == CURLE_COULDNT_CONNECT) {
            printf("   🔌 Impossible de se connecter au serveur\n");
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}

// Helper function to serialize transaction for hashing
static int serialize_transaction_for_hash(const kase_transaction_t* tx, uint8_t** data, size_t* data_len) {
    // Estimate buffer size (conservative)
    size_t estimated_size = 1024 + (tx->input_count * 256) + (tx->output_count * 256);
    uint8_t* buffer = malloc(estimated_size);
    if (!buffer) return KASE_ERR_INVALID;
    
    size_t offset = 0;
    
    // Version (4 bytes, little endian)
    uint32_t version = 1;
    memcpy(buffer + offset, &version, 4);
    offset += 4;
    
    // Input count (varint - simplified to 1 byte for now)
    buffer[offset++] = (uint8_t)tx->input_count;
    
    // Inputs
    for (size_t i = 0; i < tx->input_count; i++) {
        // Previous outpoint transaction ID (32 bytes)
        if (strlen(tx->inputs[i].transaction_id) == 64) { // hex string
            for (int j = 0; j < 32; j++) {
                sscanf(tx->inputs[i].transaction_id + (j * 2), "%2hhx", &buffer[offset + j]);
            }
        }
        offset += 32;
        
        // Previous outpoint index (4 bytes, little endian)
        uint32_t index = tx->inputs[i].output_index;
        memcpy(buffer + offset, &index, 4);
        offset += 4;
        
        // Sequence (4 bytes, little endian) - default 0xFFFFFFFF
        uint32_t sequence = 1; //0xFFFFFFFF <- value for BTC,
        memcpy(buffer + offset, &sequence, 4);
        offset += 4;
    }
    
    // Output count (varint - simplified)
    buffer[offset++] = (uint8_t)tx->output_count;
    
    // Outputs
    for (size_t i = 0; i < tx->output_count; i++) {
        // Amount (8 bytes, little endian)
        uint64_t amount = tx->outputs[i].amount;
        memcpy(buffer + offset, &amount, 8);
        offset += 8;
        
        // Script length and script (simplified - address to P2PKH script)
        // For now, just use a placeholder
        buffer[offset++] = 25; // P2PKH script length
        // P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        buffer[offset++] = 0x76; // OP_DUP
        buffer[offset++] = 0xa9; // OP_HASH160
        buffer[offset++] = 0x14; // 20 bytes
        memset(buffer + offset, 0, 20); // placeholder for address hash
        offset += 20;
        buffer[offset++] = 0x88; // OP_EQUALVERIFY
        buffer[offset++] = 0xac; // OP_CHECKSIG
    }
    
    // Lock time (4 bytes)
    uint32_t lock_time = 0;
    memcpy(buffer + offset, &lock_time, 4);
    offset += 4;
    
    *data = buffer;
    *data_len = offset;
    return KASE_OK;
}
// Fonctions de HASH et signature de transaction
// Hash d'un outpoint
static void hash_outpoint(blake2b_state *hasher, const kaspa_outpoint_t *outpoint) {
    
    printf("🔍 *** DEBUG *** hash_outpoint DEBUG:\n"); // *** DEBUG ***
        printf("   TX ID (hex): ");
        for(int i = 0; i < 32; i++) {
            printf("%02x", outpoint->transaction_id[i]);
        }
        printf("\n   TX ID (raw): ");
        for(int i = 0; i < 32; i++) {
            printf("%c", outpoint->transaction_id[i] >= 32 && outpoint->transaction_id[i] < 127 ? outpoint->transaction_id[i] : '.');
        }
        printf("\n   Index: %u\n", outpoint->index);
        
    blake2b_Update(hasher, outpoint->transaction_id, 32);
    uint8_t index_bytes[4];
    index_bytes[0] = outpoint->index & 0xFF;
    index_bytes[1] = (outpoint->index >> 8) & 0xFF;
    index_bytes[2] = (outpoint->index >> 16) & 0xFF;
    index_bytes[3] = (outpoint->index >> 24) & 0xFF;
    blake2b_Update(hasher, index_bytes, 4);
}

// Hash d'un script public key
/*
static void hash_script_public_key(blake2b_state *hasher, const uint8_t *script, size_t len) {
    uint8_t len_bytes[8];
    write_u64_le(len_bytes, len);
    blake2b_Update(hasher, len_bytes, 8);
    blake2b_Update(hasher, script, len);
}
*/
static void hash_script_public_key(blake2b_state *hasher, const uint8_t *script, size_t len) {
    // Version du script (2 bytes, toujours 0x0000 pour Kaspa)
    uint8_t version_bytes[2] = {0x00, 0x00};
    blake2b_Update(hasher, version_bytes, 2);
    printf("   --------------DEBUG  Script version: 0x%02x%02x\n", version_bytes[0], version_bytes[1]);
    
    
    // Script avec longueur variable
        printf("   Script len: %zu\n", len);
        printf("   Var len encoding: ");
    if (len < 0xfd) {
        uint8_t len_byte = (uint8_t)len;
        
    }
    // Script avec longueur variable
    write_var_bytes(hasher, script, len);
    
    printf("   Script data: ");
        for (size_t i = 0; i < len; i++) {
            printf("%02x", script[i]);
        }
        printf("\n");
    
}

// Hash des previous outputs
static void previous_outputs_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    // Utiliser Blake2b avec clef de domaine "TransactionSigningHash"
    blake2b_InitKey(&hasher, 32, "TransactionSigningHash", 22);

    for (size_t i = 0; i < tx->inputs_count; i++) {
        hash_outpoint(&hasher, &tx->inputs[i].previous_outpoint);
    }

    blake2b_Final(&hasher, hash, 32);
}

// Hash des sequences
static void sequences_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_InitKey(&hasher, 32, "TransactionSigningHash", 22);

    for (size_t i = 0; i < tx->inputs_count; i++) {
        uint8_t seq_bytes[8];
        write_u64_le(seq_bytes, tx->inputs[i].sequence);
        blake2b_Update(&hasher, seq_bytes, 8);
    }

    blake2b_Final(&hasher, hash, 32);
}

// Hash des sig_op_counts
static void sig_op_counts_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_InitKey(&hasher, 32, "TransactionSigningHash", 22);

    for (size_t i = 0; i < tx->inputs_count; i++) {
        blake2b_Update(&hasher, &tx->inputs[i].sig_op_count, 1);
    }

    blake2b_Final(&hasher, hash, 32);
}

// Hash des outputs
static void outputs_hash1(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_Init(&hasher, 32);
    
    for (size_t i = 0; i < tx->outputs_count; i++) {
        // Value (8 bytes LE)
        uint8_t value_bytes[8];
        write_u64_le(value_bytes, tx->outputs[i].value);
        blake2b_Update(&hasher, value_bytes, 8);
        
        // Script version (2 bytes LE)
        uint8_t version_bytes[2];
        write_u16_le(version_bytes, tx->outputs[i].script_version);
        blake2b_Update(&hasher, version_bytes, 2);
        
        // Script public key
        hash_script_public_key(&hasher, tx->outputs[i].script_public_key,
                              tx->outputs[i].script_public_key_len);
    }
    
    blake2b_Final(&hasher, hash, 32);
    
}

// Hash des outputs
static void outputs_hash(const kaspa_transaction_t *tx, uint8_t *out32)
{
    blake2b_state h;
    blake2b_InitKey(&h, 32, "TransactionSigningHash", 22);

#if KASE_SIGDBG
    printf("\n🔍 *** DEBUG outputs_hash() ***\n");
    printf("   Nombre d'outputs: %zu\n", tx->outputs_count);
#endif

    for (size_t i = 0; i < tx->outputs_count; i++) {
        const kaspa_output_t* o = &tx->outputs[i];

        // Value (uint64 LE)
        uint8_t valb[8];
        write_u64_le(valb, o->value);
        blake2b_Update(&h, valb, 8);

#if KASE_SIGDBG
        printf("   Output %zu:\n", i);
        printf("     Value: %llu sompi\n", (unsigned long long)o->value);
        printf("     Value (u64 LE bytes): ");
        for (int k = 0; k < 8; k++) printf("%02x", valb[k]);
        printf("\n");
        printf("     Script version: %u\n", o->script_version);
        printf("     Script length: %zu bytes\n", o->script_public_key_len);
        printf("     Script (hex): ");
        for (size_t k = 0; k < o->script_public_key_len; k++) printf("%02x", o->script_public_key[k]);
        printf("\n");
#endif

        // ScriptPublicKey = Version (u16 LE) + Script (var-bytes)
        hash_output_spk(&h, o->script_version, o->script_public_key, o->script_public_key_len);
    }

    blake2b_Final(&h, out32, 32);

#if KASE_SIGDBG
    printf("   Resulting outputsHash: ");
    for (int k = 0; k < 32; k++) printf("%02x", out32[k]);
    printf("\n");
#endif
}



// Hash du payload
static void payload_hash1(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_Init(&hasher, 32);
    
    uint8_t len_bytes[8];
    write_u64_le(len_bytes, tx->payload_len);
    blake2b_Update(&hasher, len_bytes, 8);
    
    if (tx->payload_len > 0) {
        blake2b_Update(&hasher, tx->payload, tx->payload_len);
    }
    
    blake2b_Final(&hasher, hash, 32);
}

// Nouvelle implémentation
static void payload_hash(uint8_t out32[32],
                         const uint8_t subnetwork_id[20],
                         const uint8_t* payload, size_t payload_len)
{
    // Native tx ? (SubnetworkID = 20 octets à 0) => payloadHash = 32 zéros
    bool is_native = true;
    for (int i = 0; i < 20; ++i) {
        if (subnetwork_id[i] != 0) { is_native = false; break; }
    }

    if (is_native) {
        memset(out32, 0, 32);
        return;
    }

    blake2b_state h;
    blake2b_Init(&h, 32);
    if (payload_len > 0 && payload) {
        blake2b_Update(&h, payload, payload_len);  // hash du payload (pas (len||payload))
    }
    blake2b_Final(&h, out32, 32);
}

// Shim compatible avec l’ancien appel : payload_hash(tx, out32)
static inline void payload_hash_from_tx(const kaspa_transaction_t* tx, uint8_t out32[32]) {
    payload_hash(out32, tx->subnetwork_id, tx->payload, tx->payload_len);
}


// Calcul COMPLET du SigHash Kaspa
int kaspa_calc_sighash1(const kaspa_transaction_t *tx,
                      int input_index,
                      const kaspa_utxo_entry_t *utxo,
                      uint8_t *sighash) {
    printf("🔍 =============== SIGHASH DEBUG ===============\n");
    blake2b_state hasher;
    if (blake2b_Init(&hasher, 32) != 0) return -1;
    
    // 1. Version (2 bytes LE)
    uint8_t version_bytes[2];
    write_u16_le(version_bytes, tx->version);
    blake2b_Update(&hasher, version_bytes, 2);
    printf("1. Version: %u (0x%02x%02x)\n", tx->version, version_bytes[0], version_bytes[1]);
    
    // 2. Previous outputs hash (32 bytes)
    uint8_t prev_hash[32];
    previous_outputs_hash(tx, prev_hash);  //hash_point appelé dans previous_outputs_hash, appel faux
    blake2b_Update(&hasher, prev_hash, 32);
    printf("2. Prev outputs hash: ");
        for(int i = 0; i < 8; i++) printf("%02x", prev_hash[i]);
        printf("...\n");
    
    // 3. Sequences hash (32 bytes)
    uint8_t seq_hash[32];
    sequences_hash(tx, seq_hash);
    blake2b_Update(&hasher, seq_hash, 32);
    printf("3. Sequences hash: ");
        for(int i = 0; i < 8; i++) printf("%02x", seq_hash[i]);
        printf("...\n");
    
    // 4. Sig op counts hash (32 bytes)
    uint8_t sigop_hash[32];
    sig_op_counts_hash(tx, sigop_hash);
    blake2b_Update(&hasher, sigop_hash, 32);
    printf("4. SigOp counts hash: ");
        for(int i = 0; i < 8; i++) printf("%02x", sigop_hash[i]);
        printf("...\n");
    
    // 5. Current input outpoint
    printf("5. Outpoint: %s:%u\n", tx->inputs[input_index].previous_outpoint.transaction_id,
               tx->inputs[input_index].previous_outpoint.index);
    hash_outpoint(&hasher, &tx->inputs[input_index].previous_outpoint);  // deuxième appel de hash_output, valide
    
    // 6. Current input script public key
    //hash_script_public_key(&hasher, utxo->script_public_key, utxo->script_public_key_len);
    hash_current_input_spk(&hasher,
        /*ver=*/0,                         // P2PK v0
        utxo->script_public_key,
        utxo->script_public_key_len);
    
    // 7. Current input amount (8 bytes LE)
    uint8_t amount_bytes[8];
    write_u64_le(amount_bytes, utxo->amount);
    blake2b_Update(&hasher, amount_bytes, 8);
    printf("7. Amount: %llu\n", utxo->amount);
    
    // 8. Current input sequence (8 bytes LE)
    uint8_t seq_bytes[8];
    write_u64_le(seq_bytes, tx->inputs[input_index].sequence);
    blake2b_Update(&hasher, seq_bytes, 8);
    printf("8. Sequence: %llu\n", tx->inputs[input_index].sequence);
    
    // 9. Current input sig_op_count (1 byte)
    blake2b_Update(&hasher, &tx->inputs[input_index].sig_op_count, 1);
    printf("9. SigOp count: %u\n", tx->inputs[input_index].sig_op_count);
    
    // 10. Outputs hash (32 bytes)
    uint8_t out_hash[32];
    outputs_hash(tx, out_hash);
    blake2b_Update(&hasher, out_hash, 32);
    printf("10. Outputs hash: ");
        for(int i = 0; i < 8; i++) printf("%02x", out_hash[i]);
        printf("...\n");
    
    // 11. Lock time (8 bytes LE)
    uint8_t lock_bytes[8];
    write_u64_le(lock_bytes, tx->lock_time);
    blake2b_Update(&hasher, lock_bytes, 8);
    printf("11. Lock time: %llu\n", tx->lock_time);
    
    // 12. Subnetwork ID (20 bytes)
    blake2b_Update(&hasher, tx->subnetwork_id, 20);
    printf("12. Subnetwork ID: ");
        for(int i = 0; i < 8; i++) printf("%02x", tx->subnetwork_id[i]);
    printf("...\n");
    
    // 13. Gas (8 bytes LE)
    uint8_t gas_bytes[8];
    write_u64_le(gas_bytes, tx->gas);
    blake2b_Update(&hasher, gas_bytes, 8);
    printf("13. Gas: %llu\n", tx->gas);
    
    // 14. Payload hash (32 bytes)
    uint8_t pay_hash[32];
    payload_hash_from_tx(tx, pay_hash);
    blake2b_Update(&hasher, pay_hash, 32);
    printf("14. Payload hash: ");
        for(int i = 0; i < 8; i++) printf("%02x", pay_hash[i]);
        printf("...\n");
    
    // 15. SigHash type (1 byte)
    uint8_t sighash_type = KASPA_SIG_HASH_ALL;
    blake2b_Update(&hasher, &sighash_type, 1);
    printf("15. SigHash type: 0x%02x\n", sighash_type);
    
    return blake2b_Final(&hasher, sighash, 32);
}


// Calcul COMPLET du SigHash Kaspa (instrumenté selon mdBook 1→18)
int kaspa_calc_sighash(const kaspa_transaction_t *tx,
                       int input_index,
                       const kaspa_utxo_entry_t *utxo,
                       uint8_t *sighash)
{
#if KASE_SIGDBG
    printf("🔍 =============== SIGHASH DEBUG (input %d) ===============\n", input_index);
#endif

    blake2b_state hasher;
    if (blake2b_InitKey(&hasher, 32, "TransactionSigningHash", 22) != 0) return -1;

    // 1. Version (uint16 LE)
    uint8_t vbytes[2]; write_u16_le(vbytes, tx->version);
    blake2b_Update(&hasher, vbytes, 2);
#if KASE_SIGDBG
    printf("1. Version: %u (LE %02x %02x)\n", tx->version, vbytes[0], vbytes[1]);
#endif

    // 2. previousOutputsHash (32)
    uint8_t prevouts_hash[32]; previous_outputs_hash(tx, prevouts_hash);
    blake2b_Update(&hasher, prevouts_hash, 32);
    dbg_hex("2. previousOutputsHash: ", prevouts_hash, 32, 32);

    // 3. sequencesHash (32)
    uint8_t seq_hash[32]; sequences_hash(tx, seq_hash);
    blake2b_Update(&hasher, seq_hash, 32);
    dbg_hex("3. sequencesHash: ", seq_hash, 32, 32);

    // 4. sigOpCountsHash (32)
    uint8_t sigop_hash[32]; sig_op_counts_hash(tx, sigop_hash);
    blake2b_Update(&hasher, sigop_hash, 32);
    dbg_hex("4. sigOpCountsHash: ", sigop_hash, 32, 32);

    // 5. Current input PreviousOutpoint.TransactionID (32)
    // (Attention : pas d'inversion d’endian, on pousse les 32 octets tels qu’en mémoire)
    const kaspa_input_t* in = &tx->inputs[input_index];
#if KASE_SIGDBG
    printf("5. Outpoint.txid (hex, 32): ");
    for (int i=0;i<32;i++) printf("%02x", ((const uint8_t*)in->previous_outpoint.transaction_id)[i]);
    printf("\n");
    printf("6. Outpoint.index (u32 LE): %u\n", in->previous_outpoint.index);
#endif
    blake2b_Update(&hasher, (const uint8_t*)in->previous_outpoint.transaction_id, 32);

    // 6. Current input PreviousOutpoint.Index (uint32 LE)
    uint8_t idx4[4]; write_u32_le(idx4, in->previous_outpoint.index);
    blake2b_Update(&hasher, idx4, 4);

    // 7–9. Current input ScriptPubKey (prevout)
    // 7. Version (u16 LE), 8. Length (u64 LE), 9. Script bytes
    hash_current_input_spk(&hasher, utxo->script_version, utxo->script_public_key, utxo->script_public_key_len);
#if KASE_SIGDBG
    printf("7. Prevout ScriptPubKeyVersion: %u\n", utxo->script_version);
    printf("8. Prevout ScriptPubKeyLength (u64): %zu\n", utxo->script_public_key_len);
    dbg_hex("9. Prevout ScriptPubKey (hex): ", utxo->script_public_key, utxo->script_public_key_len, 16);
#endif

    // 10. Current input PreviousOutput.Value (uint64 LE)
    uint8_t val8[8]; write_u64_le(val8, utxo->amount);
    blake2b_Update(&hasher, val8, 8);
#if KASE_SIGDBG
    printf("10. Prevout Value (satoshis): %llu\n", (unsigned long long)utxo->amount);
#endif

    // 11. Current input Sequence (uint64 LE)
    uint8_t seq8[8]; write_u64_le(seq8, in->sequence);
    blake2b_Update(&hasher, seq8, 8);
#if KASE_SIGDBG
    printf("11. Input Sequence: %llu\n", (unsigned long long)in->sequence);
#endif

    // 12. Current input SigOpCount (uint8)
    blake2b_Update(&hasher, &in->sig_op_count, 1);
#if KASE_SIGDBG
    printf("12. Input SigOpCount: %u\n", in->sig_op_count);
#endif

    // 13. outputsHash (32)
    uint8_t out_hash[32]; outputs_hash(tx, out_hash);
    blake2b_Update(&hasher, out_hash, 32);
    dbg_hex("13. outputsHash: ", out_hash, 32, 32);

    // 14. tx.Locktime (uint64 LE)
    uint8_t lock8[8]; write_u64_le(lock8, tx->lock_time);
    blake2b_Update(&hasher, lock8, 8);
#if KASE_SIGDBG
    printf("14. Locktime: %llu\n", (unsigned long long)tx->lock_time);
#endif

    // 15. tx.SubnetworkID (20)
    blake2b_Update(&hasher, tx->subnetwork_id, 20);
    dbg_hex("15. SubnetworkID (20B): ", tx->subnetwork_id, 20, 20);

    // 16. tx.Gas (uint64 LE)
    uint8_t gas8[8]; write_u64_le(gas8, tx->gas);
    blake2b_Update(&hasher, gas8, 8);
#if KASE_SIGDBG
    printf("16. Gas: %llu\n", (unsigned long long)tx->gas);
#endif

    // 17. payloadHash (32) — native => 32×00
    uint8_t pay_hash[32];
    payload_hash(pay_hash, tx->subnetwork_id, tx->payload, tx->payload_len);
    blake2b_Update(&hasher, pay_hash, 32);
    dbg_hex("17. payloadHash: ", pay_hash, 32, 32);

    // 18. SigHashType (1 byte)
    uint8_t sighash_type = KASPA_SIG_HASH_ALL; // 0x01
    blake2b_Update(&hasher, &sighash_type, 1);
#if KASE_SIGDBG
    printf("18. SigHashType: 0x%02x\n", sighash_type);
#endif

    // Final
    int rc = blake2b_Final(&hasher, sighash, 32);
    dbg_hex("✅ SIGHASH: ", sighash, 32, 32);
    return rc;
}


// Signature COMPLÈTE et fonctionnelle
int kaspa_sign_transaction(const uint8_t *private_key,
                          const kase_transaction_t *tx,
                          int input_index,
                          const kase_utxo_t *utxo,
                          const uint8_t *script,
                          size_t script_len,
                          uint8_t *signature_script,
                          size_t *sig_script_len) {
    
    // 1. Calculer le SigHash
    uint8_t sighash[32];
    if (kaspa_calc_sighash(tx, input_index, utxo, sighash) != 0) {
        return -1;
    }
    
    // 2. Signer avec Schnorr BIP340 - NOUVELLE FONCTION
    uint8_t signature[64];
    if (bip340_sign(signature, sighash, private_key, NULL) != 1) {
        return -2;
    }
    
    // 3. Construire le signature_script
    size_t offset = 0;
    
    // Signature + SigHash type (65 bytes)
    signature_script[offset++] = 65;  // longueur
    memcpy(signature_script + offset, signature, 64);
    offset += 64;
    signature_script[offset++] = KASPA_SIG_HASH_ALL;
    
    // Condition (OP_TRUE = 0x51)
    signature_script[offset++] = 0x51;
    
    // Script de déverrouillage
    signature_script[offset++] = script_len;
    memcpy(signature_script + offset, script, script_len);
    offset += script_len;
    
    *sig_script_len = offset;
    return 0;
}

// Fonction pour convertir adresse Kaspa en script Kaspa valide
static int address_to_script_pubkey(const char* address, char* script_hex, size_t script_hex_size) {
    if (!address || strlen(address) == 0 || script_hex_size < 69) { // 68 + '\0'
        return KASE_ERR_INVALID;
    }
    
    // 1. Décoder l'adresse Kaspa
    uint8_t pubkey_hash[32];
    char prefix[32];
    
    if (kaspa_decode_address(address, pubkey_hash, prefix) != KASE_OK) {
        printf("❌ Erreur décodage adresse Kaspa: %s\n", address);
        return KASE_ERR_DECODE;
    }
    
    // 2. Générer le script : PUSH(32) + hash(32 bytes) + OP_CHECKSIG
    uint8_t script[34];
    script[0] = 0x20;  // PUSH 32 bytes
    memcpy(script + 1, pubkey_hash, 32);
    script[33] = 0xac; // OP_CHECKSIG
    
    // 3. Convertir en hex avec vérification
    for (int i = 0; i < 34; i++) {
        snprintf(script_hex + (i * 2), 3, "%02x", script[i]); // Assurer 2 chars + '\0'
    }
    script_hex[68] = '\0';
    
    printf("✅ Script généré (%zu chars): %s\n", strlen(script_hex), script_hex);
    
    return KASE_OK;
}

static void write_u32_le(uint8_t *buf, uint32_t value) {
    buf[0] = value & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 24) & 0xff;
}

static void write_var_bytes(blake2b_state *hasher, const uint8_t *data, size_t len) {
    // Encode la longueur en varint
    printf("🔍 ----------------DEBUG WW write_var_bytes: len=%zu\n", len);
    if (len < 0xfd) {
        uint8_t len_byte = (uint8_t)len;
        blake2b_Update(hasher, &len_byte, 1);
    } else if (len <= 0xffff) {
        uint8_t marker = 0xfd;
        blake2b_Update(hasher, &marker, 1);
        uint8_t len_bytes[2];
        write_u16_le(len_bytes, (uint16_t)len);
        blake2b_Update(hasher, len_bytes, 2);
    } else if (len <= 0xffffffff) {
        uint8_t marker = 0xfe;
        blake2b_Update(hasher, &marker, 1);
        uint8_t len_bytes[4];
        write_u32_le(len_bytes, (uint32_t)len);
        blake2b_Update(hasher, len_bytes, 4);
    } else {
        uint8_t marker = 0xff;
        blake2b_Update(hasher, &marker, 1);
        uint8_t len_bytes[8];
        write_u64_le(len_bytes, len);
        blake2b_Update(hasher, len_bytes, 8);
    }
    
    // Puis les données
    blake2b_Update(hasher, data, len);
}
