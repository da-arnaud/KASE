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


static const char* KASPA_MAINNET_RPC = "https://api.kaspa.org";
static const char* KASPA_TESTNET_RPC_10 = "https://api-tn10.kaspa.org";
static const char* KASPA_TESTNET_RPC_11 = "https://api-tn11.kaspa.org";



int kaspa_calc_sighash(const kaspa_transaction_t *tx,
                      int input_index,
                      const kaspa_utxo_entry_t *utxo,
                      uint8_t *sighash);

// Conversion KAS <-> Sompi
uint64_t kase_kas_to_sompi(double kas) {
    return (uint64_t)(kas * 100000000.0); // 1 KAS = 100M sompi
}

double kase_sompi_to_kas(uint64_t sompi) {
    return (double)sompi / 100000000.0;
}

// Utility function to get teh endpoint
static const char* get_kaspa_rpc_endpoint(void) {
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

int kase_get_utxos(const char* address, kase_utxo_t** utxos, size_t* count) {
    if (!address || !utxos || !count) return KASE_ERR_INVALID;
    
    const char* endpoint = get_kaspa_rpc_endpoint();
        
    printf("🌐 Récupération UTXOs depuis: %s (réseau: %s)\n",
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
    
    if (kase_get_utxos(address, &utxos, &count) != KASE_OK) {
        printf("❌ Erreur parsing JSON UTXOs,error calling kase_get_utxos\n");
        return KASE_ERR_INVALID;
    }
    
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
    
    // 3. Vérifier si on a assez de fonds
    printf("kase_create_transaction - Etape 3\n");
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
    printf("kase_create_transaction - Etape 4\n");
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

int kase_broadcast_transaction(const kase_transaction_t* tx, const uint8_t* private_key, const char* sender_address) {
    if (!tx || !private_key || !sender_address) return KASE_ERR_INVALID;
    
    // 1. RÉCUPÉRER LES VRAIS UTXOs
    printf("🔐 Step 1: Getting real UTXOs for address: %s\n", sender_address);
    
    kase_utxo_t* utxos = NULL;
    size_t utxo_count = 0;
    
    int utxo_result = kase_get_utxos(sender_address, &utxos, &utxo_count);
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
        
        printf("📄 Using real script: %s (len: %zu)\n", matching_utxo->script_public_key, script_len);
        // Juste avant kaspa_calc_sighash ***BEBUG***
        printf("🔍 Debug signature:\n");
        printf("   UTXO amount: %llu\n", utxo_entry.amount);
        printf("   UTXO script: %s\n", matching_utxo->script_public_key);
        printf("   UTXO script len: %zu\n", utxo_entry.script_public_key_len);
        printf("   KASPA_SIG_HASH_ALL: 0x%02x\n", KASPA_SIG_HASH_ALL);
        
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
        int test = bip340_pubkey_create(public_key_schnorr, private_key);
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
        // *** DEBUG ***
        // Debug de la clé publique générée
        printf("🔑 Debug clés:\n");
        printf("   Private key: ");
        for (int k = 0; k < 32; k++) printf("%02x", private_key[k]);
        printf("\n");
        printf("   Generated pubkey: ");
        for (int k = 0; k < 32; k++) printf("%02x", public_key_schnorr[k]);
        printf("\n");
        printf("   UTXO script pubkey: %s\n", matching_utxo->script_public_key);
        
        
        
        
        // Signer avec BIP340
        uint8_t signature[64];
        if (bip340_sign(signature, sighash, private_key, NULL) != 1) {
            printf("❌ Failed to sign input %zu\n", i);
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
        
    

        // *** AJOUTE LE NOUVEAU DEBUG ICI ***
        printf("🔑 DEBUG COMPLET:\n");
        printf("   from_address: %s\n", sender_address);
        printf("   private_key (hex): ");
        for (int k = 0; k < 32; k++) printf("%02x", private_key[k]);
        printf("\n");

        // Générer l'adresse depuis la clé privée pour vérification
        uint8_t derived_pubkey[32];
        if (bip340_pubkey_create(derived_pubkey, private_key) == 1) {
            printf("   derived_pubkey: ");
            for (int k = 0; k < 32; k++) printf("%02x", derived_pubkey[k]);
            printf("\n");
            
            char derived_address[128];
            //kase_network_type_t network = get_kaspa_rpc_endpoint();
            if (kaspa_pubkey_to_address(derived_pubkey, derived_address, sizeof(derived_address), g_kase_network) == KASE_OK) {
                printf("   derived_address: %s\n", derived_address);
                printf("   MATCH: %s\n", strcmp(derived_address, sender_address) == 0 ? "✅ OUI" : "❌ NON");
            }
        }
        
        
        // Debug de la signature générée  ***BEBUG***
        printf("   Generated signature: ");
        for (int k = 0; k < 64; k++) printf("%02x", signature[k]);
        printf("\n");
        
        // 🎯 SIGNATURE SCRIPT KASPA CORRECT - SEULEMENT SIGNATURE !
        uint8_t sig_script[66];  // 1 + 64 + 1 = 66 bytes
        size_t sig_len = 0;

        // Format: OP_DATA65 + signature(64) + sighash_type(1)
        sig_script[sig_len++] = 0x41; // OP_DATA65 = 65 bytes
        memcpy(sig_script + sig_len, signature, 64);
        sig_len += 64;
        sig_script[sig_len++] = KASPA_SIG_HASH_ALL; // 0x01


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
    
    const char* endpoint = get_kaspa_rpc_endpoint();
    printf("📡 Broadcasting to: %s\n", endpoint);
    
    // Build URL
    char url[512];
    snprintf(url, sizeof(url) - 1, "%s/transactions", endpoint);
    url[sizeof(url) - 1] = '\0';
    
    printf("🔗 Complete broadcast URL: %s\n", url);
    
    // Build transaction JSON
    json_object* root_json = json_object_new_object();
    json_object* tx_json = json_object_new_object();
    
    // Version field
    json_object_object_add(tx_json, "version", json_object_new_int(0));
    
    // Inputs array
    json_object* inputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx.input_count; i++) {
        json_object* input_obj = json_object_new_object();
        
        // previousOutpoint object
        json_object* outpoint_obj = json_object_new_object();
        json_object_object_add(outpoint_obj, "transactionId",
                              json_object_new_string(signed_tx.inputs[i].transaction_id));
        json_object_object_add(outpoint_obj, "index",
                              json_object_new_int(signed_tx.inputs[i].output_index));
        json_object_object_add(input_obj, "previousOutpoint", outpoint_obj);
        
        // signatureScript avec signature + clé publique
        json_object_object_add(input_obj, "signatureScript",
                              json_object_new_string(signed_tx.inputs[i].signature_script));
        
        // sequence
        json_object_object_add(input_obj, "sequence", json_object_new_int64(1));
        
        // sigOpCount
        json_object_object_add(input_obj, "sigOpCount", json_object_new_int(1));
        
        json_object_array_add(inputs_array, input_obj);
    }
    json_object_object_add(tx_json, "inputs", inputs_array);
    
    // Outputs array
    json_object* outputs_array = json_object_new_array();
    for (size_t i = 0; i < signed_tx.output_count; i++) {
        json_object* output_obj = json_object_new_object();
        
        // Convert amount to string
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu", signed_tx.outputs[i].amount);
        json_object_object_add(output_obj, "amount", json_object_new_string(amount_str));
        
        // scriptPublicKey
        json_object* script_pk_obj = json_object_new_object();
        char script_hex[72];
        if (address_to_script_pubkey(signed_tx.outputs[i].address, script_hex, sizeof(script_hex)) == KASE_OK) {
            json_object_object_add(script_pk_obj, "version", json_object_new_int(0));
            json_object_object_add(script_pk_obj, "scriptPublicKey",
                                  json_object_new_string(script_hex));
        } else {
            printf("❌ Error generating script for output %zu\n", i);
            json_object_object_add(script_pk_obj, "version", json_object_new_int(0));
            json_object_object_add(script_pk_obj, "script",
                                  json_object_new_string("2014000000000000000000000000000000000000000000000000000000000000ac"));
        }
        
        json_object_object_add(output_obj, "scriptPublicKey", script_pk_obj);
        json_object_array_add(outputs_array, output_obj);
    }
    json_object_object_add(tx_json, "outputs", outputs_array);
    
    // Add transaction to root
    json_object_object_add(root_json, "transaction", tx_json);
    
    const char* json_string = json_object_to_json_string(root_json);
    printf("📄 Signed Transaction JSON: %s\n", json_string);
    
    // Send request
    http_response_t response = {0};
    int result = http_post_request(url, json_string, &response);
    
    json_object_put(root_json);
    
    if (result == 0 && response.data) {
        printf("✅ Transaction broadcast successfully\n");
        printf("   Response: %s\n", response.data);
        free(response.data);
        return KASE_OK;
    } else {
        printf("❌ Error broadcasting transaction\n");
        if (response.data) {
            printf("   Error: %s\n", response.data);
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
    blake2b_Update(hasher, outpoint->transaction_id, 32);
    uint8_t index_bytes[4];
    index_bytes[0] = outpoint->index & 0xFF;
    index_bytes[1] = (outpoint->index >> 8) & 0xFF;
    index_bytes[2] = (outpoint->index >> 16) & 0xFF;
    index_bytes[3] = (outpoint->index >> 24) & 0xFF;
    blake2b_Update(hasher, index_bytes, 4);
}

// Hash d'un script public key
static void hash_script_public_key(blake2b_state *hasher, const uint8_t *script, size_t len) {
    uint8_t len_bytes[8];
    write_u64_le(len_bytes, len);
    blake2b_Update(hasher, len_bytes, 8);
    blake2b_Update(hasher, script, len);
}

// Hash des previous outputs
static void previous_outputs_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_Init(&hasher, 32);
    
    for (size_t i = 0; i < tx->inputs_count; i++) {
        hash_outpoint(&hasher, &tx->inputs[i].previous_outpoint);
    }
    
    blake2b_Final(&hasher, hash, 32);
}

// Hash des sequences
static void sequences_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
    blake2b_state hasher;
    blake2b_Init(&hasher, 32);
    
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
    blake2b_Init(&hasher, 32);
    
    for (size_t i = 0; i < tx->inputs_count; i++) {
        blake2b_Update(&hasher, &tx->inputs[i].sig_op_count, 1);
    }
    
    blake2b_Final(&hasher, hash, 32);
}

// Hash des outputs
static void outputs_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
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

// Hash du payload
static void payload_hash(const kaspa_transaction_t *tx, uint8_t *hash) {
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

// Calcul COMPLET du SigHash Kaspa
int kaspa_calc_sighash(const kaspa_transaction_t *tx,
                      int input_index,
                      const kaspa_utxo_entry_t *utxo,
                      uint8_t *sighash) {
    blake2b_state hasher;
    if (blake2b_Init(&hasher, 32) != 0) return -1;
    
    // 1. Version (2 bytes LE)
    uint8_t version_bytes[2];
    write_u16_le(version_bytes, tx->version);
    blake2b_Update(&hasher, version_bytes, 2);
    
    // 2. Previous outputs hash (32 bytes)
    uint8_t prev_hash[32];
    previous_outputs_hash(tx, prev_hash);
    blake2b_Update(&hasher, prev_hash, 32);
    
    // 3. Sequences hash (32 bytes)
    uint8_t seq_hash[32];
    sequences_hash(tx, seq_hash);
    blake2b_Update(&hasher, seq_hash, 32);
    
    // 4. Sig op counts hash (32 bytes)
    uint8_t sigop_hash[32];
    sig_op_counts_hash(tx, sigop_hash);
    blake2b_Update(&hasher, sigop_hash, 32);
    
    // 5. Current input outpoint
    hash_outpoint(&hasher, &tx->inputs[input_index].previous_outpoint);
    
    // 6. Current input script public key
    hash_script_public_key(&hasher, utxo->script_public_key, utxo->script_public_key_len);
    
    // 7. Current input amount (8 bytes LE)
    uint8_t amount_bytes[8];
    write_u64_le(amount_bytes, utxo->amount);
    blake2b_Update(&hasher, amount_bytes, 8);
    
    // 8. Current input sequence (8 bytes LE)
    uint8_t seq_bytes[8];
    write_u64_le(seq_bytes, tx->inputs[input_index].sequence);
    blake2b_Update(&hasher, seq_bytes, 8);
    
    // 9. Current input sig_op_count (1 byte)
    blake2b_Update(&hasher, &tx->inputs[input_index].sig_op_count, 1);
    
    // 10. Outputs hash (32 bytes)
    uint8_t out_hash[32];
    outputs_hash(tx, out_hash);
    blake2b_Update(&hasher, out_hash, 32);
    
    // 11. Lock time (8 bytes LE)
    uint8_t lock_bytes[8];
    write_u64_le(lock_bytes, tx->lock_time);
    blake2b_Update(&hasher, lock_bytes, 8);
    
    // 12. Subnetwork ID (20 bytes)
    blake2b_Update(&hasher, tx->subnetwork_id, 20);
    
    // 13. Gas (8 bytes LE)
    uint8_t gas_bytes[8];
    write_u64_le(gas_bytes, tx->gas);
    blake2b_Update(&hasher, gas_bytes, 8);
    
    // 14. Payload hash (32 bytes)
    uint8_t pay_hash[32];
    payload_hash(tx, pay_hash);
    blake2b_Update(&hasher, pay_hash, 32);
    
    // 15. SigHash type (1 byte)
    uint8_t sighash_type = KASPA_SIG_HASH_ALL;
    blake2b_Update(&hasher, &sighash_type, 1);
    
    return blake2b_Final(&hasher, sighash, 32);
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
