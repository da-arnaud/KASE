//
//  bip340.c
//  KASE-Tester
//
//  Created by Daniel Arnaud on 26/08/2025.
//

#include "bip340.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "sha2.h"
#include "rfc6979.h"
#include "bignum.h"
#include <string.h>
#include <stdio.h>

// Fallback : R = k * P via double-and-add (MSB -> LSB)
static void point_scalar_mul2(const ecdsa_curve *curve,
                             const curve_point *P,
                             const bignum256 *k,
                             curve_point *R) {
    // R = ∞
    point_set_infinity(R);
    // parcourir les 256 bits de k du plus fort au plus faible
    for (int i = 255; i >= 0; --i) {
        // R = 2R
        point_double(curve, R);
        // si le bit i de k est 1 : R = R + P
        if (bn_testbit(k, i)) {
            point_add(curve, P, R); // signature: point_add(curve, addend, accumulator)
        }
    }
}

static void point_scalar_mul1(const ecdsa_curve *curve,
                             const curve_point *P,
                             const bignum256 *k,
                             curve_point *R)
{
    // R = ∞ ; Q = P ; t = k (copie mutée)
    point_set_infinity(R);
    curve_point Q = *P;
    bignum256 t = *k;

    // Tant que t != 0 :
    while (!bn_is_zero(&t)) {
        // Si bit0(t) == 1 -> R = R + Q
        if (bn_is_odd(&t)) {
            point_add(curve, &Q, R);
        }
        // Q = 2Q
        point_double(curve, &Q);
        // t >>= 1
        bn_rshift(&t);
    }
}

static void point_scalar_mul(const ecdsa_curve *curve,
                             const curve_point *P,
                             const bignum256 *k,
                             curve_point *R)
{
    point_set_infinity(R);   // R <- ∞
    curve_point Q = *P;      // Q <- P
    bignum256 t = *k;        // t <- k (copie)

    while (!bn_is_zero(&t)) {
        if (bn_is_odd(&t)) {
            // R = R + Q
            point_add(curve, &Q, R);
        }
        // Q = Q + Q (doublage via point_add uniquement)
        curve_point tmp = Q;
        point_add(curve, &tmp, &Q);
        bn_rshift(&t);  // t >>= 1
    }
}


// Hash taggé BIP-340
void bip340_tagged_hash(const char *tag, const uint8_t *msg, size_t msglen, uint8_t *hash) {
    uint8_t tag_hash[32];
    sha256_Raw((const uint8_t*)tag, strlen(tag), tag_hash);
    
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, tag_hash, 32);  // SHA256(tag)
    sha256_Update(&ctx, tag_hash, 32);  // SHA256(tag) again
    sha256_Update(&ctx, msg, msglen);   // message
    sha256_Final(&ctx, hash);
}

// Version simplifiée
static int lift_x(const uint8_t *x32, curve_point *point) {
    bignum256 x, y2;
    
    // Load x coordinate
    bn_read_be(x32, &x);
    
    // Compute y² = x³ + 7 (mod p)
    bn_copy(&x, &y2);
    bn_multiply(&x, &y2, &secp256k1.prime);  // x²
    bn_multiply(&x, &y2, &secp256k1.prime);  // x³
    bn_addmod(&y2, &secp256k1.b, &secp256k1.prime); // x³ + 7
    
    // Compute square root
    bn_sqrt(&y2, &secp256k1.prime);  // y2 devient sqrt(y2)
    
    // Choose even y (BIP-340 requirement)
    if (bn_is_odd(&y2)) {
        bn_subtract(&secp256k1.prime, &y2, &y2);
    }
    
    // Set point
    bn_copy(&x, &point->x);
    bn_copy(&y2, &point->y);
    
    return 1;
}
// Generate x-only pubkey from private key
int bip340_pubkey_create(uint8_t *pubkey32, const uint8_t *seckey32) {
    curve_point point;
    bignum256 k;
    
    // Load private key
    bn_read_be(seckey32, &k);
    
    // Check if private key is valid
    if (bn_is_zero(&k) || !bn_is_less(&k, &secp256k1.order)) {
        return 0;
    }
    
    // Compute P = k*G
    scalar_multiply(&secp256k1, &k, &point);
    
    // If y is odd, negate private key
    if (bn_is_odd(&point.y)) {
        bn_subtract(&secp256k1.order, &k, &k);
        scalar_multiply(&secp256k1, &k, &point);
        
        // ← SAUVEGARDER la clé privée corrigée ! on retire ce check en mode DEBUG
                //bn_write_be(&k, seckey32);
    }
    
    // Output x coordinate only
    bn_write_be(&point.x, pubkey32);
    
    return 1;
}

// BIP-340 Schnorr Signature
int bip340_sign1(uint8_t *sig64, const uint8_t *msg32, const uint8_t *seckey32, const uint8_t *aux32) {
    bignum256 d, k, r, e, s;
    curve_point R, P;
    uint8_t hash_input[96]; // P || R || m
    uint8_t challenge[32];
    uint8_t nonce_hash[32];
    uint8_t pubkey[32];
    
    // Load private key
    bn_read_be(seckey32, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, &secp256k1.order)) {
        return 0;
    }
    
    // Generate public key P = d*G
    scalar_multiply(&secp256k1, &d, &P);
    
    // If P.y is odd, negate d
    if (bn_is_odd(&P.y)) {
        bn_subtract(&secp256k1.order, &d, &d);
        scalar_multiply(&secp256k1, &d, &P);
    }
    
    // Store P.x as pubkey
    bn_write_be(&P.x, pubkey);
    
    // Generate nonce: k = hash(d || aux || m) mod n
    memcpy(hash_input, seckey32, 32);
    if (aux32) {
        memcpy(hash_input + 32, aux32, 32);
    } else {
        memset(hash_input + 32, 0, 32);
    }
    memcpy(hash_input + 64, msg32, 32);
    
    bip340_tagged_hash("BIP0340/nonce", hash_input, 96, nonce_hash);
    bn_read_be(nonce_hash, &k);
    bn_mod(&k, &secp256k1.order);
    
    // If k = 0, fail
    if (bn_is_zero(&k)) {
        return 0;
    }
    
    // R = k*G
    scalar_multiply(&secp256k1, &k, &R);
    
    // If R.y is odd, negate k
    if (bn_is_odd(&R.y)) {
        bn_subtract(&secp256k1.order, &k, &k);
        scalar_multiply(&secp256k1, &k, &R);
    }
    
    // r = R.x
    bn_copy(&R.x, &r);
    
    // Challenge: e = hash(r || P || m) mod n
    bn_write_be(&r, hash_input);        // r (32 bytes)
    memcpy(hash_input + 32, pubkey, 32); // P.x (32 bytes)
    memcpy(hash_input + 64, msg32, 32);  // m (32 bytes)
    
    bip340_tagged_hash("BIP0340/challenge", hash_input, 96, challenge);
    bn_read_be(challenge, &e);
    bn_mod(&e, &secp256k1.order);
    
    // s = k + e*d mod n
    bignum256 ed;            // ed = e*d mod n
    bn_copy(&d, &ed);        // ed <- d
    bn_multiply(&e, &ed, &secp256k1.order);   // ed = ed * e (mod n)

    bignum256 s_bn;          // s = k + ed (mod n)
    bn_copy(&k, &s_bn);      // s_bn <- k
    bn_addmod(&s_bn, &ed, &secp256k1.order);

    bn_copy(&s_bn, &s);      // s <- s_bn
    //bn_multiply(&e, &d, &secp256k1.order);  // e*d
    //bn_addmod(&k, &e, &secp256k1.order);   // k + e*d
    //bn_copy(&e, &s);  // s = k + e*d
    
    // Output signature: r || s
    bn_write_be(&r, sig64);      // First 32 bytes: r
    bn_write_be(&s, sig64 + 32); // Last 32 bytes: s
    
    return 1;
}

// BIP-340 Schnorr Signature
int bip340_sign(uint8_t *sig64, const uint8_t *msg32,
                const uint8_t *seckey32, const uint8_t *aux32)
{
    const bignum256 *n = &secp256k1.order;

    // --- 0) Charger d et valider 1..n-1
    bignum256 d; bn_read_be(seckey32, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, n)) return 0;

    // --- 1) P = d·G ; forcer y(P) pair en ajustant d (BIP340)
    curve_point P; scalar_multiply(&secp256k1, &d, &P);
    if (bn_is_odd(&P.y)) {              // si y(P) impair -> d = n - d ; recalcule P
        bn_subtract(n, &d, &d);
        scalar_multiply(&secp256k1, &d, &P);
    }
    uint8_t px[32]; bn_write_be(&P.x, px);  // pk x-only (32B)

    // --- 2) Nonce conforme BIP-340
    // haux = H_tag("BIP0340/aux", aux32 || 32x00)
    uint8_t auxbuf[32] = {0};
    if (aux32) memcpy(auxbuf, aux32, 32);
    uint8_t haux[32];
    bip340_tagged_hash("BIP0340/aux", auxbuf, 32, haux);

    // t = d_be XOR haux
    uint8_t d_be[32]; bn_write_be(&d, d_be);
    uint8_t t[32];
    for (int i = 0; i < 32; i++) t[i] = d_be[i] ^ haux[i];

    // k0 = int(H_tag("BIP0340/nonce", t || pk32 || m)) mod n ; refuser si 0
    uint8_t nb[96];
    memcpy(nb,       t,   32);
    memcpy(nb + 32,  px,  32);
    memcpy(nb + 64,  msg32, 32);
    uint8_t khash[32];
    bip340_tagged_hash("BIP0340/nonce", nb, sizeof nb, khash);

    bignum256 k; bn_read_be(khash, &k); bn_mod(&k, n);
    if (bn_is_zero(&k)) return 0;

    // --- 3) R = k·G ; si y(R) impair -> k = n - k ; R = k·G ; r = x(R)
    curve_point R; scalar_multiply(&secp256k1, &k, &R);
    if (bn_is_odd(&R.y)) {
        bn_subtract(n, &k, &k);
        scalar_multiply(&secp256k1, &k, &R);
    }
    bignum256 r; bn_copy(&R.x, &r);

    // --- 4) e = int(H_tag("BIP0340/challenge", r||pk32||m)) mod n
    uint8_t ch[96];
    bn_write_be(&r, ch);                 // r (32)
    memcpy(ch + 32, px, 32);             // pk x-only (32)
    memcpy(ch + 64, msg32, 32);          // m (32)
    uint8_t eh[32];
    bip340_tagged_hash("BIP0340/challenge", ch, sizeof ch, eh);
    bignum256 e; bn_read_be(eh, &e); bn_mod(&e, n);

    // --- 5) s = (k + e·d) mod n   (sans écraser d/e/k)
    bignum256 ed; bn_copy(&d, &ed);                  // ed <- d
    bn_multiply(&e, &ed, n);                         // ed = ed * e (mod n)
    bignum256 s;  bn_copy(&k, &s);                   // s <- k
    bn_addmod(&s, &ed, n);                           // s = s + ed (mod n)
    //*** DEBUG ***
    curve_point R1, R2;
    scalar_multiply(&secp256k1, &s, &R1);      // sG
    scalar_multiply(&secp256k1, &e, &R2);      // eP
    point_subtract(&secp256k1, &R2, &R1);      // R1 = sG - eP
    if (point_is_infinity(&R1)) { printf("[sign] R' is infinity\n"); return 0; }
    uint8_t Rx[32]; bn_write_be(&R1.x, Rx);
    printf("[sign] Rx': "); for(int i=0;i<32;i++) printf("%02x", Rx[i]); printf("\n");
    
    // *** DEBUG ***

    // --- 6) sortie r||s (BE)
    bn_write_be(&r, sig64);
    bn_write_be(&s, sig64 + 32);
    
    uint8_t r_be[32], s_be[32], e_be[32];
    bn_write_be(&r, r_be); bn_write_be(&s, s_be); bn_write_be(&e, e_be);
    printf("[sign] r: "); for (int i=0;i<32;i++) printf("%02x", r_be[i]); printf("\n");
    printf("[sign] s: "); for (int i=0;i<32;i++) printf("%02x", s_be[i]); printf("\n");
    printf("[sign] e: "); for (int i=0;i<32;i++) printf("%02x", e_be[i]); printf("\n");
    
    return 1;
}


// --- Canonical lift_x_even for secp256k1: from x32 -> point (x, y_even)
// Uses: y^2 = x^3 + 7 (mod p); choose y with even parity.
static bool lift_x_even(const uint8_t x32[32], curve_point *P) {
    const bignum256 *p = &secp256k1.prime;

    // x <- x32 (BE) mod p
    bignum256 x; bn_read_be(x32, &x); bn_mod(&x, p); bn_normalize(&x);

    // y2 = x^3 + 7 (mod p)
    bignum256 y2 = x;                 // y2 = x
    bn_multiply(&x, &y2, p);          // y2 = x^2
    bn_multiply(&x, &y2, p);          // y2 = x^3
    bn_addi(&y2, 7);                  // y2 = x^3 + 7
    bn_mod(&y2, p); bn_normalize(&y2);

    // y = sqrt(y2) mod p
    bignum256 y = y2;
    bn_sqrt(&y, p);                   // Tonelli–Shanks in lib
    // Garde-fou : vérifier y^2 == y2 (mod p)
    bignum256 yy = y;
    bn_multiply(&y, &yy, p);
    bn_mod(&yy, p); bn_normalize(&yy);
    if (!bn_is_equal(&yy, &y2)) {
        return false;                 // pas une racine valable → x invalide
    }

    // BIP-340: imposer y pair
    bn_normalize(&y);
    if (bn_is_odd(&y)) {
        bn_subtract(p, &y, &y);       // y = p - y
        bn_normalize(&y);
    }

    P->x = x;
    P->y = y;
    return true;
}

// BIP-340 Schnorr Verification
bool bip340_verify1(const uint8_t *sig64, const uint8_t *msg32, const uint8_t *pubkey32) {
    bignum256 r, s, e;
    curve_point P, R1, R2;
    uint8_t hash_input[96];
    uint8_t challenge[32];
    
    // Parse signature: r || s
    bn_read_be(sig64, &r);
    bn_read_be(sig64 + 32, &s);
    
    // Check r and s are in range [0, p-1] and [0, n-1]
    if (!bn_is_less(&r, &secp256k1.prime) || !bn_is_less(&s, &secp256k1.order)) {
        return false;
    }
    
    // Lift x coordinate to get point P
    //if (!lift_x(pubkey32, &P)) {
    //    return false;
    //}
    
    if (!lift_x_even(pubkey32, &P)) return false;
    
    // BIP-340: P doit avoir y pair
    if (bn_is_odd(&P.y)) {
        bn_subtract(&secp256k1.prime, &P.y, &P.y);
    }
    
    
    // Challenge: e = hash(r || P || m) mod n
    bn_write_be(&r, hash_input);          // r (32 bytes)
    memcpy(hash_input + 32, pubkey32, 32); // P.x (32 bytes)
    memcpy(hash_input + 64, msg32, 32);   // m (32 bytes)
    
    bip340_tagged_hash("BIP0340/challenge", hash_input, 96, challenge);
    bn_read_be(challenge, &e);
    bn_mod(&e, &secp256k1.order);
    
#if defined(KASE_SIGDBG) && KASE_SIGDBG
{
    // Self-test: vérifier que notre mul scalaire générique marche comme la mul native sur G
    curve_point Q1, Q2;

    // Q1 = s * G (routine native qui multiplie le générateur)
    scalar_multiply(&secp256k1, &s, &Q1);

    // Q2 = s * G via notre routine "point_scalar_mul" en passant G comme point arbitraire
    point_scalar_mul(&secp256k1, &secp256k1.G, &s, &Q2);

    if (!bn_is_equal(&Q1.x, &Q2.x) || !bn_is_equal(&Q1.y, &Q2.y)) {
        fprintf(stderr, "[selftest] point_scalar_mul mismatch against scalar_multiply(G,s)\n");
        return false; // échoue explicitement: problème dans point_scalar_mul
    }
    
    curve_point A, B, C;
        point_scalar_mul(&secp256k1, &P, &e, &A);              // A = e*P
        bignum256 n_minus_e = secp256k1.order; bn_subtract(&secp256k1.order, &e, &n_minus_e);
        point_scalar_mul(&secp256k1, &P, &n_minus_e, &B);      // B = (n-e)*P
        C = A; point_add(&secp256k1, &B, &C);                  // C = A + B
        if (!point_is_infinity(&C)) {
            fprintf(stderr, "[selftest] eP + (n-e)P != ∞  -> scalar mul on P is wrong\n");
            return false;
        }
}
#endif
    
    // R1 = s*G
    scalar_multiply(&secp256k1, &s, &R1);
    
    // R2 = e*P
    //scalar_multiply(&secp256k1, &e, &R2);
    //point_multiply(&secp256k1, &P, &e, &R2);
    point_scalar_mul(&secp256k1, &P, &e, &R2);
    
    // *** DEBUG ***
    uint8_t r_be[32], s_be[32], e_be[32];
    bn_write_be(&r, r_be); bn_write_be(&s, s_be); bn_write_be(&e, e_be);
    printf("[verify] r: "); for(int i=0;i<32;i++) printf("%02x", r_be[i]); printf("\n");
    printf("[verify] s: "); for(int i=0;i<32;i++) printf("%02x", s_be[i]); printf("\n");
    printf("[verify] e: "); for(int i=0;i<32;i++) printf("%02x", e_be[i]); printf("\n");
    // *** FIN DEBUG ***
    
    // R = R1 - R2 = s*G - e*P
    //point_subtract(&secp256k1, &R2, &R1); // R1 = R1 - R2
    
    // R2neg = -R2  (x, p - y)
    curve_point R2neg = R2;
    bn_subtract(&secp256k1.prime, &R2neg.y, &R2neg.y);

    // R1 = R1 + R2neg = sG - eP
    bn_subtract(&secp256k1.prime, &R2neg.y, &R2neg.y);
    point_add(&secp256k1, &R2neg, &R1);
    
    uint8_t Ry_be[32], p_minus_Ry_be[32];
    bn_write_be(&R1.y, Ry_be);
    bignum256 p_minus_Ry = R1.y;                      // p - R1.y
    bn_subtract(&secp256k1.prime, &p_minus_Ry, &p_minus_Ry);
    bn_write_be(&p_minus_Ry, p_minus_Ry_be);

    printf("[verify] R1.y: ");         for (int i=0;i<32;i++) printf("%02x", Ry_be[i]); printf("\n");
    printf("[verify] p - R1.y: ");     for (int i=0;i<32;i++) printf("%02x", p_minus_Ry_be[i]); printf("\n");
    printf("[verify] y(R1) parity: %s\n", bn_is_odd(&R1.y) ? "odd" : "even");
    

    
    // *** DEBUG ***
    if (point_is_infinity(&R1)) {
        fprintf(stderr, "[verify] R is infinity\n");
        return false;
    }
    uint8_t Rx[32]; bn_write_be(&R1.x, Rx);
    printf("[verify] Rx: ");
    for(int i=0;i<32;i++) printf("%02x", Rx[i]); printf("\n");
    
    if (bn_is_odd(&R1.y)) {
        fprintf(stderr, "[verify] R.y is odd → fail\n");
        return false;
    }
    if (!bn_is_equal(&R1.x, &r)) {
        uint8_t Rx[32], r_bytes[32];
        bn_write_be(&R1.x, Rx); bn_write_be(&r, r_bytes);
        fprintf(stderr, "[verify] Rx != r\n  Rx: "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",Rx[i]);
        fprintf(stderr, "\n   r: "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",r_bytes[i]);
        fprintf(stderr, "\n");
        return false;
    }
    
    // *** FIN DEBUG ***
    
    return true;
}

bool bip340_verify(const uint8_t *sig64, const uint8_t *msg32, const uint8_t *pubkey32) {
    bignum256 r, s, e;
    curve_point P, R, sG, eP, sum;
    uint8_t hash_input[96], challenge[32];

    // 0) parse r,s
    bn_read_be(sig64,      &r);
    bn_read_be(sig64 + 32, &s);

    // bornes: r < p, s < n
    if (!bn_is_less(&r, &secp256k1.prime) || !bn_is_less(&s, &secp256k1.order)) {
        return false;
    }

    // 1) P = lift_x_even(pubkey32)
    if (!lift_x_even(pubkey32, &P)) return false;
    
    uint8_t Px[32]; bn_write_be(&P.x, Px);
    if (memcmp(Px, pubkey32, 32) != 0) {
        fprintf(stderr, "[verify] P.x != pubkey32 (lift mismatch)\n");
        return false;
    }
    

    // 2) e = H_tag("BIP0340/challenge", r||pk||m) mod n
    bn_write_be(&r, hash_input);
    memcpy(hash_input + 32, pubkey32, 32);
    memcpy(hash_input + 64, msg32, 32);
    bip340_tagged_hash("BIP0340/challenge", hash_input, 96, challenge);
    bn_read_be(challenge, &e); bn_mod(&e, &secp256k1.order);

    // 3) R = lift_x_even(r)  (BIP-340: R.y doit être pair)
    uint8_t r_be[32]; bn_write_be(&r, r_be);
    if (!lift_x_even(r_be, &R)) return false;

    // 4) sG, eP
    scalar_multiply(&secp256k1, &s, &sG);      // s * G
    point_scalar_mul(&secp256k1, &P, &e, &eP); // e * P
    
    bignum256 n_minus_e = secp256k1.order; bn_subtract(&secp256k1.order, &e, &n_minus_e);
    curve_point t = P, A = eP, B;
    point_scalar_mul(&secp256k1, &P, &n_minus_e, &B);
    point_add(&secp256k1, &B, &A);
    if (!point_is_infinity(&A)) {
        fprintf(stderr, "[verify] group law failed: eP + (n-e)P != ∞\n");
        return false;
    }

    // 5) sum = R + eP
    sum = R;
    point_add(&secp256k1, &eP, &sum);

    // 6) Comparer points : sG == R + eP  (égalité x et y)
    // (normaliser pour éviter des restes non réduits)
    bn_mod(&sG.x, &secp256k1.prime); bn_normalize(&sG.x);
    bn_mod(&sG.y, &secp256k1.prime); bn_normalize(&sG.y);
    bn_mod(&sum.x, &secp256k1.prime); bn_normalize(&sum.x);
    bn_mod(&sum.y, &secp256k1.prime); bn_normalize(&sum.y);

    if (!bn_is_equal(&sG.x, &sum.x) || !bn_is_equal(&sG.y, &sum.y)) {
        // Logs utiles si besoin
        uint8_t sGx[32], sGy[32], Sx[32], Sy[32];
        bn_write_be(&sG.x, sGx); bn_write_be(&sG.y, sGy);
        bn_write_be(&sum.x, Sx); bn_write_be(&sum.y, Sy);
        fprintf(stderr, "[verify] sG != R + eP\n");
        fprintf(stderr, "  sG.x: "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",sGx[i]); fprintf(stderr,"\n");
        fprintf(stderr, "  sG.y: "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",sGy[i]); fprintf(stderr,"\n");
        fprintf(stderr, "  S.x : "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",Sx[i]);  fprintf(stderr,"\n");
        fprintf(stderr, "  S.y : "); for(int i=0;i<32;i++) fprintf(stderr,"%02x",Sy[i]);  fprintf(stderr,"\n");
        return false;
    }
    
    

    return true;
}
