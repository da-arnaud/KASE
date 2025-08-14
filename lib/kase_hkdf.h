//
//  kasia_hkdf.h
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 29/06/2025.
//

#ifndef kase_hkdf_h
#define kase_hkdf_h

#include <stdint.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

#define KASE_HKDF_OK 0
#define KASE_HKDF_ERR -1

// Output length must be <= 255 * SHA256_DIGEST_LENGTH (8160 bytes)
int kase_hkdf_sha256(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm, size_t okm_len);

#ifdef __cplusplus
}
#endif
#endif /* kase_hkdf_h */
