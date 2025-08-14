//
//  kasia_random.c
//  XMKasiaMsg
//
//  Created by Daniel Arnaud on 27/06/2025.
//

#include "kase_random.h"

#include <stdint.h>
#include <time.h>

uint32_t random32(void) {
    return (uint32_t)(clock() ^ (uintptr_t)&random32);
}
