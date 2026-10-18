//
// Inverso modular por la iteracion de Newton (sin divisiones).
//

#include "Tables.h"

uint64_t Tables::modInverse(uint64_t m) {

    // Un par comparte el factor 2 con 2^64, asi que ningun numero multiplicado
    // por el puede dar 1: no tiene inverso
    if ((m & 1) == 0) throw std::invalid_argument("modInverse: el numero es par y no tiene inverso modulo 2^64");

    // Truco: para todo impar m, m * m == 1 (mod 8), o sea que m ya es su propio
    // inverso en los 3 bits mas bajos.
    uint64_t inv = m;

    // Cada vuelta de Newton (inv = inv * (2 - m * inv)) duplica los bits correctos:
    // 3 -> 6 -> 12 -> 24 -> 48 -> 96. Con 5 vueltas pasamos de 64 bits.
    // Todo es uint64_t, asi que el "mod 2^64" lo hace solo el desbordamiento.
    for (int i = 0; i < 5; i++) {
        inv *= 2 - m * inv;
    }
    return inv;
}
