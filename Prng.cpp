//
// Implementacion de splitmix64 y xoshiro256** exactamente como en la especificacion.
// Todas las operaciones son sobre uint64_t: las sumas y multiplicaciones se
// desbordan modulo 2^64 a proposito (en enteros sin signo eso esta bien definido).
//

#include "Prng.h"

uint64_t Prng::splitmix64(uint64_t &x) {
    // 0x9E37... es la parte fraccionaria de la razon aurea por 2^64: hace que
    // estados consecutivos queden muy separados entre si
    x += 0x9E3779B97F4A7C15ULL;
    uint64_t z = x;

    // Dos rondas de "xorshift + multiplicar": cada bit de x termina influyendo
    // en casi todos los bits de z
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

Prng::Prng(uint64_t hi, uint64_t lo) {
    // splitmix64 convierte los 128 bits de la clave en los 256 bits de estado.
    // El orden (a, b, a, b) es parte de la especificacion: cambiarlo da otro cifrado.
    uint64_t a = hi;
    uint64_t b = lo;
    s0 = splitmix64(a);
    s1 = splitmix64(b);
    s2 = splitmix64(a);
    s3 = splitmix64(b);

    // xoshiro se queda atorado en ceros si todo su estado es 0; nunca debe pasar
    if (s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0) s0 = 1;
}

uint64_t Prng::rotl(uint64_t x, unsigned n) {
    // n siempre es 7 o 45 aqui, nunca 0 ni 64 (desplazar 64 bits es indefinido)
    return (x << n) | (x >> (64 - n));
}

uint64_t Prng::next() {
    // El "**" del nombre: multiplicar, rotar y multiplicar el resultado de s1
    const uint64_t resultado = rotl(s1 * 5, 7) * 9;

    // Avance lineal del estado (el orden importa: cada linea usa lo de la anterior)
    const uint64_t t = s1 << 17;
    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;
    s2 ^= t;
    s3 = rotl(s3, 45);

    return resultado;
}
