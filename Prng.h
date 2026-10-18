//
// Generador pseudoaleatorio determinista de KDSPN-64: splitmix64 para sembrar
// y xoshiro256** para generar. De aqui salen todas las tablas de la clave.
//
// No usamos rand, std::mt19937 ni std::shuffle: su salida puede cambiar entre
// compiladores o versiones de la biblioteca, y entonces un texto cifrado en una
// maquina no se podria descifrar en otra. Estos dos algoritmos son publicos y
// estan definidos bit por bit, asi que dan lo mismo en cualquier compilador.
//
// OJO: xoshiro256** NO es un generador criptografico. Sirve para un cifrado de
// juguete, no para uno real.
//

#ifndef CIBER_PRNG_H
#define CIBER_PRNG_H

#include <cstdint>

class Prng {

public:
    /**
     * Siembra el generador con los 128 bits de la clave partidos en dos mitades.
     * @param hi primeros 8 bytes de la clave (Block::bytesToBlock(key, 0))
     * @param lo ultimos 8 bytes de la clave (Block::bytesToBlock(key, 8))
     */
    Prng(uint64_t hi, uint64_t lo);

    /**
     * Siguiente numero de 64 bits de xoshiro256**.
     * @return un valor pseudoaleatorio; avanza el estado interno
     */
    uint64_t next();

    /**
     * Un paso de splitmix64: avanza x y devuelve un valor "mezclado".
     * @param x estado de splitmix64; se modifica (por eso va por referencia)
     * @return el valor generado a partir del nuevo x
     */
    static uint64_t splitmix64(uint64_t& x);

private:
    // Estado de xoshiro256**: 4 palabras de 64 bits = 256 bits
    uint64_t s0, s1, s2, s3;

    // Rotacion propia; la de SPN se usa para el bloque y esta solo para el generador
    static uint64_t rotl(uint64_t x, unsigned n);
};


#endif //CIBER_PRNG_H
