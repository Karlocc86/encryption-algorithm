//
// Cifrado y descifrado de un solo bloque de 64 bits con KDSPN-64.
// Es un cifrado de juguete para aprender: no es seguro.
//

#ifndef CIBER_BLOCKCIPHER_H
#define CIBER_BLOCKCIPHER_H

#include <cstdint>

#include "KeySchedule.h"

class BlockCipher {

public:
    /**
     * Cifra un bloque: 10 rondas de (XOR con subclave, S-box, permutacion,
     * multiplicacion por un impar, rotacion) y un XOR final con la ultima subclave.
     * @param block bloque en claro
     * @param schedule tablas derivadas de la clave (KeySchedule::expand)
     * @return bloque cifrado
     */
    static uint64_t encryptBlock(uint64_t block, const Schedule& schedule);

    /**
     * Descifra un bloque: aplica las operaciones inversas en orden contrario,
     * de la ultima ronda a la primera.
     * @param block bloque cifrado
     * @param schedule las mismas tablas con las que se cifro
     * @return bloque en claro
     */
    static uint64_t decryptBlock(uint64_t block, const Schedule& schedule);
};


#endif //CIBER_BLOCKCIPHER_H
