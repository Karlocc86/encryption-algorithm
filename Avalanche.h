//
// Medicion del efecto avalancha: si cambia un solo bit de la entrada (o de la
// clave), deberia cambiar en promedio la mitad de los bits de la salida, o sea
// unos 32 de 64. Es la forma de comprobar con numeros que hay buena difusion.
//

#ifndef CIBER_AVALANCHE_H
#define CIBER_AVALANCHE_H

#include <array>
#include <cstdint>

#include "Config.h"

class Avalanche {

public:
    /**
     * Avalancha del texto plano: para cada bloque aleatorio y cada uno de sus 64
     * bits, voltea ese bit, cifra los dos bloques con la misma clave y cuenta
     * cuantos bits difieren los cifrados.
     * @param key clave (se expande una sola vez)
     * @param blocks numero de bloques aleatorios (la guia usa 1000)
     * @param seed semilla de std::mt19937_64 para que sea reproducible (la guia usa 12345)
     * @return promedio de bits distintos, de 0 a 64 (lo ideal es 32)
     */
    static double plaintext(const std::array<uint8_t, KEY_BYTES>& key, int blocks, uint64_t seed);

    /**
     * Avalancha de la clave: para cada bloque aleatorio y cada uno de los 128 bits
     * de la clave, voltea ese bit, vuelve a expandir la clave, cifra el mismo
     * bloque y cuenta cuantos bits difieren del cifrado con la clave original.
     * @param key clave original
     * @param blocks numero de bloques aleatorios (la guia usa 50)
     * @param seed semilla de std::mt19937_64 (la guia usa 12345)
     * @return promedio de bits distintos, de 0 a 64 (lo ideal es 32)
     */
    static double key(const std::array<uint8_t, KEY_BYTES>& key, int blocks, uint64_t seed);
};


#endif //CIBER_AVALANCHE_H
