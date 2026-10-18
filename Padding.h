//
// Relleno PKCS#7 con bloque de 8 bytes: el cifrado trabaja con bloques
// completos, asi que el mensaje se completa hasta un multiplo de 8.
//

#ifndef CIBER_PADDING_H
#define CIBER_PADDING_H

#include <cstdint>
#include <vector>

class Padding {

public:
    /**
     * Agrega n = 8 - (largo % 8) bytes, cada uno con el valor n (de 1 a 8).
     * Siempre agrega algo: un mensaje que ya mide un multiplo de 8 recibe un
     * bloque entero de 0x08, asi al quitarlo nunca hay duda de cuanto quitar.
     * @param datos mensaje original (puede estar vacio)
     * @return mensaje con relleno, de largo multiplo de 8
     */
    static std::vector<uint8_t> pad(const std::vector<uint8_t>& datos);

    /**
     * Quita el relleno PKCS#7 y valida que este bien formado.
     * @param datos mensaje con relleno
     * @return mensaje original
     * @throws std::invalid_argument si esta vacio, si no mide un multiplo de 8,
     *         si el ultimo byte no esta entre 1 y 8 o si los bytes de relleno no coinciden
     */
    static std::vector<uint8_t> unpad(const std::vector<uint8_t>& datos);
};


#endif //CIBER_PADDING_H
