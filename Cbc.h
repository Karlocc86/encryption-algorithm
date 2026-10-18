//
// Modo CBC (Cipher Block Chaining): encadena los bloques para que dos bloques
// iguales del mensaje no den dos bloques cifrados iguales (que es el problema
// de cifrar cada bloque por separado, el modo ECB).
//
// CBC no autentica: no detecta si alguien modifico el texto cifrado.
//

#ifndef CIBER_CBC_H
#define CIBER_CBC_H

#include <array>
#include <cstdint>
#include <vector>

#include "Config.h"
#include "KeySchedule.h"

class Cbc {

public:
    /**
     * Cifra con un IV dado: C[0] = IV y C[i] = E(P[i] XOR C[i-1]). Agrega el
     * relleno PKCS#7 antes de cifrar.
     * @param plain mensaje en claro (cualquier largo, incluso vacio)
     * @param schedule tablas de la clave, calculadas una sola vez afuera
     * @param iv vector de inicializacion de 8 bytes
     * @return IV (8 bytes) seguido de los bloques cifrados
     */
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain, const Schedule& schedule,
                                        const std::array<uint8_t, BLOCK_BYTES>& iv);

    /**
     * Igual que la anterior, pero con un IV aleatorio de std::random_device.
     * Asi cifrar dos veces el mismo texto da dos resultados distintos.
     * @param plain mensaje en claro
     * @param schedule tablas de la clave
     * @return IV (8 bytes) seguido de los bloques cifrados
     */
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain, const Schedule& schedule);

    /**
     * Descifra: P[i] = D(C[i]) XOR C[i-1] y quita el relleno.
     * @param ivAndCipher IV seguido de los bloques cifrados
     * @param schedule las mismas tablas con las que se cifro
     * @return mensaje en claro
     * @throws std::invalid_argument si el largo no es 8 + 8k con k >= 1, o si el
     *         relleno es invalido (lo normal con una clave equivocada)
     */
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ivAndCipher, const Schedule& schedule);
};


#endif //CIBER_CBC_H
