//
// Derivacion de todas las piezas del cifrado a partir de la clave. Esto es lo
// que hace distinto a KDSPN-64: la clave no solo se mezcla con XOR, tambien
// decide la S-box, la permutacion de bits, las rotaciones y los multiplicadores.
// Dos claves distintas arman dos cifrados con piezas distintas.
//

#ifndef CIBER_KEYSCHEDULE_H
#define CIBER_KEYSCHEDULE_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "Config.h"

/// Todas las tablas que salen de una clave. Se calcula una sola vez por operacion
/// y se reutiliza para cada bloque (generarla hace reintentos y no es gratis).
struct Schedule {
    std::array<uint8_t, 16> sbox;        ///< S-box de 4 bits, sin puntos fijos
    std::array<uint8_t, 16> invSbox;     ///< su inversa, para descifrar
    std::array<uint8_t, 64> perm;        ///< perm[i] = posicion destino del bit i
    std::array<uint8_t, 64> invPerm;     ///< su inversa, para descifrar
    std::array<unsigned, ROUNDS> rot;    ///< rotacion de cada ronda, de 1 a 63
    std::array<uint64_t, ROUNDS> mul;    ///< multiplicador impar de cada ronda
    std::array<uint64_t, ROUNDS> mulInv; ///< inverso modulo 2^64 de cada multiplicador
    std::array<uint64_t, SUBKEYS> subkeys; ///< una subclave por ronda mas la del blanqueo final

    std::size_t sboxAttempts; ///< barajadas que necesito la S-box (informativo)
    std::size_t permAttempts; ///< barajadas que necesito la permutacion (informativo)
};

class KeySchedule {

public:
    /**
     * Deriva todas las tablas de la clave, en el orden exacto de la especificacion
     * (sbox, perm, rot, mul, subclaves). Cambiar el orden daria otro cifrado.
     * @param key los 16 bytes de la clave
     * @return la Schedule completa
     * @throws std::runtime_error si la S-box o la permutacion no se logran en
     *         MAX_TABLE_ATTEMPTS intentos (en la practica no pasa)
     */
    static Schedule expand(const std::array<uint8_t, KEY_BYTES>& key);

    /**
     * Revisa la condicion de los nibbles: los 4 bits de cada nibble deben ir a 4
     * nibbles distintos, para que la S-box de la ronda siguiente reciba bits de
     * varias partes del bloque y no de una sola.
     * @param perm permutacion de 64 posiciones
     * @return true si la cumple
     */
    static bool spreadsNibbles(const std::array<uint8_t, 64>& perm);
};


#endif //CIBER_KEYSCHEDULE_H
