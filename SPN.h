//
// Created by sebas on 16/10/2026.
//

#ifndef CIBER_SPN_H
#define CIBER_SPN_H
#include <cstdint>
#include <array>

//para que puedan entender S-Box o sustitution box
//https://www.geeksforgeeks.org/computer-networks/what-is-s-box-substitution/
//

class SPN {

private:
    static uint64_t aplicarTabla(uint64_t block, const std::array<uint8_t, 16>& tablita);

public:
    // La fase de confusion. La S-box ya no es fija: sale de la clave (KeySchedule)
    // y se pasa como parametro. Para deshacerla se pasa la tabla inversa.

    /**
     * Sustituye cada uno de los 16 nibbles del bloque usando la tabla.
     * @param block bloque de 64 bits
     * @param table S-box de 4 bits (o su inversa, para descifrar)
     * @return el bloque con cada nibble x cambiado por table[x]
     */
    static uint64_t subNibbles(uint64_t block, const std::array<uint8_t, 16>& table);

    // La fase de difusion

    /**
     * Mueve cada bit del bloque a otra posicion: el bit i pasa al bit table[i].
     * Asi los 4 bits que salen de una S-box llegan a S-boxes distintas en la
     * siguiente ronda.
     * @param block bloque de 64 bits
     * @param table permutacion de 0 a 63 (o su inversa, para descifrar)
     * @return el bloque con los bits reacomodados (conserva cuantos bits hay en 1)
     */
    static uint64_t permuteBits(uint64_t block, const std::array<uint8_t, 64>& table);

};


#endif //CIBER_SPN_H
