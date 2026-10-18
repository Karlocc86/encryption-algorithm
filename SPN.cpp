//
// Created by sebas on 16/10/2026.
//

#include "SPN.h"

// La S-box fija de PRESENT y hacerInversa se fueron: ahora la S-box sale de la
// clave (KeySchedule), PRESENT_SBOX vive en Tables solo para pruebas, y la
// inversa la calcula Tables::invertTable (que ademas valida la tabla).

uint64_t SPN::aplicarTabla(uint64_t block, const std::array<uint8_t, 16> &tablita) {

    uint64_t resultado{}; //{} no mas lo aplique por fanci y para probar. Pero es lo mismo que resultado = 0;

    for (int i = 0 ; i < 16 ; i++) {

        //Extraemos lo del inicio al final por nibbles con una mascara [1111] y directamente le aplicamos su valor de
        //sustitucion de Sbox (el nibble extraido se pasa como idx de Sbox para conseguir su valor de sustitucion)
        uint8_t nibble= tablita[block >> (60 - 4 * i) & 0xF];


        resultado |= static_cast<uint64_t>(nibble) << (60 - 4 * i); // Se va construyendo el block inverso por asi decirlo

    }
    return resultado;
}

uint64_t SPN::subNibbles(uint64_t block, const std::array<uint8_t, 16> &table) {
    // Cada nibble se sustituye por separado, asi que el orden en que aplicarTabla
    // los recorre (del mas alto al mas bajo) no cambia el resultado
    return aplicarTabla(block, table);
}

uint64_t SPN::permuteBits(uint64_t block, const std::array<uint8_t, 64> &table) {

    uint64_t resultado = 0;

    for (unsigned i = 0; i < 64; i++) {
        // Sacamos el bit i: lo bajamos a la posicion 0 y lo aislamos con la mascara 1
        const uint64_t bit = (block >> i) & 1ULL;

        // Y lo pegamos en su nueva posicion. Como bit ya es uint64_t, el << puede
        // llegar hasta la posicion 63 sin que C++ lo promueva a un int de 32 bits
        resultado |= bit << table[i];
    }
    return resultado;
}
