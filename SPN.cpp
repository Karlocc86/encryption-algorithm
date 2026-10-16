//
// Created by sebas on 16/10/2026.
//

#include "SPN.h"
#include <Block.h>

const std::array<uint8_t,16> SPN::sbox = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
   0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

std::array<uint8_t, 16> SPN::hacerInversa(const std::array<uint8_t, 16> &sbox) {

    std::array<uint8_t,16> inversa{};

    for ( int x = 0 ; x < 16 ; x++) {
        inversa[sbox[x]] = static_cast<uint8_t>(x);
    }

    return inversa;
}

const std::array<uint8_t,16> SPN::invSbox = hacerInversa(sbox);

uint64_t SPN::aplicarTabla(uint64_t block, const std::array<uint8_t, 16> &tablita) {

    uint64_t resultado{}; //{} no mas lo aplique por fanci y para probar. Pero es lo mismo que resultado = 0;

    for (int i = 0 ; i < 16 ; i++) {
        uint8_t nibble= tablita[block >> (60 - 4 * i) & 0xF];

        resultado |= static_cast<uint64_t>(nibble) << (60 - 4 * i);

    }
    return resultado;
}

uint64_t SPN::subNibbles(uint64_t block) {
    return aplicarTabla(block,sbox);
}

uint64_t SPN::invSubNibbles(uint64_t block) {
    return aplicarTabla(block,invSbox);
}
