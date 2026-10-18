//
// Created by sebas on 16/10/2026.
//

#ifndef CIBER_BLOCK_H
#define CIBER_BLOCK_H
#include <cstdint> // Para uint8_t y uint16_t como lo dice, c - standard - int
                   // int de bites especificos
#include <vector>


class Block {

public:

    //8 bytes de datos de txtToBinary y meterlos en un bloque de 64 bytes
    static uint64_t bytesToBlock(const std::vector<uint8_t>& datos, size_t inicio);

    //
    static void blockToBytes(uint64_t bloque, std::vector<uint8_t>& datos, size_t inicio);


};


#endif //CIBER_BLOCK_H
