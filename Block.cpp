//
// Created by sebas on 16/10/2026.
//

#include "Block.h"
#include <stdexcept>
#include <cstdint>

uint64_t Block::bytesToBlock(const std::vector<uint8_t> &datos, size_t inicio) {

    if (inicio > datos.size() || datos.size() - inicio < 8) {
        throw std::out_of_range("bytesToBlock: no hay 8 bytes desde el inicio para construir el bloque");
    }

    uint64_t bloque = 0;

    //For que mueve a la izquierda lo bytes en un bloque de 8 bytes,
    //
    for (size_t i = 0; i<8 ; i++) {

        //Es necesario el static_cast a int de 64 bits, porque por defecto c++ aplica promocion de enteros
        // siendo que datos[i] trae enteros de 8 bits c++ lo promovera a uno de 32, y ya que estamos trabajando
        // con 56 - 8 * 1 llegando a mover 56 posiciones o bites, nos dara un desbordamiento mover 56 posiciones a
        // un entero de 32, por eso lo transformamos a uno de 64 y poder almacenar 8 bytes en los 64 bits
        bloque |= static_cast<uint64_t>(datos[inicio + i]) << (56 - 8 * 1);

    }

    return bloque;

}


void Block::blockToBytes(uint64_t bloque, std::vector<int8_t> &datos, size_t inicio) {

    if (inicio > datos.size() || datos.size() - inicio < 8) throw
    std::out_of_range("blocToBytes: no hay espacio para 8 bytes");

    for (size_t i  = 0; i < 8 ; i++) {

        //& operacion and en bits. & 0XFF mascara de [1111 1111]
        //Ejemplo
        //bloque de 32: 11010101 10101010 010101010 10001100
        //0xFF        : 00000000 00000000 000000000 11111111
        //            _______________________________________
        //resultado   : 00000000 00000000 000000000 10001100 <- bloque de 8 bits a guardar


        //>> es solo para mover que tantos bits a la derecha (>> posiciones_a_mover)
        //En este caso vamos por los finales al inicio, vamos moviendo 56, 48, ... , 0
        //la mascara nos ayuda a sacar el primer byte
        datos[inicio + i] = static_cast<uint8_t>((bloque >> (56 - 8 * i)) & 0xFF);
    }

}
