//
// Created by sebas on 14/10/2026.
//

#include <iostream>
#include "txtToBinary.h"


void aplicarXOR(std::vector<uint8_t>& datos) {

    for (uint8_t& binary : datos) {
        binary ^= 0xA0; //XOR -> ^=
    }
    std::cout<<std::endl;
}

void showCharXOR(std::vector<uint8_t>& datos) {

    for (uint8_t& binary : datos) {
        std::cout<<binary<<" ";
    }
    std::cout<<std::endl;
}
void showBinXOR(std::vector<uint8_t>& datos) {

    for (uint8_t& binary : datos) {
        std::cout<<static_cast<int>(binary)<<" ";
    }
    std::cout<<std::endl;
}
int main() {

    std::vector<uint8_t> datos = txtToBinary::leerArchivo("text.txt");

    showCharXOR(datos);
    showBinXOR(datos);

    aplicarXOR(datos);

    showCharXOR(datos);
    showBinXOR(datos);
    aplicarXOR(datos);

    showCharXOR(datos);
    showBinXOR(datos);

    return 0;
}