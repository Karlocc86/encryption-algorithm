//
// Created by sebas on 14/10/2026.
//

#include <iostream>
#include "txtToBinary.h"

int main() {

    std::vector<uint8_t> archivoBinario = txtToBinary::leerArchivo("text.txt");
    for (uint8_t binary : archivoBinario) {
        std::cout<<static_cast<int>(binary)<<" ";
    }
    return 0;
}