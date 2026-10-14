//
// Created by sebas on 14/10/2026.
//

#ifndef CIBER_TXTTOBINARY_H
#define CIBER_TXTTOBINARY_H


#include <string>
#include <vector>
#include <cstdint>


class txtToBinary {

public:
    std::vector<uint8_t>leerArchivo(std::string& ruta);
    void escribirArchivo(std::string& ruta, std::vector<uint8_t>& datos);
};


#endif //CIBER_TXTTOBINARY_H
