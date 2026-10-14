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
    //static para no tener que instanciar un objeto para usarlas
    static std::vector<uint8_t>leerArchivo(const std::string& ruta);
    static void escribirArchivo(const std::string& ruta,const std::vector<uint8_t>& datos);
};


#endif //CIBER_TXTTOBINARY_H
