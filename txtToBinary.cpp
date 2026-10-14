//
// Created by sebas on 14/10/2026.
//

#include "txtToBinary.h"
#include <fstream>
#include <stdexcept>
#include <iterator>

std::vector<uint8_t> txtToBinary::leerArchivo(const std::string &ruta) {
    std::ifstream f(ruta, std::ios::binary); //Input File Stream -> lee datos de un archivo
    //ios::binary siendo el modo de apertura, en este caso
    //lo abre como binario puro para evitar conversiones y los char
    //se traten como su binario directo (8 bits {0 - 255}).

    if (!f) throw std::runtime_error("Por x o y razon no se pudo abrir el archivo: " + ruta);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {}); // {} actua como un EOF (fin el archivo)
                                                                                      // istreambuf_iterator<char>
                                                                                      // i - input | streambuf - stream buffer
                                                                                      // <char> extrae chars en cada paso de ++it
                                                                                      // funciona con inicio (f) puntero apuntando
                                                                                      // al primer byte de [f] y fin ({});
}

