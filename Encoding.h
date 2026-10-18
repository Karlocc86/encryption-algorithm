//
// Conversiones de texto: bytes <-> hexadecimal, y la clave que escribe el
// usuario <-> los 16 bytes que usa el cifrado.
//

#ifndef CIBER_ENCODING_H
#define CIBER_ENCODING_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "Config.h"

class Encoding {

public:
    /**
     * Convierte bytes a hexadecimal en mayusculas, sin separadores.
     * @param datos bytes a convertir
     * @return dos digitos por byte, por ejemplo {0x0A, 0xFF} -> "0AFF"
     */
    static std::string toHex(const std::vector<uint8_t>& datos);

    /**
     * Convierte hexadecimal a bytes. Ignora espacios, tabuladores y saltos de
     * linea, y acepta mayusculas y minusculas.
     * @param hex texto hexadecimal
     * @return los bytes que codifica
     * @throws std::invalid_argument si hay un caracter que no es hexadecimal o
     *         si el numero de digitos es impar
     */
    static std::vector<uint8_t> fromHex(const std::string& hex);

    /**
     * Convierte la clave del usuario en los 16 bytes del cifrado:
     * - de 1 a 16 bytes de texto: esos bytes, rellenados con 0x00 hasta 16;
     * - exactamente 32 digitos hexadecimales: los 16 bytes que codifican.
     * No hay ambiguedad porque un texto mide a lo mucho 16 y una clave hex mide 32.
     * @param clave lo que escribio el usuario
     * @return los 16 bytes de la clave
     * @throws std::invalid_argument si esta vacia, si mide de 17 a 31, o si mide
     *         mas de 16 sin ser 32 digitos hexadecimales
     */
    static std::array<uint8_t, KEY_BYTES> parseKey(const std::string& clave);
};


#endif //CIBER_ENCODING_H
