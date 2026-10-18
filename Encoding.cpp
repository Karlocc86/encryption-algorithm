//
// Implementacion de las conversiones de texto.
//

#include "Encoding.h"

#include <stdexcept>

// Valor de un digito hexadecimal, o -1 si el caracter no es hexadecimal
static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

std::string Encoding::toHex(const std::vector<uint8_t> &datos) {
    const char *digitos = "0123456789ABCDEF";
    std::string hex;
    hex.reserve(datos.size() * 2);
    for (uint8_t b : datos) {
        hex += digitos[b >> 4];   // nibble alto
        hex += digitos[b & 0xF];  // nibble bajo
    }
    return hex;
}

std::vector<uint8_t> Encoding::fromHex(const std::string &hex) {
    std::vector<uint8_t> datos;
    int alto = -1; // nibble alto pendiente, o -1 si no hay

    for (char c : hex) {
        // Espacios y saltos de linea se ignoran: asi se puede pegar un cifrado partido
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;

        const int v = hexValue(c);
        if (v < 0) {
            throw std::invalid_argument(std::string("hexadecimal invalido: el caracter '") + c
                                        + "' no es un digito hexadecimal");
        }
        if (alto < 0) {
            alto = v;
        } else {
            datos.push_back(static_cast<uint8_t>((alto << 4) | v));
            alto = -1;
        }
    }
    if (alto >= 0) throw std::invalid_argument("hexadecimal invalido: el numero de digitos es impar");
    return datos;
}

std::array<uint8_t, KEY_BYTES> Encoding::parseKey(const std::string &clave) {
    std::array<uint8_t, KEY_BYTES> key{}; // {} = todo en 0x00, que sirve de relleno

    if (clave.empty()) {
        throw std::invalid_argument("clave invalida: no puede estar vacia");
    }

    // Texto de hasta 16 bytes (una letra con acento como la o con tilde ocupa 2)
    if (clave.size() <= KEY_BYTES) {
        for (std::size_t i = 0; i < clave.size(); i++) key[i] = static_cast<uint8_t>(clave[i]);
        return key;
    }

    // Clave hexadecimal de exactamente 32 digitos
    if (clave.size() == 2 * KEY_BYTES) {
        bool todoHex = true;
        for (char c : clave) todoHex = todoHex && hexValue(c) >= 0;
        if (todoHex) {
            const std::vector<uint8_t> bytes = fromHex(clave);
            for (std::size_t i = 0; i < KEY_BYTES; i++) key[i] = bytes[i];
            return key;
        }
    }

    throw std::invalid_argument("clave invalida: debe tener de 1 a 16 caracteres o exactamente "
                                "32 digitos hexadecimales (tiene " + std::to_string(clave.size()) + ")");
}
