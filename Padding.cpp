//
// Implementacion del relleno PKCS#7.
//

#include "Padding.h"

#include <stdexcept>

#include "Config.h"

std::vector<uint8_t> Padding::pad(const std::vector<uint8_t> &datos) {
    // Ejemplo: 5 bytes -> faltan 3 -> se agregan 03 03 03
    //          8 bytes -> 8 - 0 = 8 -> se agregan ocho 08
    const std::size_t n = BLOCK_BYTES - (datos.size() % BLOCK_BYTES);

    std::vector<uint8_t> resultado = datos;
    resultado.insert(resultado.end(), n, static_cast<uint8_t>(n));
    return resultado;
}

std::vector<uint8_t> Padding::unpad(const std::vector<uint8_t> &datos) {
    if (datos.empty() || datos.size() % BLOCK_BYTES != 0) {
        throw std::invalid_argument("unpad: el largo no es un multiplo de 8, el relleno es invalido");
    }

    // El ultimo byte dice cuantos bytes de relleno hay
    const std::size_t n = datos.back();
    if (n < 1 || n > BLOCK_BYTES) {
        throw std::invalid_argument("unpad: el ultimo byte no esta entre 1 y 8, el relleno es invalido");
    }

    // Y todos esos bytes deben valer n
    for (std::size_t i = datos.size() - n; i < datos.size(); i++) {
        if (datos[i] != n) {
            throw std::invalid_argument("unpad: los bytes de relleno no coinciden");
        }
    }

    return std::vector<uint8_t>(datos.begin(), datos.end() - static_cast<std::ptrdiff_t>(n));
}
