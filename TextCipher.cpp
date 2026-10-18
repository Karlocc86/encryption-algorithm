//
// Implementacion de la capa de texto sobre Encoding, KeySchedule y Cbc.
//

#include "TextCipher.h"

#include <stdexcept>
#include <vector>

#include "Cbc.h"
#include "Config.h"
#include "Encoding.h"
#include "KeySchedule.h"

std::string TextCipher::encryptText(const std::string &plain, const std::string &key) {
    // El limite es de bytes, no de letras: "ó" ocupa 2 bytes en UTF-8
    if (plain.size() > MAX_TEXT_BYTES) {
        throw std::invalid_argument("el texto tiene " + std::to_string(plain.size())
                                    + " bytes; el maximo es " + std::to_string(MAX_TEXT_BYTES));
    }

    // La Schedule se calcula una sola vez y Cbc la reutiliza en cada bloque
    const Schedule schedule = KeySchedule::expand(Encoding::parseKey(key));
    const std::vector<uint8_t> bytes(plain.begin(), plain.end());
    return Encoding::toHex(Cbc::encrypt(bytes, schedule));
}

std::string TextCipher::decryptText(const std::string &hex, const std::string &key) {
    const Schedule schedule = KeySchedule::expand(Encoding::parseKey(key));
    const std::vector<uint8_t> datos = Encoding::fromHex(hex);

    if (datos.size() < 2 * BLOCK_BYTES || datos.size() % BLOCK_BYTES != 0) {
        throw std::invalid_argument("hexadecimal invalido: debe medir 8 + 8k bytes con k >= 1 (tiene "
                                    + std::to_string(datos.size()) + " bytes)");
    }

    std::vector<uint8_t> plano;
    try {
        plano = Cbc::decrypt(datos, schedule);
    } catch (const std::invalid_argument &) {
        // Un relleno invalido casi siempre significa clave equivocada
        throw std::invalid_argument("no se pudo descifrar: la clave es incorrecta o el cifrado esta danado");
    }
    return std::string(plano.begin(), plano.end());
}
