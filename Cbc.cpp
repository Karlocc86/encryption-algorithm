//
// Implementacion del modo CBC sobre BlockCipher, usando Block para pasar de
// bytes a bloques de 64 bits y de regreso.
//

#include "Cbc.h"

#include <random>
#include <stdexcept>

#include "Block.h"
#include "BlockCipher.h"
#include "Padding.h"

std::vector<uint8_t> Cbc::encrypt(const std::vector<uint8_t> &plain, const Schedule &schedule,
                                  const std::array<uint8_t, BLOCK_BYTES> &iv) {

    const std::vector<uint8_t> conRelleno = Padding::pad(plain);

    // La salida empieza con el IV: el que descifra lo necesita y no es secreto
    std::vector<uint8_t> salida(iv.begin(), iv.end());
    salida.resize(BLOCK_BYTES + conRelleno.size());

    // "anterior" es C[i-1]; para el primer bloque es el IV
    uint64_t anterior = Block::bytesToBlock(salida, 0);

    for (std::size_t i = 0; i < conRelleno.size(); i += BLOCK_BYTES) {
        const uint64_t p = Block::bytesToBlock(conRelleno, i);

        // El XOR con el cifrado anterior es lo que encadena los bloques: dos
        // bloques iguales en el mensaje entran distintos al cifrado
        const uint64_t c = BlockCipher::encryptBlock(p ^ anterior, schedule);

        Block::blockToBytes(c, salida, BLOCK_BYTES + i);
        anterior = c;
    }
    return salida;
}

std::vector<uint8_t> Cbc::encrypt(const std::vector<uint8_t> &plain, const Schedule &schedule) {
    // std::random_device pide numeros al sistema operativo (no a una semilla fija)
    std::random_device rd;
    std::array<uint8_t, BLOCK_BYTES> iv{};
    for (auto &b : iv) b = static_cast<uint8_t>(rd() & 0xFF);
    return encrypt(plain, schedule, iv);
}

std::vector<uint8_t> Cbc::decrypt(const std::vector<uint8_t> &ivAndCipher, const Schedule &schedule) {

    // Minimo el IV y un bloque (el relleno garantiza al menos uno)
    if (ivAndCipher.size() < 2 * BLOCK_BYTES || ivAndCipher.size() % BLOCK_BYTES != 0) {
        throw std::invalid_argument("Cbc::decrypt: el cifrado debe medir 8 + 8k bytes con k >= 1");
    }

    std::vector<uint8_t> conRelleno(ivAndCipher.size() - BLOCK_BYTES);
    uint64_t anterior = Block::bytesToBlock(ivAndCipher, 0); // el IV

    for (std::size_t i = BLOCK_BYTES; i < ivAndCipher.size(); i += BLOCK_BYTES) {
        const uint64_t c = Block::bytesToBlock(ivAndCipher, i);
        const uint64_t p = BlockCipher::decryptBlock(c, schedule) ^ anterior;
        Block::blockToBytes(p, conRelleno, i - BLOCK_BYTES);
        anterior = c;
    }

    // Con una clave equivocada lo normal es que el relleno salga invalido y
    // unpad lance excepcion (aunque a veces sale valido por azar)
    return Padding::unpad(conRelleno);
}
