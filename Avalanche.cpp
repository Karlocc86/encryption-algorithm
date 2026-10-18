//
// Implementacion de la medicion de avalancha. std::mt19937_64 aqui SI esta bien:
// solo genera bloques de prueba, no forma parte del cifrado.
//

#include "Avalanche.h"

#include <bitset>
#include <random>
#include <vector>

#include "BlockCipher.h"
#include "KeySchedule.h"

// Cuantos bits son distintos entre a y b: el XOR deja un 1 justo donde difieren
static std::size_t bitsDistintos(uint64_t a, uint64_t b) {
    return std::bitset<64>(a ^ b).count();
}

double Avalanche::plaintext(const std::array<uint8_t, KEY_BYTES> &key, int blocks, uint64_t seed) {
    const Schedule s = KeySchedule::expand(key); // una sola vez para todos los bloques
    std::mt19937_64 gen(seed);

    std::size_t total = 0, pruebas = 0;
    for (int b = 0; b < blocks; b++) {
        const uint64_t p = gen();
        const uint64_t c = BlockCipher::encryptBlock(p, s);
        for (unsigned bit = 0; bit < 64; bit++) {
            const uint64_t p2 = p ^ (1ULL << bit); // el mismo bloque con un bit volteado
            total += bitsDistintos(c, BlockCipher::encryptBlock(p2, s));
            pruebas++;
        }
    }
    return pruebas == 0 ? 0.0 : static_cast<double>(total) / static_cast<double>(pruebas);
}

double Avalanche::key(const std::array<uint8_t, KEY_BYTES> &key, int blocks, uint64_t seed) {
    const Schedule original = KeySchedule::expand(key);

    // Las 128 claves con un bit volteado se expanden una vez y se reutilizan
    // para todos los bloques (expandir es lo caro)
    std::vector<Schedule> vecinas;
    for (unsigned bit = 0; bit < 8 * KEY_BYTES; bit++) {
        std::array<uint8_t, KEY_BYTES> k2 = key;
        k2[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
        vecinas.push_back(KeySchedule::expand(k2));
    }

    std::mt19937_64 gen(seed);
    std::size_t total = 0, pruebas = 0;
    for (int b = 0; b < blocks; b++) {
        const uint64_t p = gen();
        const uint64_t c = BlockCipher::encryptBlock(p, original);
        for (const Schedule &s2 : vecinas) {
            total += bitsDistintos(c, BlockCipher::encryptBlock(p, s2));
            pruebas++;
        }
    }
    return pruebas == 0 ? 0.0 : static_cast<double>(total) / static_cast<double>(pruebas);
}
