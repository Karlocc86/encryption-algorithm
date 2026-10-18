//
// Implementacion de la derivacion de tablas. Todas las llamadas a next() van en
// el orden de la especificacion: sbox -> perm -> rot -> mul -> subclaves.
//

#include "KeySchedule.h"

#include <stdexcept>
#include <utility>
#include <vector>

#include "Block.h"
#include "Prng.h"
#include "Tables.h"

// Baraja de Fisher-Yates "de atras hacia adelante": para cada posicion i, desde
// la ultima hasta la 1, se intercambia con una posicion j al azar entre 0 e i.
// Asi todas las permutaciones son posibles. El % sobre un uint64_t tiene un sesgo
// minusculo (64 bits contra a lo mucho 64 opciones), despreciable aqui.
template <std::size_t N>
static std::array<uint8_t, N> shuffledIdentity(Prng& gen) {
    std::array<uint8_t, N> t{};
    for (std::size_t i = 0; i < N; i++) t[i] = static_cast<uint8_t>(i);

    // i es size_t (no uint8_t) para no caer en contadores que se desbordan
    for (std::size_t i = N - 1; i >= 1; i--) {
        const std::size_t j = static_cast<std::size_t>(gen.next() % (i + 1));
        std::swap(t[i], t[j]);
    }
    return t;
}

// Un punto fijo (sbox[x] == x) dejaria pasar ese nibble sin cambio; se descartan
static bool hasFixedPoint(const std::array<uint8_t, 16>& sbox) {
    for (std::size_t x = 0; x < 16; x++) {
        if (sbox[x] == x) return true;
    }
    return false;
}

bool KeySchedule::spreadsNibbles(const std::array<uint8_t, 64> &perm) {
    for (std::size_t n = 0; n < 16; n++) {
        // Nibble destino de cada uno de los 4 bits del nibble n (posicion / 4)
        bool usado[16] = {};
        for (std::size_t k = 0; k < 4; k++) {
            const std::size_t destino = perm[4 * n + k] / 4;
            if (usado[destino]) return false; // dos bits caen en el mismo nibble
            usado[destino] = true;
        }
    }
    return true;
}

Schedule KeySchedule::expand(const std::array<uint8_t, KEY_BYTES> &key) {

    // Las dos mitades de la clave, con el primer byte en los bits altos (como Block)
    const std::vector<uint8_t> bytes(key.begin(), key.end());
    Prng gen(Block::bytesToBlock(bytes, 0), Block::bytesToBlock(bytes, 8));

    Schedule s{};

    // 1. S-box sin puntos fijos
    s.sboxAttempts = 0;
    do {
        if (++s.sboxAttempts > MAX_TABLE_ATTEMPTS) {
            throw std::runtime_error("KeySchedule: no se encontro una S-box sin puntos fijos");
        }
        s.sbox = shuffledIdentity<16>(gen);
    } while (hasFixedPoint(s.sbox));
    s.invSbox = Tables::invertTable(s.sbox);

    // 2. Permutacion de bits que reparte cada nibble en 4 nibbles distintos
    s.permAttempts = 0;
    do {
        if (++s.permAttempts > MAX_TABLE_ATTEMPTS) {
            throw std::runtime_error("KeySchedule: no se encontro una permutacion que cumpla la condicion de los nibbles");
        }
        s.perm = shuffledIdentity<64>(gen);
    } while (!spreadsNibbles(s.perm));
    s.invPerm = Tables::invertTable(s.perm);

    // 3. Rotaciones de 1 a 63 (nunca 0 ni 64, que no moverian nada o serian indefinidas)
    for (std::size_t r = 0; r < ROUNDS; r++) {
        s.rot[r] = 1 + static_cast<unsigned>(gen.next() % 63);
    }

    // 4. Multiplicadores: el "| 1" fuerza el bit 0 a 1, o sea, un numero impar,
    //    porque solo los impares tienen inverso modulo 2^64
    for (std::size_t r = 0; r < ROUNDS; r++) {
        s.mul[r] = gen.next() | 1ULL;
        s.mulInv[r] = Tables::modInverse(s.mul[r]);
    }

    // 5. Subclaves de 64 bits
    for (std::size_t r = 0; r < SUBKEYS; r++) {
        s.subkeys[r] = gen.next();
    }

    return s;
}
