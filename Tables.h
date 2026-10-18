//
// Utilidades de tablas: la S-box de PRESENT (solo para pruebas con vectores
// conocidos), la inversion de una permutacion y el inverso modular de un impar.
//

#ifndef CIBER_TABLES_H
#define CIBER_TABLES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

class Tables {

public:
    /// S-box de 4 bits del cifrado PRESENT. KDSPN-64 no la usa para cifrar (sus
    /// S-boxes salen de la clave); se conserva para probar con vectores verificados.
    static inline const std::array<uint8_t, 16> PRESENT_SBOX = {
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
    };

    /**
     * Invierte una permutacion: si table[x] = y, la inversa cumple inversa[y] = x.
     * Sirve igual para la S-box (N = 16) que para la permutacion de bits (N = 64).
     * @param table permutacion de los valores 0 a N-1
     * @return la tabla inversa
     * @throws std::invalid_argument si algun valor se repite o es mayor que N-1
     *         (entonces no es una permutacion y no tiene inversa)
     */
    template <std::size_t N>
    static std::array<uint8_t, N> invertTable(const std::array<uint8_t, N>& table) {
        std::array<uint8_t, N> inversa{};
        std::array<bool, N> visto{}; // {} deja todo en false

        for (std::size_t x = 0; x < N; x++) {
            const std::size_t y = table[x];
            if (y >= N) {
                throw std::invalid_argument("invertTable: el valor " + std::to_string(y)
                                            + " esta fuera del rango 0 a " + std::to_string(N - 1));
            }
            if (visto[y]) {
                throw std::invalid_argument("invertTable: el valor " + std::to_string(y)
                                            + " se repite, la tabla no es una permutacion");
            }
            visto[y] = true;
            inversa[y] = static_cast<uint8_t>(x); // la llave pasa a ser el valor y viceversa
        }
        return inversa;
    }

    /**
     * Inverso multiplicativo modulo 2^64: el numero inv tal que m * inv == 1 (mod 2^64).
     * Asi se deshace la multiplicacion de cada ronda.
     * @param m numero impar (los pares no tienen inverso modulo 2^64)
     * @return el inverso de m
     * @throws std::invalid_argument si m es par
     */
    static uint64_t modInverse(uint64_t m);
};


#endif //CIBER_TABLES_H
