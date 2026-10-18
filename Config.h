//
// Constantes de KDSPN-64. Viven en un solo lugar para que ningun modulo
// repita "numeros magicos" (si cambia ROUNDS, cambia en todo el cifrado).
//

#ifndef CIBER_CONFIG_H
#define CIBER_CONFIG_H

#include <cstddef>

// inline constexpr (C++17): el valor se conoce en compilacion y, al ser inline,
// todos los .cpp que incluyan este header comparten la misma constante sin
// romper la regla de una sola definicion.

/// Tamano del bloque en bytes (64 bits).
inline constexpr std::size_t BLOCK_BYTES = 8;

/// Tamano de la clave en bytes (128 bits).
inline constexpr std::size_t KEY_BYTES = 16;

/// Numero de rondas del cifrado.
inline constexpr std::size_t ROUNDS = 10;

/// Una subclave por ronda mas la del XOR final (blanqueo).
inline constexpr std::size_t SUBKEYS = ROUNDS + 1;

/// Limite de bytes de la capa de texto y de la GUI (el PDF pide 100 caracteres).
inline constexpr std::size_t MAX_TEXT_BYTES = 100;

/// Reintentos maximos al generar la S-box y la permutacion antes de rendirse.
inline constexpr std::size_t MAX_TABLE_ATTEMPTS = 1000000;

#endif //CIBER_CONFIG_H
