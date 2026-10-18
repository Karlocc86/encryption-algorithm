//
// La ronda de KDSPN-64 y su inversa.
//

#include "BlockCipher.h"

#include "SPN.h"

uint64_t BlockCipher::encryptBlock(uint64_t block, const Schedule &schedule) {
    uint64_t s = block;

    for (std::size_t r = 0; r < ROUNDS; r++) {
        s ^= schedule.subkeys[r];                   // 1. confusion: mezcla con la clave
        s = SPN::subNibbles(s, schedule.sbox);      // 2. confusion: S-box en cada nibble
        s = SPN::permuteBits(s, schedule.perm);     // 3. difusion: reparte los bits
        s *= schedule.mul[r];                       // 4. confusion y difusion: cada bit
                                                    //    afecta a los de arriba (mod 2^64)
        s = SPN::rotl(s, schedule.rot[r]);          // 5. difusion: baja los bits altos,
                                                    //    que la multiplicacion no lleva abajo
    }

    // Blanqueo final: sin este XOR, la ultima rotacion se podria deshacer sin la clave
    return s ^ schedule.subkeys[ROUNDS];
}

uint64_t BlockCipher::decryptBlock(uint64_t block, const Schedule &schedule) {
    uint64_t s = block ^ schedule.subkeys[ROUNDS];

    // De la ultima ronda a la primera, cada paso deshace el de cifrado en orden
    // inverso. r es int (no size_t) para que el bucle pueda llegar a -1 y terminar.
    for (int r = static_cast<int>(ROUNDS) - 1; r >= 0; r--) {
        s = SPN::rotr(s, schedule.rot[r]);          // deshace 5
        s *= schedule.mulInv[r];                    // deshace 4: m * m^-1 == 1 (mod 2^64)
        s = SPN::permuteBits(s, schedule.invPerm);  // deshace 3
        s = SPN::subNibbles(s, schedule.invSbox);   // deshace 2
        s ^= schedule.subkeys[r];                   // deshace 1: (x ^ k) ^ k == x
    }
    return s;
}
