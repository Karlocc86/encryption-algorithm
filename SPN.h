//
// Created by sebas on 16/10/2026.
//

#ifndef CIBER_SPN_H
#define CIBER_SPN_H
#include <cstdint>
#include <array>

//para que puedan entender S-Box o sustitution box
//https://www.geeksforgeeks.org/computer-networks/what-is-s-box-substitution/
//

class SPN {

private:
    static const std::array<uint8_t, 16> sbox;
    static const std::array<uint8_t, 16> invSbox;
    static std::arrat<uint8_t,16> hacerInversa(const std::array<uint8_t,16>& sbox);
    static uint64_t aplicarTabla(uint64_t block, const std::array<uint8_t, 16>& tablita);

public:
    // La fase de confusion
    static uint64_t subNibbles(uint64_t block);

    static uint64_t invSubNibbles(uint64_t block);

};


#endif //CIBER_SPN_H
