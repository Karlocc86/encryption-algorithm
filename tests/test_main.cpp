//
// Pruebas de KDSPN-64: marco minimo sin dependencias externas.
// Se ejecuta con ciber_tests (o con ctest) e imprime "N checks, M fallos".
//

#include <array>
#include <bitset>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "Block.h"
#include "Config.h"
#include "Prng.h"
#include "SPN.h"
#include "Tables.h"
#include "txtToBinary.h"

namespace fs = std::filesystem;

static int g_total = 0, g_fail = 0;

// Cuenta una comprobacion; si falla, imprime archivo, linea y la condicion
#define CHECK(cond) do { ++g_total; if (!(cond)) { ++g_fail; \
    std::cerr << __FILE__ << ":" << __LINE__ << " CHECK falló: " #cond "\n"; } } while (0)

// Comprueba que evaluar expr lance una excepcion del tipo indicado (o de uno derivado)
#define CHECK_THROWS(expr, ExType) do { ++g_total; bool lanzo_ = false; \
    try { (void)(expr); } catch (const ExType&) { lanzo_ = true; } catch (...) {} \
    if (!lanzo_) { ++g_fail; std::cerr << __FILE__ << ":" << __LINE__ \
    << " CHECK_THROWS falló: " #expr " no lanzó " #ExType "\n"; } } while (0)

// Ruta de un archivo temporal fuera del repositorio, para no ensuciarlo
static std::string tempPath(const std::string& nombre) {
    return (fs::temp_directory_path() / ("ciber_test_" + nombre)).string();
}

static void testConfig() {
    // Relaciones que el resto del cifrado da por hechas
    CHECK(BLOCK_BYTES * 8 == 64);
    CHECK(KEY_BYTES == 2 * BLOCK_BYTES);
    CHECK(SUBKEYS == ROUNDS + 1);
}

static void testBlock() {
    const std::vector<uint8_t> ocho = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    CHECK(Block::bytesToBlock(ocho, 0) == 0x0102030405060708ULL);

    // Con inicio > 0 se leen los 8 bytes a partir de esa posicion
    const std::vector<uint8_t> conPrefijo = {0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    CHECK(Block::bytesToBlock(conPrefijo, 2) == 0x0102030405060708ULL);

    // blockToBytes deja el primer byte con los bits mas altos, igual que bytesToBlock
    std::vector<uint8_t> salida(8, 0);
    Block::blockToBytes(0x0102030405060708ULL, salida, 0);
    CHECK(salida == ocho);

    // Ida y vuelta sin tocar los bytes que quedan fuera de las 8 posiciones
    const uint64_t valores[] = {0x0ULL, 0x1ULL, 0x8000000000000000ULL,
                                0xFFFFFFFFFFFFFFFFULL, 0x0123456789ABCDEFULL};
    for (uint64_t v : valores) {
        std::vector<uint8_t> buf(10, 0x5A);
        Block::blockToBytes(v, buf, 1);
        CHECK(Block::bytesToBlock(buf, 1) == v);
        CHECK(buf[0] == 0x5A && buf[9] == 0x5A);
    }

    // Sin 8 bytes disponibles desde el inicio: std::out_of_range
    const std::vector<uint8_t> siete(7, 0);
    CHECK_THROWS(Block::bytesToBlock(siete, 0), std::out_of_range);
    CHECK_THROWS(Block::bytesToBlock(ocho, 1), std::out_of_range);
    CHECK_THROWS(Block::bytesToBlock(ocho, 9), std::out_of_range);
    std::vector<uint8_t> corto(7, 0);
    CHECK_THROWS(Block::blockToBytes(1, corto, 0), std::out_of_range);
}

static void testTxtToBinary() {
    // "m de megalodón" en UTF-8: la ó ocupa dos bytes (195 179)
    const std::vector<uint8_t> megalodon = {109, 32, 100, 101, 32, 109, 101, 103,
                                            97, 108, 111, 100, 195, 179, 110};
    const std::string rutaTexto = tempPath("megalodon.txt");
    txtToBinary::escribirArchivo(rutaTexto, megalodon);
    const std::vector<uint8_t> leido = txtToBinary::leerArchivo(rutaTexto);
    CHECK(leido.size() == 15);
    CHECK(leido == megalodon);

    // En modo binario \r\n (13 10) se conserva tal cual, igual que 0 y 255
    const std::vector<uint8_t> saltos = {'a', 13, 10, 'b', 10, 13, 0, 255};
    const std::string rutaSaltos = tempPath("saltos.bin");
    txtToBinary::escribirArchivo(rutaSaltos, saltos);
    CHECK(txtToBinary::leerArchivo(rutaSaltos) == saltos);

    // Un archivo vacio se lee como un vector vacio
    const std::string rutaVacio = tempPath("vacio.bin");
    txtToBinary::escribirArchivo(rutaVacio, {});
    CHECK(txtToBinary::leerArchivo(rutaVacio).empty());

    // Abrir un archivo inexistente lanza std::runtime_error
    const std::string rutaInexistente = tempPath("no_existe.bin");
    fs::remove(rutaInexistente);
    CHECK_THROWS(txtToBinary::leerArchivo(rutaInexistente), std::runtime_error);

    fs::remove(rutaTexto);
    fs::remove(rutaSaltos);
    fs::remove(rutaVacio);
}

static void testSPN() {
    // Vectores verificados a mano con la S-box de PRESENT pasada como parametro
    const std::array<uint8_t, 16>& S = Tables::PRESENT_SBOX;
    CHECK(SPN::subNibbles(0x0123456789ABCDEFULL, S) == 0xC56B90AD3EF84712ULL);
    CHECK(SPN::subNibbles(0x0000000000000000ULL, S) == 0xCCCCCCCCCCCCCCCCULL);
    CHECK(SPN::subNibbles(0xFFFFFFFFFFFFFFFFULL, S) == 0x2222222222222222ULL);

    // Con la tabla inversa, subNibbles se deshace (10 000 valores, en ambos sentidos)
    const std::array<uint8_t, 16> invS = Tables::invertTable(S);
    std::mt19937_64 gen(12345);
    bool idaVuelta = true;
    for (int i = 0; i < 10000; i++) {
        const uint64_t v = gen();
        idaVuelta = idaVuelta && (SPN::subNibbles(SPN::subNibbles(v, S), invS) == v)
                              && (SPN::subNibbles(SPN::subNibbles(v, invS), S) == v);
    }
    CHECK(idaVuelta);
}

static void testPrng() {
    // Vector publicado de splitmix64 (primera salida con x = 0); tambien cruzado
    // con una referencia independiente en Python
    uint64_t x = 0;
    CHECK(Prng::splitmix64(x) == 0xE220A8397B1DCDAFULL);
    CHECK(x == 0x9E3779B97F4A7C15ULL); // x avanzo exactamente una vez

    // Primeras salidas de next(), cruzadas con la referencia en Python
    Prng p(0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL);
    CHECK(p.next() == 0x70FB7C77B676C8CBULL);
    CHECK(p.next() == 0xDC66249BA38DF6EBULL);
    CHECK(p.next() == 0x002500F6BECFC2ABULL);

    // La clave de puros ceros no deja al generador atorado en ceros
    Prng ceros(0, 0);
    CHECK(ceros.next() == 0xDEC90D521E93E35DULL);
    CHECK(ceros.next() == 0x99EC5F36CB75F2B4ULL);

    // Misma semilla, misma secuencia (determinista)
    Prng a(42, 7), b(42, 7);
    bool iguales = true;
    for (int i = 0; i < 1000; i++) iguales = iguales && (a.next() == b.next());
    CHECK(iguales);

    // Semillas que difieren en un solo bit dan secuencias distintas
    Prng c(42, 7), d(42, 6), e(43, 7);
    bool distintasLo = false, distintasHi = false;
    for (int i = 0; i < 16; i++) {
        const uint64_t vc = c.next();
        distintasLo = distintasLo || (vc != d.next());
        distintasHi = distintasHi || (vc != e.next());
    }
    CHECK(distintasLo);
    CHECK(distintasHi);
}

// Permutacion de bits de PRESENT: P(i) = 16i mod 63, con P(63) = 63
static std::array<uint8_t, 64> presentPerm() {
    std::array<uint8_t, 64> p{};
    for (int i = 0; i < 63; i++) p[i] = static_cast<uint8_t>((16 * i) % 63);
    p[63] = 63;
    return p;
}

static void testTables() {
    // Vectores de modInverse de la guia
    CHECK(Tables::modInverse(1) == 1);
    CHECK(Tables::modInverse(3) == 0xAAAAAAAAAAAAAAABULL);
    CHECK(Tables::modInverse(0xFFFFFFFFFFFFFFFFULL) == 0xFFFFFFFFFFFFFFFFULL);

    // m * modInverse(m) == 1 para 1000 impares aleatorios
    std::mt19937_64 gen(12345);
    bool todosUno = true;
    for (int i = 0; i < 1000; i++) {
        const uint64_t m = gen() | 1;
        todosUno = todosUno && (m * Tables::modInverse(m) == 1);
    }
    CHECK(todosUno);

    // Un par no tiene inverso
    CHECK_THROWS(Tables::modInverse(0), std::invalid_argument);
    CHECK_THROWS(Tables::modInverse(2), std::invalid_argument);

    // Inversa de la S-box de PRESENT: S[0] = 0xC, asi que inv[0xC] = 0
    const std::array<uint8_t, 16> invS = Tables::invertTable(Tables::PRESENT_SBOX);
    CHECK(invS[0xC] == 0x0);
    CHECK(invS[0x2] == 0xF);
    CHECK(Tables::invertTable(invS) == Tables::PRESENT_SBOX);

    // Inversa de la permutacion de PRESENT y vuelta
    const std::array<uint8_t, 64> perm = presentPerm();
    const std::array<uint8_t, 64> invP = Tables::invertTable(perm);
    CHECK(invP[16] == 1); // el bit 1 va al 16, asi que el 16 viene del 1
    CHECK(Tables::invertTable(invP) == perm);

    // Tablas que no son permutaciones
    std::array<uint8_t, 16> repetida = Tables::PRESENT_SBOX;
    repetida[1] = repetida[0];
    CHECK_THROWS(Tables::invertTable(repetida), std::invalid_argument);
    std::array<uint8_t, 16> fueraDeRango = Tables::PRESENT_SBOX;
    fueraDeRango[0] = 16;
    CHECK_THROWS(Tables::invertTable(fueraDeRango), std::invalid_argument);
}

static void testPermuteBits() {
    // Vectores verificados a mano con la permutacion de PRESENT
    const std::array<uint8_t, 64> P = presentPerm();
    CHECK(SPN::permuteBits(0x1ULL, P) == 0x1ULL);
    CHECK(SPN::permuteBits(0x2ULL, P) == 0x10000ULL);
    CHECK(SPN::permuteBits(0x10ULL, P) == 0x2ULL);
    CHECK(SPN::permuteBits(0xF0ULL, P) == 0x0002000200020002ULL);
    CHECK(SPN::permuteBits(0x8000000000000000ULL, P) == 0x8000000000000000ULL);

    // Con la tabla inversa se deshace, y nunca cambia cuantos bits hay en 1
    const std::array<uint8_t, 64> invP = Tables::invertTable(P);
    std::mt19937_64 gen(777);
    bool idaVuelta = true, mismosUnos = true;
    for (int i = 0; i < 10000; i++) {
        const uint64_t v = gen();
        const uint64_t p = SPN::permuteBits(v, P);
        idaVuelta = idaVuelta && (SPN::permuteBits(p, invP) == v);
        mismosUnos = mismosUnos && (std::bitset<64>(p).count() == std::bitset<64>(v).count());
    }
    CHECK(idaVuelta);
    CHECK(mismosUnos);
}

// Corre un grupo de pruebas; una excepcion inesperada cuenta como fallo y no detiene a los demas
static void run(const char* nombre, void (*prueba)()) {
    try {
        prueba();
    } catch (const std::exception& e) {
        ++g_total;
        ++g_fail;
        std::cerr << nombre << ": excepción inesperada: " << e.what() << "\n";
    }
}

int main() {
    run("Config", testConfig);
    run("Block", testBlock);
    run("txtToBinary", testTxtToBinary);
    run("SPN", testSPN);
    run("Prng", testPrng);
    run("Tables", testTables);
    run("permuteBits", testPermuteBits);

    std::cout << g_total << " checks, " << g_fail << " fallos\n";
    return g_fail == 0 ? 0 : 1;
}
