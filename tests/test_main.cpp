//
// Pruebas de KDSPN-64: marco minimo sin dependencias externas.
// Se ejecuta con ciber_tests (o con ctest) e imprime "N checks, M fallos".
//

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "Block.h"
#include "Config.h"
#include "SPN.h"
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
    // Vectores verificados a mano con la S-box de PRESENT (la fija que hoy tiene SPN)
    CHECK(SPN::subNibbles(0x0123456789ABCDEFULL) == 0xC56B90AD3EF84712ULL);
    CHECK(SPN::subNibbles(0x0000000000000000ULL) == 0xCCCCCCCCCCCCCCCCULL);
    CHECK(SPN::subNibbles(0xFFFFFFFFFFFFFFFFULL) == 0x2222222222222222ULL);

    // invSubNibbles deshace subNibbles y viceversa
    std::mt19937_64 gen(12345);
    for (int i = 0; i < 1000; i++) {
        const uint64_t v = gen();
        CHECK(SPN::invSubNibbles(SPN::subNibbles(v)) == v);
        CHECK(SPN::subNibbles(SPN::invSubNibbles(v)) == v);
    }
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

    std::cout << g_total << " checks, " << g_fail << " fallos\n";
    return g_fail == 0 ? 0 : 1;
}
