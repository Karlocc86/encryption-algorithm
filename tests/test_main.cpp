//
// Pruebas de KDSPN-64: marco minimo sin dependencias externas.
// Se ejecuta con ciber_tests (o con ctest) e imprime "N checks, M fallos".
//

#include <algorithm>
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
#include "BlockCipher.h"
#include "Cbc.h"
#include "Config.h"
#include "KeySchedule.h"
#include "Padding.h"
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

static void testRotations() {
    // Vectores verificados a mano
    CHECK(SPN::rotl(0x1ULL, 13) == 0x2000ULL);
    CHECK(SPN::rotl(0x8000000000000000ULL, 1) == 0x1ULL);
    CHECK(SPN::rotr(0x1ULL, 1) == 0x8000000000000000ULL);

    // rotr deshace rotl para todos los n validos
    std::mt19937_64 gen(2024);
    bool idaVuelta = true;
    for (unsigned n = 1; n <= 63; n++) {
        for (int i = 0; i < 100; i++) {
            const uint64_t v = gen();
            idaVuelta = idaVuelta && (SPN::rotr(SPN::rotl(v, n), n) == v);
        }
    }
    CHECK(idaVuelta);

    // n = 0 y n = 64 desplazarian 64 bits (comportamiento indefinido)
    CHECK_THROWS(SPN::rotl(1, 0), std::invalid_argument);
    CHECK_THROWS(SPN::rotl(1, 64), std::invalid_argument);
    CHECK_THROWS(SPN::rotr(1, 0), std::invalid_argument);
    CHECK_THROWS(SPN::rotr(1, 64), std::invalid_argument);
}

// Clave de 16 bytes a partir de un texto (relleno con ceros), como hara parseKey
static std::array<uint8_t, KEY_BYTES> keyFromText(const std::string& texto) {
    std::array<uint8_t, KEY_BYTES> k{};
    for (std::size_t i = 0; i < texto.size() && i < KEY_BYTES; i++) k[i] = static_cast<uint8_t>(texto[i]);
    return k;
}

// Las 5 claves de prueba de la guia: ceros, 0xFF, "0123456789ABCDEF", "a" y una aleatoria
static std::vector<std::array<uint8_t, KEY_BYTES>> testKeys() {
    std::array<uint8_t, KEY_BYTES> ceros{}, unos{}, aleatoria{};
    unos.fill(0xFF);
    std::mt19937_64 gen(99);
    for (auto& b : aleatoria) b = static_cast<uint8_t>(gen());
    return {ceros, unos, keyFromText("0123456789ABCDEF"), keyFromText("a"), aleatoria};
}

static std::string hexNibbles(const std::array<uint8_t, 16>& t) {
    const char* dig = "0123456789ABCDEF";
    std::string s;
    for (uint8_t v : t) s += dig[v & 0xF];
    return s;
}

static bool sameSchedule(const Schedule& a, const Schedule& b) {
    return a.sbox == b.sbox && a.invSbox == b.invSbox && a.perm == b.perm && a.invPerm == b.invPerm
        && a.rot == b.rot && a.mul == b.mul && a.mulInv == b.mulInv && a.subkeys == b.subkeys;
}

static void testKeySchedule() {
    // La condicion de los nibbles: la identidad no la cumple, la de PRESENT si
    std::array<uint8_t, 64> identidad{};
    for (int i = 0; i < 64; i++) identidad[i] = static_cast<uint8_t>(i);
    CHECK(!KeySchedule::spreadsNibbles(identidad));
    CHECK(KeySchedule::spreadsNibbles(presentPerm()));

    const auto claves = testKeys();
    const char* nombres[] = {"ceros", "0xFF", "0123456789ABCDEF", "a", "aleatoria"};
    std::vector<Schedule> schedules;

    for (std::size_t c = 0; c < claves.size(); c++) {
        const Schedule s = KeySchedule::expand(claves[c]);
        schedules.push_back(s);

        // S-box: permutacion sin puntos fijos, con su inversa correcta
        CHECK(s.invSbox == Tables::invertTable(s.sbox)); // invertTable lanza si no es permutacion
        bool sinPuntosFijos = true;
        for (int x = 0; x < 16; x++) sinPuntosFijos = sinPuntosFijos && (s.sbox[x] != x);
        CHECK(sinPuntosFijos);

        // Permutacion de bits: valida, con su inversa, y cumple la condicion de los nibbles
        CHECK(s.invPerm == Tables::invertTable(s.perm));
        CHECK(KeySchedule::spreadsNibbles(s.perm));

        // Rotaciones de 1 a 63; multiplicadores impares con su inverso
        bool rotOk = true, mulOk = true;
        for (std::size_t r = 0; r < ROUNDS; r++) {
            rotOk = rotOk && s.rot[r] >= 1 && s.rot[r] <= 63;
            mulOk = mulOk && (s.mul[r] & 1) && (s.mul[r] * s.mulInv[r] == 1);
        }
        CHECK(rotOk);
        CHECK(mulOk);
        CHECK(s.subkeys.size() == 11);

        // Determinista: la misma clave da exactamente las mismas tablas
        CHECK(sameSchedule(s, KeySchedule::expand(claves[c])));

        // La guia pide reportar los intentos (se esperan cientos para la permutacion)
        CHECK(s.permAttempts <= 10000);
        std::cout << "  KeySchedule [" << nombres[c] << "]: sbox " << s.sboxAttempts
                  << " intentos, perm " << s.permAttempts << " intentos\n";
    }

    // Claves distintas dan tablas distintas
    bool distintas = true;
    for (std::size_t i = 0; i < schedules.size(); i++)
        for (std::size_t j = i + 1; j < schedules.size(); j++)
            distintas = distintas && schedules[i].perm != schedules[j].perm
                                  && schedules[i].subkeys != schedules[j].subkeys;
    CHECK(distintas);

    // Vectores cruzados con una referencia independiente en Python de la especificacion
    const Schedule& z = schedules[0];
    CHECK(hexNibbles(z.sbox) == "3497BA20516C8EFD");
    CHECK(z.sboxAttempts == 8 && z.permAttempts == 103);
    CHECK(z.perm[0] == 49 && z.perm[1] == 4 && z.perm[2] == 32 && z.perm[7] == 24);
    CHECK((z.rot == std::array<unsigned, ROUNDS>{27, 63, 48, 44, 4, 34, 26, 9, 21, 49}));
    CHECK(z.mul[0] == 0x9C0EEB7F67416D0FULL);
    CHECK(z.subkeys[0] == 0x5D594A26F9DC2C96ULL && z.subkeys[10] == 0x776E6DF80AA98AF9ULL);

    const Schedule& f = schedules[1];
    CHECK(hexNibbles(f.sbox) == "C0E7D642AB1359F8");
    CHECK(f.subkeys[0] == 0x88C4CBB5D56EE87EULL && f.subkeys[10] == 0x2EC592C76EE82A59ULL);

    const Schedule& t = schedules[2];
    CHECK(hexNibbles(t.sbox) == "4DE8BC23615F7A90");
    CHECK(t.sboxAttempts == 3 && t.permAttempts == 243);
    CHECK((t.rot == std::array<unsigned, ROUNDS>{31, 7, 35, 16, 42, 45, 40, 8, 31, 57}));
    CHECK(t.mul[0] == 0xC4B618A382D3322BULL);
    CHECK(t.subkeys[0] == 0xF90009F518B44CA6ULL && t.subkeys[10] == 0xC20D2BC65019F4E3ULL);

    const Schedule& a = schedules[3];
    CHECK(hexNibbles(a.sbox) == "EF3C9BD061872A45");
    CHECK(a.perm[0] == 44 && a.perm[7] == 43);
    CHECK(a.subkeys[0] == 0x6267A5C8E34DF56CULL);
}

static void testBlockCipher() {
    const auto claves = testKeys();
    std::mt19937_64 gen(31337);

    for (const auto& clave : claves) {
        const Schedule s = KeySchedule::expand(clave);

        // Ida y vuelta para 10 000 bloques; el cifrado nunca deja el bloque igual
        bool idaVuelta = true, cambia = true;
        for (int i = 0; i < 10000; i++) {
            const uint64_t p = gen();
            const uint64_t c = BlockCipher::encryptBlock(p, s);
            idaVuelta = idaVuelta && (BlockCipher::decryptBlock(c, s) == p);
            cambia = cambia && (c != p);
        }
        CHECK(idaVuelta);
        CHECK(cambia);

        // Determinista: el mismo bloque con la misma clave da lo mismo
        CHECK(BlockCipher::encryptBlock(0x0123456789ABCDEFULL, s)
              == BlockCipher::encryptBlock(0x0123456789ABCDEFULL, s));

        // Una clave que difiere en 1 bit no recupera el bloque
        for (int bit : {0, 63, 127}) {
            std::array<uint8_t, KEY_BYTES> otra = clave;
            otra[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
            const Schedule s2 = KeySchedule::expand(otra);
            const uint64_t p = 0x0123456789ABCDEFULL;
            CHECK(BlockCipher::decryptBlock(BlockCipher::encryptBlock(p, s), s2) != p);
        }
    }
}

static void testBlockCipherVectors() {
    // Vectores de regresion: 3 bloques con 3 claves. No son vectores publicados
    // (el cifrado es nuestro); los calculo una implementacion independiente de la
    // especificacion en Python, que no esta en el repo. Si alguno cambia, cambio el cifrado.
    const auto claves = testKeys(); // [0] ceros, [1] 0xFF, [2] "0123456789ABCDEF"
    const uint64_t planos[3] = {0x0000000000000000ULL, 0x0123456789ABCDEFULL, 0xFFFFFFFFFFFFFFFFULL};
    const uint64_t esperados[3][3] = {
        {0xFBD5EAAB2516F13DULL, 0x3ED97D801B218A9AULL, 0x6B48063149273D1EULL},
        {0xBC091FC1C7F7BD4EULL, 0xD7985B017686CED2ULL, 0x5846A4A781817688ULL},
        {0x0EB29014992FA241ULL, 0xF4640B08F3F10C77ULL, 0xA9D085FD50A6AED4ULL},
    };
    for (int c = 0; c < 3; c++) {
        const Schedule s = KeySchedule::expand(claves[c]);
        for (int p = 0; p < 3; p++) {
            CHECK(BlockCipher::encryptBlock(planos[p], s) == esperados[c][p]);
            CHECK(BlockCipher::decryptBlock(esperados[c][p], s) == planos[p]);
        }
    }
}

static void testPadding() {
    // Vectores de la guia
    CHECK(Padding::pad({}) == std::vector<uint8_t>(8, 0x08));
    const std::vector<uint8_t> siete = {1, 2, 3, 4, 5, 6, 7};
    CHECK(Padding::pad(siete) == (std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 0x01}));
    const std::vector<uint8_t> ocho = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint8_t> ochoConRelleno = ocho;
    ochoConRelleno.insert(ochoConRelleno.end(), 8, 0x08);
    CHECK(Padding::pad(ocho) == ochoConRelleno);

    // Ida y vuelta y largo siempre multiplo de 8, para largos de 0 a 40
    bool idaVuelta = true, multiplo = true;
    for (std::size_t len = 0; len <= 40; len++) {
        std::vector<uint8_t> m(len);
        for (std::size_t i = 0; i < len; i++) m[i] = static_cast<uint8_t>(i * 37);
        const std::vector<uint8_t> p = Padding::pad(m);
        multiplo = multiplo && (p.size() % 8 == 0) && (p.size() > len) && (p.size() <= len + 8);
        idaVuelta = idaVuelta && (Padding::unpad(p) == m);
    }
    CHECK(idaVuelta);
    CHECK(multiplo);

    // Rellenos invalidos
    std::vector<uint8_t> cero = {1, 2, 3, 4, 5, 6, 7, 0};
    std::vector<uint8_t> nueve = {1, 2, 3, 4, 5, 6, 7, 9};
    std::vector<uint8_t> distintos = {1, 2, 3, 4, 5, 2, 3, 3}; // dice 3 pero hay 2 3 3
    std::vector<uint8_t> noMultiplo = {1, 2, 3, 1};
    CHECK_THROWS(Padding::unpad(cero), std::invalid_argument);
    CHECK_THROWS(Padding::unpad(nueve), std::invalid_argument);
    CHECK_THROWS(Padding::unpad(distintos), std::invalid_argument);
    CHECK_THROWS(Padding::unpad(noMultiplo), std::invalid_argument);
    CHECK_THROWS(Padding::unpad({}), std::invalid_argument);
}

static void testCbc() {
    const Schedule s = KeySchedule::expand(keyFromText("0123456789ABCDEF"));
    const std::array<uint8_t, BLOCK_BYTES> iv = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

    // Ida y vuelta para largos de 0 a 64 y para 100 y 1000 bytes, con IV fijo y aleatorio
    std::vector<std::size_t> largos;
    for (std::size_t l = 0; l <= 64; l++) largos.push_back(l);
    largos.push_back(100);
    largos.push_back(1000);

    std::mt19937_64 gen(4242);
    bool idaVuelta = true, tamano = true, empiezaConIv = true;
    for (std::size_t len : largos) {
        std::vector<uint8_t> m(len);
        for (auto& b : m) b = static_cast<uint8_t>(gen());
        const std::vector<uint8_t> c = Cbc::encrypt(m, s, iv);
        idaVuelta = idaVuelta && (Cbc::decrypt(c, s) == m)
                              && (Cbc::decrypt(Cbc::encrypt(m, s), s) == m);
        tamano = tamano && (c.size() == 8 + Padding::pad(m).size());
        empiezaConIv = empiezaConIv && std::equal(iv.begin(), iv.end(), c.begin());
    }
    CHECK(idaVuelta);
    CHECK(tamano);
    CHECK(empiezaConIv);

    // El mismo texto con IV distintos da cifrados distintos
    const std::string hola = "Hola mundo";
    const std::vector<uint8_t> m(hola.begin(), hola.end());
    std::array<uint8_t, BLOCK_BYTES> iv2 = iv;
    iv2[7] ^= 1;
    CHECK(Cbc::encrypt(m, s, iv) != Cbc::encrypt(m, s, iv2));
    CHECK(Cbc::encrypt(m, s) != Cbc::encrypt(m, s)); // dos IV aleatorios

    // 3 bloques iguales en el mensaje dan 3 bloques cifrados distintos (por eso no ECB)
    const std::vector<uint8_t> aes(24, 'A');
    const std::vector<uint8_t> c = Cbc::encrypt(aes, s, iv);
    const uint64_t c1 = Block::bytesToBlock(c, 8), c2 = Block::bytesToBlock(c, 16), c3 = Block::bytesToBlock(c, 24);
    CHECK(c1 != c2 && c2 != c3 && c1 != c3);

    // Largos invalidos al descifrar: solo IV, no multiplo de 8, vacio
    CHECK_THROWS(Cbc::decrypt(std::vector<uint8_t>(8, 0), s), std::invalid_argument);
    CHECK_THROWS(Cbc::decrypt(std::vector<uint8_t>(20, 0), s), std::invalid_argument);
    CHECK_THROWS(Cbc::decrypt(std::vector<uint8_t>(), s), std::invalid_argument);

    // Con una clave equivocada nunca se recupera el original (error o basura)
    const Schedule otra = KeySchedule::expand(keyFromText("0123456789ABCDEG"));
    bool nuncaOriginal = true;
    for (int i = 0; i < 200; i++) {
        std::array<uint8_t, BLOCK_BYTES> ivi = iv;
        ivi[0] = static_cast<uint8_t>(i);
        try {
            nuncaOriginal = nuncaOriginal && (Cbc::decrypt(Cbc::encrypt(m, s, ivi), otra) != m);
        } catch (const std::invalid_argument&) {
            // relleno invalido: es lo esperado
        }
    }
    CHECK(nuncaOriginal);
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
    run("rotaciones", testRotations);
    run("KeySchedule", testKeySchedule);
    run("BlockCipher", testBlockCipher);
    run("BlockCipher vectores", testBlockCipherVectors);
    run("Padding", testPadding);
    run("Cbc", testCbc);

    std::cout << g_total << " checks, " << g_fail << " fallos\n";
    return g_fail == 0 ? 0 : 1;
}
