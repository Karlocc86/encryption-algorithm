//
// Created by sebas on 14/10/2026.
//
// Linea de comandos de KDSPN-64 (reemplaza el andamio de pruebas con XOR).
// Codigos de salida: 0 si todo va bien, 1 en cualquier error. Los errores van a
// stderr y no se escribe nada en stdout, para que otros programas (como la GUI)
// puedan usar la salida sin confundirla con un mensaje de error.
//

#include <cstddef>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX // que windows.h no defina macros min y max
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#endif

#include "Cbc.h"
#include "Config.h"
#include "Encoding.h"
#include "KeySchedule.h"
#include "TextCipher.h"
#include "txtToBinary.h"

namespace fs = std::filesystem;

static void printUsage() {
    std::cerr << "Uso:\n"
                 "  ciber enc-text \"<texto>\" <clave>     cifra un texto (max. 100 bytes) e imprime hexadecimal\n"
                 "  ciber dec-text <hex> <clave>          descifra el hexadecimal e imprime el texto\n"
                 "  ciber enc <entrada> <salida> <clave>  cifra un archivo (salida binaria: IV || cifrado)\n"
                 "  ciber dec <entrada> <salida> <clave>  descifra un archivo\n"
                 "  ciber tables <clave>                  muestra las tablas que salen de la clave\n"
                 "La clave es de 1 a 16 caracteres o de exactamente 32 digitos hexadecimales.\n";
}

// Argumentos en UTF-8. En Windows, argv llega en la pagina de codigos ANSI y una
// "ó" no seria igual que en un archivo UTF-8; por eso se lee la linea de comandos
// en UTF-16 y se convierte a UTF-8. En otros sistemas argv ya viene en UTF-8.
static std::vector<std::string> utf8Args(int argc, char *argv[]) {
#ifdef _WIN32
    int n = 0;
    LPWSTR *w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (w != nullptr && n == argc) {
        std::vector<std::string> args;
        for (int i = 0; i < n; i++) {
            const int largo = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
            std::string s(static_cast<std::size_t>(largo > 0 ? largo - 1 : 0), '\0');
            if (largo > 1) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, &s[0], largo, nullptr, nullptr);
            args.push_back(s);
        }
        LocalFree(w);
        return args;
    }
    if (w != nullptr) LocalFree(w);
#endif
    return std::vector<std::string>(argv, argv + argc);
}

// La salida nunca puede ser el mismo archivo que la entrada: se perderia el original
static void checkDifferentFiles(const std::string &entrada, const std::string &salida) {
    std::error_code ec;
    if (fs::exists(salida, ec) && fs::equivalent(entrada, salida, ec)) {
        throw std::invalid_argument("la salida no puede ser el mismo archivo que la entrada");
    }
}

static std::string hex64(uint64_t v) {
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << v;
    return os.str();
}

static int cmdEncText(const std::vector<std::string> &a) {
    const std::string hex = TextCipher::encryptText(a[2], a[3]);
    std::cout << hex << "\n";
    return 0;
}

static int cmdDecText(const std::vector<std::string> &a) {
    const std::string texto = TextCipher::decryptText(a[2], a[3]);
    std::cout << texto << "\n";
    return 0;
}

static int cmdEnc(const std::vector<std::string> &a, char *argv[]) {
    // Las rutas se usan tal como las entrego Windows (argv), que es lo que entiende ifstream
    const std::string entrada = argv[2], salida = argv[3];
    checkDifferentFiles(entrada, salida);

    const Schedule schedule = KeySchedule::expand(Encoding::parseKey(a[4]));
    const std::vector<uint8_t> plano = txtToBinary::leerArchivo(entrada);
    const std::vector<uint8_t> cifrado = Cbc::encrypt(plano, schedule);
    txtToBinary::escribirArchivo(salida, cifrado);

    std::cout << "cifrado: " << plano.size() << " bytes -> " << cifrado.size() << " bytes en " << salida << "\n";
    return 0;
}

static int cmdDec(const std::vector<std::string> &a, char *argv[]) {
    const std::string entrada = argv[2], salida = argv[3];
    checkDifferentFiles(entrada, salida);

    const Schedule schedule = KeySchedule::expand(Encoding::parseKey(a[4]));
    const std::vector<uint8_t> cifrado = txtToBinary::leerArchivo(entrada);

    std::vector<uint8_t> plano;
    try {
        plano = Cbc::decrypt(cifrado, schedule);
    } catch (const std::invalid_argument &e) {
        throw std::invalid_argument(std::string("no se pudo descifrar (clave incorrecta o archivo danado): ") + e.what());
    }
    // Solo se escribe si el descifrado salio bien: nunca queda un archivo a medias
    txtToBinary::escribirArchivo(salida, plano);

    std::cout << "descifrado: " << cifrado.size() << " bytes -> " << plano.size() << " bytes en " << salida << "\n";
    return 0;
}

static int cmdTables(const std::vector<std::string> &a) {
    const Schedule s = KeySchedule::expand(Encoding::parseKey(a[2]));

    // Se arma todo antes de imprimir, asi un error no deja salida a medias
    std::ostringstream os;
    const char *dig = "0123456789ABCDEF";
    os << "S-box:           ";
    for (uint8_t v : s.sbox) os << dig[v & 0xF];
    os << "\nPermutacion:     ";
    for (std::size_t i = 0; i < s.perm.size(); i++) os << static_cast<int>(s.perm[i]) << (i + 1 < s.perm.size() ? " " : "");
    os << "\nRotaciones:      ";
    for (std::size_t r = 0; r < ROUNDS; r++) os << s.rot[r] << (r + 1 < ROUNDS ? " " : "");
    os << "\nMultiplicadores:";
    for (std::size_t r = 0; r < ROUNDS; r++) os << "\n  ronda " << std::setw(2) << r << "  " << hex64(s.mul[r]);
    os << "\nSubclaves:";
    for (std::size_t r = 0; r < SUBKEYS; r++) os << "\n  K[" << std::setw(2) << r << "]   " << hex64(s.subkeys[r]);
    os << "\nIntentos:        S-box " << s.sboxAttempts << ", permutacion " << s.permAttempts << "\n";

    std::cout << os.str();
    return 0;
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    // stdout en modo binario: sin esto Windows cambia cada \n por \r\n y un texto
    // descifrado que traia \r\n saldria como \r\r\n
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    const std::vector<std::string> a = utf8Args(argc, argv);
    if (a.size() < 2) {
        printUsage();
        return 1;
    }

    const std::string cmd = a[1];
    try {
        if (cmd == "enc-text" && a.size() == 4) return cmdEncText(a);
        if (cmd == "dec-text" && a.size() == 4) return cmdDecText(a);
        if (cmd == "enc" && a.size() == 5) return cmdEnc(a, argv);
        if (cmd == "dec" && a.size() == 5) return cmdDec(a, argv);
        if (cmd == "tables" && a.size() == 3) return cmdTables(a);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    std::cerr << "Error: comando o numero de argumentos invalido\n";
    printUsage();
    return 1;
}
