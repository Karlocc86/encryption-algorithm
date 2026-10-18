# KDSPN-64: cifrado por bloques con tablas derivadas de la clave

Cifrado por bloques hecho para la materia *Integration of Computer Security in Networks and Software Systems*. Es una red de sustitución-permutación (SPN) de 64 bits de bloque y 128 de clave, en la que **la clave no solo se mezcla con XOR: también decide la S-box, la permutación de bits, las rotaciones y los multiplicadores** de cada ronda.

> **Es un cifrado de juguete para aprender.** No es seguro y no debe usarse para proteger información real (ver [Limitaciones y ataques](#limitaciones-y-ataques)).

Contenido: [Parámetros](#parámetros) · [El algoritmo](#el-algoritmo) · [Derivación de tablas](#derivación-de-las-tablas-desde-la-clave) · [CBC y relleno](#modo-cbc-relleno-y-formatos) · [Resultados](#resultados-medidos) · [Compilar](#cómo-compilar) · [Usar](#cómo-usar) · [Cómo se probó](#cómo-se-probó) · [Limitaciones](#limitaciones-y-ataques) · [Rúbrica](#relación-con-la-rúbrica) · [Guion](#guion-de-presentación-5-minutos) · [Preguntas](#preguntas-probables)

---

## Objetivo y alcance

Diseñar, implementar y probar un cifrado simétrico que:

- cifre y descifre textos de hasta 100 caracteres y archivos de cualquier tamaño;
- tenga al menos dos operaciones de confusión y dos de difusión, todas invertibles;
- muestre con números (efecto avalancha) que cambiar un bit cambia la mitad de la salida;
- tenga una interfaz gráfica y una línea de comandos.

Lo que lo hace distinto de un SPN de libro: en vez de una S-box y una permutación fijas (como PRESENT o AES), **cada clave arma su propio cifrado**. Dos claves distintas no producen "el mismo cifrado con otros números", sino cifrados con piezas distintas. La idea tiene antecedentes reales: Blowfish y Twofish también usan S-boxes que dependen de la clave.

## Parámetros

| Parámetro | Valor |
| --- | --- |
| Estructura | SPN con tablas derivadas de la clave |
| Bloque | 64 bits (8 bytes) |
| Clave | 128 bits (1 a 16 caracteres, o exactamente 32 dígitos hexadecimales) |
| Rondas | 10, más un XOR final con la subclave 11 (blanqueo) |
| Modo de operación | CBC con relleno PKCS#7 e IV aleatorio |
| Salida de texto | Hexadecimal en mayúsculas |
| Generador para las tablas | splitmix64 (siembra) + xoshiro256\*\* |

## Estructura del repositorio

| Archivo | Qué hace |
| --- | --- |
| `Config.h` | Constantes: `BLOCK_BYTES`, `KEY_BYTES`, `ROUNDS`, `SUBKEYS`, `MAX_TEXT_BYTES`, `MAX_TABLE_ATTEMPTS` |
| `txtToBinary.h/.cpp` | Leer y escribir archivos en modo binario |
| `Block.h/.cpp` | 8 bytes ↔ un `uint64_t` (el primer byte va a los bits altos) |
| `Prng.h/.cpp` | splitmix64 y xoshiro256\*\*, deterministas en cualquier compilador |
| `Tables.h/.cpp` | `PRESENT_SBOX` (solo para pruebas), `invertTable`, `modInverse` |
| `SPN.h/.cpp` | Operaciones de la ronda: `subNibbles`, `permuteBits`, `rotl`, `rotr` |
| `KeySchedule.h/.cpp` | Deriva todas las tablas de la clave (`Schedule`) |
| `BlockCipher.h/.cpp` | Cifra y descifra un bloque |
| `Padding.h/.cpp` | Relleno PKCS#7 |
| `Cbc.h/.cpp` | Modo CBC |
| `Encoding.h/.cpp` | Hexadecimal y lectura de la clave del usuario |
| `TextCipher.h/.cpp` | Cifrar y descifrar texto (lo que usan la CLI y la GUI) |
| `Avalanche.h/.cpp` | Medición del efecto avalancha |
| `main.cpp` | Línea de comandos `ciber` |
| `gui/ciber_gui.py` | Interfaz gráfica (Tkinter) que llama a `ciber` |
| `tests/test_main.cpp` | Pruebas (`ciber_tests`) |

---

## El algoritmo

### La ronda

Cada una de las 10 rondas aplica cinco operaciones al bloque `s` de 64 bits:

| # | Operación | Código | Tipo |
| --- | --- | --- | --- |
| 1 | XOR con la subclave de la ronda | `s ^= K[r]` | Confusión |
| 2 | S-box de 4 bits en cada uno de los 16 nibbles | `SPN::subNibbles(s, sbox)` | Confusión |
| 3 | Permutación de los 64 bits | `SPN::permuteBits(s, perm)` | Difusión |
| 4 | Multiplicación por un impar, módulo 2^64 | `s *= mul[r]` | Confusión y difusión |
| 5 | Rotación circular a la izquierda | `SPN::rotl(s, rot[r])` | Difusión |

Al final de las 10 rondas: `s ^= K[10]` (blanqueo). Son tres operaciones de confusión y dos de difusión, más la multiplicación que cuenta para ambas.

### Por qué está cada operación

- **XOR con la subclave.** Es lo que mete la clave en los datos. Sin él, todo lo demás sería público una vez conocidas las tablas.
- **S-box.** Es la única parte no lineal con respecto al XOR: rompe la relación sencilla entre entrada y salida. Sin ella, todo el cifrado sería un sistema de ecuaciones lineales (sobre bits) que se resuelve con álgebra.
- **Permutación de bits.** Reparte los 4 bits que salen de cada S-box hacia 4 S-boxes distintas de la ronda siguiente (ver la condición de los nibbles). Así, en pocas rondas cada bit de entrada influye en todo el bloque.
- **Multiplicación por un impar.** Mezcla muchos bits a la vez: con los acarreos, cada bit afecta a todos los bits de su misma posición hacia arriba.
- **Rotación.** Al multiplicar módulo 2^64, un bit solo influye hacia arriba, nunca hacia abajo, así que los bits altos nunca alcanzarían a los bajos. La rotación (distinta en cada ronda) baja esos bits altos, y la siguiente multiplicación los vuelve a esparcir. **Por eso la multiplicación y la rotación van juntas.**
- **Blanqueo final.** Sin el último XOR, un atacante podría deshacer la última rotación sin conocer la clave.

### Descifrado

Aplica las inversas en orden contrario y recorre las rondas de la última a la primera:

```text
s ^= K[10]
para r = 9 hasta 0:
    s = rotr(s, rot[r])            deshace la rotación
    s *= mulInv[r]                 deshace la multiplicación: mul * mulInv == 1 (mod 2^64)
    s = permuteBits(s, invPerm)    deshace la permutación
    s = subNibbles(s, invSbox)     deshace la S-box
    s ^= K[r]                      deshace el XOR: (x ^ k) ^ k == x
```

### Diagrama de flujo

```mermaid
flowchart LR
    subgraph Cifrado
        direction TB
        P["Bloque en claro (64 bits)"] --> X1["XOR con K[r]"]
        X1 --> S1["S-box en los 16 nibbles"]
        S1 --> P1["Permutación de bits"]
        P1 --> M1["Multiplicar por mul[r] mod 2^64"]
        M1 --> R1["Rotar a la izquierda rot[r]"]
        R1 -->|"r < 9: siguiente ronda"| X1
        R1 -->|"r = 9"| W1["XOR con K[10]"]
        W1 --> C["Bloque cifrado"]
    end
    subgraph Descifrado
        direction TB
        C2["Bloque cifrado"] --> W2["XOR con K[10]"]
        W2 --> R2["Rotar a la derecha rot[r]"]
        R2 --> M2["Multiplicar por mulInv[r]"]
        M2 --> P2["Permutación inversa"]
        P2 --> S2["S-box inversa"]
        S2 --> X2["XOR con K[r]"]
        X2 -->|"r > 0: ronda anterior"| R2
        X2 -->|"r = 0"| PT["Bloque en claro"]
    end
```

---

## Derivación de las tablas desde la clave

La clave de 16 bytes se parte en dos mitades de 64 bits (`hi` y `lo`, con `Block::bytesToBlock`). Con ellas se siembra el generador y se derivan las piezas **en este orden exacto**. Cambiar el orden da otro cifrado.

| # | Pieza | Cómo se obtiene | Por qué se puede invertir |
| --- | --- | --- | --- |
| 1 | S-box de 4 bits | Barajar 0 a 15 (Fisher-Yates) hasta que no tenga puntos fijos | Es una permutación: su inversa es otra tabla |
| 2 | Permutación de 64 bits | Barajar 0 a 63 hasta que cumpla la condición de los nibbles | Es una permutación: su inversa es otra tabla |
| 3 | 10 rotaciones | `1 + next() % 63`: entre 1 y 63 | Se rota hacia el otro lado |
| 4 | 10 multiplicadores | `next() \| 1`: impar | Todo impar tiene inverso módulo 2^64 |
| 5 | 11 subclaves | `next()` | El XOR se deshace con el mismo XOR |

### El generador

Se usan splitmix64 (para pasar de 128 bits de clave a 256 bits de estado) y xoshiro256\*\* (para generar). Son algoritmos públicos definidos bit por bit, así que dan exactamente lo mismo en cualquier compilador. **No se usa `rand`, `std::mt19937` ni `std::shuffle`**: su salida puede cambiar entre compiladores o bibliotecas, y entonces un texto cifrado en una máquina no se podría descifrar en otra.

### S-box sin puntos fijos

Se descartan las S-boxes con algún `sbox[x] == x`, porque ese nibble pasaría sin cambio. Para la clave `0123456789ABCDEF` la S-box resultante es `4DE8BC23615F7A90`.

### La condición de los nibbles

La permutación se acepta solo si **los 4 bits de cada nibble van a 4 nibbles distintos** (`perm[4n+k] / 4` distintos para k = 0..3). La salida de una S-box son 4 bits que dependen fuertemente entre sí. Si dos de ellos cayeran en la misma S-box de la ronda siguiente, esa S-box recibiría información "repetida" y la difusión sería más lenta. Con la condición, cada S-box alimenta a cuatro S-boxes distintas. La permutación de PRESENT cumple esta misma propiedad, y hay una prueba que lo verifica (`KeySchedule::spreadsNibbles`).

Cuántas barajadas hacen falta, medido con las 5 claves de prueba:

| Clave | Intentos S-box | Intentos permutación |
| --- | --- | --- |
| 16 bytes `0x00` | 8 | 103 |
| 16 bytes `0xFF` | 2 | 17 |
| `0123456789ABCDEF` | 3 | 243 |
| `a` (rellena con ceros) | 4 | 205 |
| aleatoria (`mt19937_64(99)`) | 6 | 150 |

El límite de seguridad es `MAX_TABLE_ATTEMPTS` = 1 000 000. Si se superara, `expand` lanza `std::runtime_error`, pero en la práctica hacen falta del orden de cientos.

### La multiplicación por un impar y su inverso

Un número par comparte el factor 2 con 2^64, así que ningún número multiplicado por él puede dar 1: no tiene inverso. Por eso el multiplicador siempre lleva `| 1`. El inverso se calcula **sin divisiones**, con la iteración de Newton (`Tables::modInverse`):

```text
inv = m                       // para todo impar, m * m == 1 (mod 8): ya es correcto en 3 bits
repetir 5 veces:
    inv = inv * (2 - m * inv) // cada vuelta duplica los bits correctos: 3, 6, 12, 24, 48, 96
```

Todo es `uint64_t`, así que el "módulo 2^64" lo hace solo el desbordamiento sin signo (que en C++ está bien definido).

---

## Modo CBC, relleno y formatos

- **Relleno PKCS#7 (bloque de 8):** se agregan `n = 8 - (largo % 8)` bytes con valor `n`, de 1 a 8. Un mensaje cuyo largo es múltiplo de 8 recibe un bloque completo de `0x08`, así al quitarlo nunca hay duda.
- **CBC:** `C[0] = IV`, `C[i] = E(P[i] XOR C[i-1])`. Al descifrar, `P[i] = D(C[i]) XOR C[i-1]`. Gracias al encadenamiento, dos bloques iguales del mensaje producen bloques cifrados distintos. Hay una prueba con `AAAAAAAAAAAAAAAAAAAAAAAA` (3 bloques iguales) que produce 3 bloques cifrados distintos, que es la razón para no usar ECB.
- **IV:** 8 bytes aleatorios de `std::random_device`. No es secreto y va al inicio de la salida. Por eso cifrar dos veces el mismo texto da dos resultados distintos.
- **Formato cifrado:** `IV (8 bytes) || C[1] ... C[n]`, de `8 + largo con relleno` bytes. En texto se muestra en hexadecimal en mayúsculas. Al leer se ignoran espacios y saltos de línea y se aceptan minúsculas.
- **Clave de usuario:** de 1 a 16 bytes de texto (rellenos con `0x00`), o exactamente 32 dígitos hexadecimales. No hay ambigüedad, porque un texto mide a lo mucho 16 y una clave hexadecimal 32. Cualquier otra cosa da un error claro.
- **Límite de texto:** la capa de texto y la GUI rechazan más de 100 **bytes** (una letra con acento ocupa 2 bytes en UTF-8). El núcleo cifra archivos de cualquier tamaño.
- **Clave equivocada:** casi siempre el relleno sale inválido y el programa da un error. A veces sale válido por azar y se obtiene basura sin error. Nunca se recupera el texto original.

---

## Resultados medidos

### Efecto avalancha

Salida real de `ciber avalanche`, con la clave `0123456789ABCDEF` y `std::mt19937_64(12345)`:

```text
Avalancha de texto plano: 32.01 bits de 64 (1000 bloques x 64 bits volteados)
Avalancha de clave:       32.04 bits de 64 (50 bloques x 128 bits de clave volteados)
Ideal: 32 bits. Aceptable: de 28 a 36. Tiempo: 0.11 s
```

Voltear **un solo bit** del texto plano cambia en promedio 32.01 de los 64 bits del cifrado, y voltear un bit de la clave cambia 32.04. Las dos cifras están prácticamente en el ideal de 32 (la mitad). El criterio de aceptación era de 28 a 36.

### Las tablas cambian con la clave

| Clave | S-box derivada |
| --- | --- |
| `0123456789ABCDEF` | `4DE8BC23615F7A90` |
| `otra clave` | `3C0D26A9EB158F47` |
| `00112233445566778899AABBCCDDEEFF` | `9BCE0F4A125378D6` |

---

## Cómo compilar

Requisitos: un compilador de C++17 (probado con MinGW GCC 13.1 de CLion y GCC 14.2 de MSYS2) y Python 3 con Tkinter para la interfaz.

### Con g++ (desde la raíz de este repositorio)

```bash
# Programa de línea de comandos
g++ -std=c++17 -Wall -Wextra -I. *.cpp -o ciber -static -lshell32

# Pruebas: todos los .cpp menos main.cpp
g++ -std=c++17 -Wall -Wextra -I. tests/test_main.cpp Avalanche.cpp Block.cpp BlockCipher.cpp Cbc.cpp \
    Encoding.cpp KeySchedule.cpp Padding.cpp Prng.cpp SPN.cpp Tables.cpp TextCipher.cpp txtToBinary.cpp \
    -o ciber_tests -static
```

`-lshell32` solo hace falta en Windows (la CLI lee los argumentos en UTF-8 con `CommandLineToArgvW`). `-static` hace que `ciber.exe` corra sin las DLL de MinGW en el `PATH`, que es lo que necesita la GUI.

### Con CMake y CLion

En el proyecto de CLion, este repositorio es la carpeta `CypherAlgorithm/` y el `CMakeLists.txt` está en la carpeta de arriba. Si no lo tienes, créalo ahí con este contenido:

```cmake
cmake_minimum_required(VERSION 3.16)
project(ciber CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(cipher_core STATIC
        CypherAlgorithm/txtToBinary.cpp CypherAlgorithm/Block.cpp CypherAlgorithm/SPN.cpp
        CypherAlgorithm/Prng.cpp CypherAlgorithm/Tables.cpp CypherAlgorithm/KeySchedule.cpp
        CypherAlgorithm/BlockCipher.cpp CypherAlgorithm/Padding.cpp CypherAlgorithm/Cbc.cpp
        CypherAlgorithm/Encoding.cpp CypherAlgorithm/TextCipher.cpp CypherAlgorithm/Avalanche.cpp)
target_include_directories(cipher_core PUBLIC CypherAlgorithm)
if(NOT MSVC)
    target_compile_options(cipher_core PUBLIC -Wall -Wextra)
endif()

add_executable(ciber CypherAlgorithm/main.cpp)
target_link_libraries(ciber PRIVATE cipher_core)
if(WIN32)
    target_link_libraries(ciber PRIVATE shell32)
endif()

enable_testing()
add_executable(ciber_tests CypherAlgorithm/tests/test_main.cpp)
target_link_libraries(ciber_tests PRIVATE cipher_core)
add_test(NAME ciber_tests COMMAND ciber_tests)

if(MINGW)
    target_link_options(ciber PRIVATE -static)
    target_link_options(ciber_tests PRIVATE -static)
endif()
```

En CLion: *Reload CMake Project*, compilar los objetivos `ciber` y `ciber_tests`, y correr `ciber_tests`.

---

## Cómo usar

### Línea de comandos

| Comando | Qué hace |
| --- | --- |
| `ciber enc-text "<texto>" <clave>` | Cifra un texto (máx. 100 bytes) e imprime el hexadecimal |
| `ciber dec-text <hex> <clave>` | Descifra el hexadecimal e imprime el texto |
| `ciber enc <entrada> <salida> <clave>` | Cifra un archivo; la salida es binaria (`IV \|\| cifrado`) |
| `ciber dec <entrada> <salida> <clave>` | Descifra un archivo |
| `ciber tables <clave>` | Muestra la S-box, la permutación, las rotaciones, los multiplicadores y las subclaves |
| `ciber avalanche` | Mide la avalancha de texto plano y de clave |

Devuelve 0 si todo va bien y 1 si hay cualquier error. Los errores van a `stderr` y en ese caso no se escribe nada en `stdout`. Se rechaza una salida igual a la entrada, un texto de más de 100 bytes, una clave o un hexadecimal inválidos y un archivo inexistente. Si el descifrado de un archivo falla, no se escribe ningún archivo de salida.

Ejemplo real (el hexadecimal cambia en cada ejecución por el IV aleatorio):

```text
> ciber enc-text "Hola mundo" 0123456789ABCDEF
13314975EFC8F2DBCCC5624252DC15A12B24B20CBB39CF9A
> ciber dec-text 13314975EFC8F2DBCCC5624252DC15A12B24B20CBB39CF9A 0123456789ABCDEF
Hola mundo
> ciber dec-text 13314975EFC8F2DBCCC5624252DC15A12B24B20CBB39CF9A 0123456789ABCDEG
Error: no se pudo descifrar: la clave es incorrecta o el cifrado esta danado
```

Los 48 dígitos hexadecimales son 24 bytes: 8 del IV más 16 del mensaje (10 bytes de "Hola mundo" más 6 de relleno).

La consola de Windows muestra la `ó` como `├│`. No es un error de datos: compara archivos con `fc /b`, no a ojo.

### Interfaz gráfica

```bash
python gui/ciber_gui.py
```

La interfaz no contiene nada del algoritmo: cada botón ejecuta `ciber`. La ruta de `ciber.exe` está en el campo de arriba. Por defecto toma el compilado más reciente de `cmake-build-debug`, `cmake-build-release` o `cmake-build-claude`.

| Elemento | Qué hace |
| --- | --- |
| Clave | 1 a 16 caracteres o 32 dígitos hexadecimales |
| Texto original | Con contador de bytes; se pone en rojo después de 100 |
| `Cifrar ↓` | Cifra el texto y muestra el hexadecimal abajo |
| Texto cifrado | Editable: se puede pegar un cifrado, incluso partido en líneas |
| `Descifrar ↑` | Descifra el cuadro de abajo y muestra el texto arriba |
| `Abrir archivo` / `Guardar resultado` | Cada cuadro tiene los suyos, junto a su título: arriba cargan o guardan el texto original y abajo el texto cifrado (hexadecimal), en UTF-8 |
| `Ver tablas` | Muestra las tablas de la clave escrita, para enseñar que cambian con la clave |

Los errores (clave inválida, hexadecimal inválido, clave equivocada, texto de más de 100 bytes) se muestran en un mensaje, sin cerrar el programa.

---

## Cómo se probó

`ciber_tests` corre **229 comprobaciones** sin dependencias externas (un marco `CHECK` propio), con 0 advertencias de compilación con `-Wall -Wextra`:

| Grupo | Qué comprueba |
| --- | --- |
| Block, txtToBinary | Vectores fijos, ida y vuelta, `ó` como 195 179, `\r\n`, archivo vacío, excepciones |
| Prng | Vector publicado de splitmix64 (`0xE220A8397B1DCDAF`), determinismo, semillas distintas dan secuencias distintas |
| Tables | Vectores de `modInverse`; `m * modInverse(m) == 1` para 1000 impares; inversión de tablas; tablas inválidas |
| SPN | Vectores con la S-box y la permutación de PRESENT; ida y vuelta de 10 000 valores; la permutación conserva el número de unos; rotaciones |
| KeySchedule | Para 5 claves: S-box sin puntos fijos, condición de los nibbles, rotaciones de 1 a 63, impares con inverso, 11 subclaves, determinismo, claves distintas dan tablas distintas |
| BlockCipher | Ida y vuelta de 10 000 bloques por clave; una clave que difiere en 1 bit no descifra; vectores de regresión |
| Padding, Cbc | Largos de relleno; rellenos inválidos; ida y vuelta de 0 a 64, 100 y 1000 bytes; IV distintos dan cifrados distintos; 3 bloques iguales cifran distinto |
| Encoding, TextCipher | Hexadecimal con espacios y minúsculas; claves válidas e inválidas; 100 bytes sí y 101 no; clave equivocada nunca da el original |
| Avalancha | Los dos promedios entre 28 y 36, en menos de 10 s |

**Vectores cruzados.** Como el cifrado es nuestro, no existen vectores publicados. Para no depender solo de nuestro propio código, se escribió aparte una implementación independiente de la especificación en Python (no incluida en el repositorio). Las tablas derivadas (S-box, permutación, rotaciones, multiplicadores, subclaves y número de intentos) y los cifrados de 3 bloques con 3 claves coinciden exactamente con los del C++, y se guardaron como pruebas de regresión.

**Pruebas de aceptación de la CLI.** Cifrar y descifrar `text.txt` (`m de megalodón`, 15 bytes) con clave de texto y con clave hexadecimal; archivo vacío (16 bytes de cifrado: IV más un bloque de relleno); archivo con `\r\n`; texto de 100 bytes. `fc /b` no encontró diferencias. También se comprobó que cada error devuelve 1 y deja `stdout` vacío.

**GUI.** Las funciones que llaman a `ciber` se probaron sin abrir la ventana: cifrar, descifrar, hexadecimal pegado con espacios, acentos en el texto y en la clave, clave equivocada, límite de 100 bytes, tablas distintas y ejecutable inexistente. También se construyó la ventana y se probaron los botones `Cifrar` y `Descifrar`. La lista de comprobación a mano está en el guion.

---

## Limitaciones y ataques

KDSPN-64 sirve para aprender cómo se construye un cifrado, no para proteger nada. Sus debilidades conocidas:

1. **El generador no es criptográfico y es invertible.** Las subclaves son salidas directas de xoshiro256\*\*, cuya función de salida se puede invertir. Con unas cuantas subclaves consecutivas se reconstruye el estado del generador y, de ahí, todas las tablas. Como splitmix64 también es invertible, **se llega hasta la clave**. Un cifrado real derivaría las tablas con una función criptográfica (por ejemplo, un hash o un cifrado ya probado).
2. **S-boxes al azar.** Solo se descartan las que tienen puntos fijos. Una S-box barajada al azar puede tener malas propiedades diferenciales o lineales, mientras que la de PRESENT se eligió a propósito contra esos ataques. Algunas claves pueden dar cifrados más débiles que otras.
3. **Criptoanálisis diferencial y lineal.** Con 10 rondas de un diseño sin análisis formal, no hay garantía de resistencia. Nadie ha calculado las mejores características diferenciales de este cifrado.
4. **Bloque de 64 bits.** Por la paradoja del cumpleaños, tras unos 2^32 bloques (32 GB) cifrados con la misma clave empiezan a repetirse bloques en CBC, lo que filtra información (ataques tipo Sweet32).
5. **CBC no autentica.** No detecta si alguien modificó el cifrado: cambiar un bit del IV cambia el mismo bit del primer bloque descifrado.
6. **Oráculo de relleno.** El programa responde distinto a un relleno inválido que a uno válido. Un atacante que pueda pedir descifrados y ver la respuesta puede recuperar el texto byte por byte (ataque de Vaudenay, 2002).
7. **Claves de texto.** Una clave de texto corta tiene mucho menos de 128 bits de entropía y se rompe por fuerza bruta. No hay función de derivación de claves (KDF) ni sal.
8. **El efecto avalancha no demuestra seguridad.** Que la avalancha dé 32 bits es necesario pero no suficiente: un cifrado puede tener buena avalancha y aun así romperse.

---

## Relación con la rúbrica

Esta tabla se armó con los requisitos que cita la guía del proyecto. Conviene cotejarla con la rúbrica oficial.

| Criterio | Dónde se cubre |
| --- | --- |
| Al menos 2 operaciones de confusión | XOR con subclave y S-box (más la multiplicación): [La ronda](#la-ronda), `SPN.cpp`, `BlockCipher.cpp` |
| Al menos 2 operaciones de difusión | Permutación de bits y rotación (más la multiplicación): [La ronda](#la-ronda), `SPN.cpp` |
| El descifrado invierte las operaciones | [Descifrado](#descifrado), `BlockCipher::decryptBlock`; ida y vuelta probada con 10 000 bloques por clave |
| Cifrar texto de hasta 100 caracteres | `TextCipher`, `ciber enc-text`, GUI (límite de 100 bytes) |
| Cifrar archivos | `ciber enc` y `ciber dec`, verificado con `fc /b` |
| Clave de 128 bits | [Parámetros](#parámetros), `Encoding::parseKey` |
| Interfaz gráfica | `gui/ciber_gui.py`, [Interfaz gráfica](#interfaz-gráfica) |
| Evidencia de difusión | [Efecto avalancha](#efecto-avalancha): 32.01 y 32.04 bits de 64 |
| Pruebas | [Cómo se probó](#cómo-se-probó), `tests/test_main.cpp` |
| Manual técnico | Este README |
| Presentación | [Guion de presentación](#guion-de-presentación-5-minutos) |

---

## Guion de presentación (5 minutos)

Antes de empezar, compila `ciber` en CLion, abre una terminal en la carpeta del ejecutable y ten la GUI cerrada.

**0:00 a 0:45: objetivo y qué lo hace distinto.**
"KDSPN-64 es una red de sustitución-permutación de 64 bits con clave de 128. Lo distinto es que la clave no solo se mezcla con XOR: decide cómo está construido el cifrado. De la clave salen la S-box, la permutación de bits, las rotaciones y los multiplicadores. Dos claves distintas son dos cifrados distintos. Blowfish y Twofish hacen algo parecido con S-boxes que dependen de la clave."

**0:45 a 2:00: el diseño de la ronda.**
Mostrar la tabla de [La ronda](#la-ronda). Explicar las 5 operaciones y el blanqueo final. Remarcar dos cosas: por qué la multiplicación necesita la rotación (los bits altos nunca bajan) y cómo se invierte todo (permutaciones con su tabla inversa, impares con su inverso por Newton, XOR consigo mismo). Mencionar la condición de los nibbles de la permutación.

**2:00 a 3:00: confusión, difusión y avalancha.**
"Hay tres operaciones de confusión y dos de difusión. La evidencia de que la difusión funciona es la avalancha":

```text
ciber avalanche
```

"Voltear un bit del texto cambia 32.01 de 64 bits del cifrado, y voltear un bit de la clave cambia 32.04. El ideal es 32, la mitad."

**3:00 a 4:30: demostración en vivo.**

```text
ciber enc-text "Hola mundo" 0123456789ABCDEF
ciber enc-text "Hola mundo" 0123456789ABCDEF      (otro hexadecimal: el IV es aleatorio)
ciber dec-text <HEX> 0123456789ABCDEF              -> Hola mundo
ciber dec-text <HEX> 0123456789ABCDEG              -> error: clave incorrecta
ciber tables 0123456789ABCDEF                      -> S-box 4DE8BC23615F7A90
ciber tables "otra clave"                          -> S-box 3C0D26A9EB158F47
```

Después abrir la GUI (`python gui/ciber_gui.py`): cifrar y descifrar "Hola mundo" y abrir `Ver tablas` con dos claves.

**4:30 a 5:00: limitaciones y cierre.**
"Es un cifrado de juguete: el generador de tablas no es criptográfico y desde unas subclaves se puede llegar a la clave; las S-boxes al azar no tienen garantías contra criptoanálisis diferencial; el bloque de 64 bits limita cuánto se puede cifrar con una clave; y CBC no autentica. Lo que sí muestra es cómo se construye un SPN, cómo se invierte y cómo se mide la difusión."

### Lista de comprobación a mano de la GUI

- [ ] Cifrar `Hola mundo` con la clave `0123456789ABCDEF` muestra un hexadecimal
- [ ] Descifrar ese hexadecimal con la misma clave devuelve `Hola mundo`
- [ ] Una clave equivocada muestra un mensaje de error o un texto distinto, sin cerrar el programa
- [ ] Más de 100 bytes de texto se rechazan con un mensaje
- [ ] `Ver tablas` con dos claves distintas muestra S-boxes distintas

---

## Preguntas probables

**1. ¿Por qué derivar la S-box de la clave en vez de usar una fija?**
Para que la estructura del cifrado sea secreta y cambie con cada clave: el atacante no conoce ni la S-box ni la permutación. Es la idea de Blowfish y Twofish. El costo es que no se puede garantizar que cada S-box sea buena, como sí pasa con la de PRESENT, que se eligió con cuidado.

**2. Si las tablas son aleatorias, ¿cómo se garantiza que se pueda descifrar?**
Por tres razones. Todas las piezas son invertibles: la S-box y la permutación son permutaciones (con tabla inversa), los multiplicadores son impares (tienen inverso módulo 2^64) y el XOR se deshace con sí mismo. Además, el generador es determinista: la misma clave produce exactamente las mismas tablas al cifrar y al descifrar. Y no se usa `rand` ni `mt19937`, que podrían cambiar entre compiladores.

**3. ¿Por qué el multiplicador tiene que ser impar y cómo se calcula su inverso?**
Un par comparte el factor 2 con 2^64 y no tiene inverso. Con `| 1` se fuerza el bit más bajo a 1. El inverso se calcula con la iteración de Newton `inv = inv * (2 - m * inv)`, que parte de 3 bits correctos y duplica en cada vuelta; con 5 vueltas se cubren los 64 bits, sin ninguna división.

**4. ¿Qué es la condición de los nibbles?**
Que los 4 bits que salen de cada S-box vayan a 4 S-boxes distintas en la ronda siguiente. Así la salida de una S-box se reparte por el bloque en vez de concentrarse. Se aplica al generar la permutación: se baraja hasta cumplirla, y con las claves de prueba hicieron falta entre 17 y 243 intentos.

**5. ¿Por qué CBC y no ECB? ¿El IV no tiene que ser secreto?**
En ECB, dos bloques iguales del mensaje dan dos bloques cifrados iguales, y se ven patrones. En CBC cada bloque se mezcla con el cifrado anterior: la prueba con 3 bloques de `A` da 3 bloques cifrados distintos. El IV no es secreto, solo debe ser impredecible; va al inicio del cifrado y hace que el mismo texto cifre distinto cada vez.

**6. ¿Qué mide la avalancha y qué resultado obtuvieron?**
Cuántos bits del cifrado cambian al voltear un solo bit de la entrada o de la clave. Lo ideal es la mitad (32 de 64). Se obtuvo 32.01 para el texto plano (1000 bloques) y 32.04 para la clave (50 bloques por 128 bits), con la semilla fija 12345 para que sea reproducible.

**7. ¿Es seguro? ¿Cómo lo atacarían?**
No. El ataque más directo es contra el generador: las subclaves salen directo de xoshiro256\*\*, que es invertible, así que con unas cuantas subclaves se reconstruye el estado y se llega a la clave. Además, las S-boxes al azar podrían tener debilidades diferenciales, el bloque de 64 bits limita el volumen cifrado (Sweet32), CBC no detecta modificaciones y el mensaje de relleno inválido permite un ataque de oráculo de relleno.

**8. ¿Qué pasa si se descifra con la clave equivocada?**
Lo normal es que el relleno PKCS#7 salga inválido y el programa dé un error. Con probabilidad baja el relleno sale válido por azar y se obtiene basura sin error. Nunca se recupera el original: hay pruebas que intentan cientos de descifrados con una clave que difiere en un solo carácter.
