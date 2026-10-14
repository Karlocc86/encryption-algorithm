//
// Created by sebas on 14/10/2026.
//

#include "txtToBinary.h"
#include <fstream>
#include <stdexcept>
#include <iterator>

std::vector<uint8_t> txtToBinary::leerArchivo(const std::string &ruta) {
    std::ifstream f(ruta, std::ios::binary); //Input File Stream -> lee datos de un archivo
    //ios::binary siendo el modo de apertura, en este caso
    //lo abre como binario puro para evitar conversiones y los char
    //se traten como su binario directo (8 bits {0 - 255}).

    if (!f) throw std::runtime_error("Por x o y razon no se pudo abrir el archivo: " + ruta); 

    //(std::istreambuf_iterator<char>(f) , {}) | resumen -> es un iterador que comienza con el primer byte de [f] siendo
    //el iterador de inicio, en cada paso (++) va a extrar cualquier <char> del archivo f que le pasamos, {} es un iterador
    //por defecto que por convenio marca el fin del archivo (EOF).
    // {} = constructor por defecto deducido por el compilador; en este iterador equivale a istreambuf_iterator<char>()
    // {} = inicialización por defecto (value initialization): el compilador deduce el tipo esperado y llama a su constructor vacío T()
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});


}

void txtToBinary::escribirArchivo(const std::string &ruta, const std::vector<uint8_t> &datos) {

    //Recordatorio: operar con el modo de apertura en binario (ios::binary) ayuda a que el OS no altere los
    //datos, sobretodo los saltos de linea y se consideren directamente como su binario (10).
    //Se hace porque por ejemplo yo con windows el \n = (10) el salto completo es \r\n = (13 10)
    //siendo dos bytes
    std::ofstream f(ruta,std::ios::binary);

    if (!f) {
        throw std::runtime_error("No se pudo abrir el txt: "+ ruta);
    }

    //firma de write -> std::ostream& write(const char* s, std::streamsize n);
    //  s = siendo donde deberia empezar a escribir o direccion del primer bloque de
    //  bytes

    //  n = siendo cuantos bytes debe de escribit en el archivo

    //datos -> vector -> un vector es un objeto
    //vector en si solo guarda 3 cosas:
    //1: puntero al inicio de a memoria del heap -> .data() me da esto
    //2: un puntero del final del ultimo elemento del vector -> se usa para conseguir .size()
    //3. un puntero al final de la memoria reservada

    // reinterpret_cast<const char *> -> como el compilador a fuerzas requiere <char *>,
    // vector en si tiene elementos <uint8_t> asi que reinterpret_cast<const char *> hace eso
    // que uint8_t se vea como <char> -> los * (punteros) surgen de la llamada de .data() y
    // recorrer los elementos por direccion

    // streamsize = En C++, std::streamsize es un tipo de dato entero con signo definido en la cabecera
    // por eso la necesidad del cast
    f.write(reinterpret_cast<const char *> (datos.data()),
        static_cast<std::streamsize>(datos.size()));

    //Checamos por si por alguna razon no pudo hacer el trabajo de escribir

    if (!f) throw std::runtime_error("Hubo un error en la escritura de: " + ruta);

}


