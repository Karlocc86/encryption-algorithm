//
// Capa de texto: lo que usan la linea de comandos y la interfaz grafica.
// Recibe texto y clave como los escribe el usuario y devuelve hexadecimal.
//

#ifndef CIBER_TEXTCIPHER_H
#define CIBER_TEXTCIPHER_H

#include <string>

class TextCipher {

public:
    /**
     * Cifra un texto de hasta MAX_TEXT_BYTES bytes con CBC y un IV aleatorio.
     * @param plain texto en claro (sus bytes tal cual, por ejemplo UTF-8)
     * @param key clave de 1 a 16 caracteres o de 32 digitos hexadecimales
     * @return IV y cifrado en hexadecimal (mayusculas)
     * @throws std::invalid_argument si el texto pasa de 100 bytes o la clave es invalida
     */
    static std::string encryptText(const std::string& plain, const std::string& key);

    /**
     * Descifra el hexadecimal que produjo encryptText.
     * @param hex IV y cifrado en hexadecimal (se ignoran espacios y saltos de linea)
     * @param key la misma clave con la que se cifro
     * @return el texto original
     * @throws std::invalid_argument si el hexadecimal o la clave son invalidos, si
     *         el largo no es 8 + 8k bytes, o si el relleno sale invalido (clave
     *         incorrecta o cifrado danado)
     */
    static std::string decryptText(const std::string& hex, const std::string& key);
};


#endif //CIBER_TEXTCIPHER_H
