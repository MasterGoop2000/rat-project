#include <Winsock2.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>

std::vector<std::string> obfAlpha = { "apple", "banana", "cherry", "database", "elephant", "falcon", "galaxy", "horizon", "igloo", "jaguar", "kangaroo", "lantern", "matrix", "neuron", "octane", "phantom", "quantum", "radar", "shadow", "titanium", "universe", "vortex", "wisdom", "xenon", "yogurt", "zephyr", "Avalanche", "Blizzard", "Cyclone", "Diamond", "Eclipse", "Firewall", "Glacier", "Hurricane", "Iceberg", "Jupiter", "Kinetic", "Lightning", "Moonlight", "Nebula", "Oceanic", "Pinnacle", "Quasar", "Radiant", "Sapphire", "Tornado", "Uutrium", "Velocity", "Wavelength", "Xylophone", "Yosemite", "Zenith", "1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "0th", "!excleamation", "@meneation", "#hashadtag", "$dolleasar", "%perceeadnt", "^careaset", "&ampeasfrsafnd", "*asteasfdasdrisk", "(parenaweadsasfthesis", ")closweasdfe_bracket", "-daawfsh", "=equeasals", "\\bacakfdslash", "/slaasdfash", ".dwdot", "'ap2osteropfhe", "\"thingy", " space", ":omfd"};

std::string deObfAlpha(std::vector<std::string> vec) {
    std::string buf;
    for (size_t i = 0; i < vec.size(); i++) {
        buf += vec[i].front();
    }
    return buf;
}

std::string encryptCaesar(const std::string& plaintext, const std::string& alphabet, int key) {
    std::string ciphertext = "";
    size_t algoLength = alphabet.length();
    for (size_t i = 0; i < plaintext.length(); i++) {
        char target = plaintext[i];
        size_t pos = alphabet.find(target);
        if (pos != std::string::npos) {
            size_t newPos = (pos + key) % algoLength;
            ciphertext += alphabet[newPos];
        }
        else {
            ciphertext += target;
        }
    }
    return ciphertext;
}

std::vector<int> obfuscate(const std::string& alpha, const std::string& word) {
    std::vector<int> result;
    for (size_t i = 0; i < word.length(); i++) {
        for (size_t d = 0; d < alpha.length(); d++) {
            if (alpha[d] == word[i]) {
                result.push_back(static_cast<int>(d));
                break; 
            }
        }
    }
    return result;
}

std::vector<int> vectorMultiply(std::vector<int> orgVec, int key) {
    std::vector<int> submit = orgVec;
    for (size_t i = 0; i < orgVec.size(); i++) {
        submit[i] *= key;
    }
    return submit;
}

std::vector<int> talbotEncrypt(std::string input, int caeserCipher, int coefficient) {
    std::string alphabet = deObfAlpha(obfAlpha);
    std::string cWord = encryptCaesar(input, alphabet, caeserCipher);
    std::vector<int> vWord = obfuscate(alphabet, cWord);
    std::vector<int> product = vectorMultiply(vWord, coefficient);
    return product;
}

std::vector<int> vectorDivide(std::vector<int> input, int coefficient) {
    std::vector<int> product = input;
    for (size_t i = 0; i < product.size(); i++) {
        product[i] /= coefficient;
    }
    return product;
}

std::string orgStr(const std::string& alpha, const std::vector<int>& obj) {
    std::string str;
    for (size_t i = 0; i < obj.size(); i++) {
        if (obj[i] >= 0 && static_cast<size_t>(obj[i]) < alpha.length()) {
            str += alpha[obj[i]];
        }
    }
    return str;
}

std::string decryptCaesar(const std::string& ciphertext, const std::string& alphabet, int key) {
    std::string plaintext;
    size_t algoLength = alphabet.length();
    for (size_t i = 0; i < ciphertext.length(); i++) {
        char target = ciphertext[i];
        size_t pos = alphabet.find(target);
        if (pos != std::string::npos) {
            size_t newPos = (pos - key % algoLength + algoLength) % algoLength;
            plaintext += alphabet[newPos];
        }
        else {
            plaintext += target;
        }
    }
    return plaintext;
}

std::string talbotDecrypt(std::vector<int> input, int caeserCipher, int coefficient) {
    std::string alphabet = deObfAlpha(obfAlpha);
    std::vector<int> product = vectorDivide(input, coefficient);
    std::string vWord = orgStr(alphabet, product);
    std::string cWord = decryptCaesar(vWord, alphabet, caeserCipher);
    return cWord;
}

int main() {
    std::string name = "WSAStartup";
    int increment = 1;
    int coefficient = 23;
    std::vector<int> wsa = talbotEncrypt(name, increment, coefficient);
    std::cout << "std::vector<int> " << "r" << name << " = {";
    for (int i = 0; i < wsa.size(); i++) {
        std::cout << wsa[i] << ", ";
    }
    std::cout << "};\n\n";
    std::cout << "talbotDecrypt(" << "r" << name << ", " << increment << ", " << coefficient << ");" << std::endl;
    return 0;
}
