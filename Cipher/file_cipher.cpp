#include <iostream>
#include <fstream>
#include <string>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/sha.h>
#include <crypto++/pwdbased.h>
#include <crypto++/osrng.h>
#include <crypto++/files.h>

using namespace std;
using namespace CryptoPP;

void DeriveKey(const string& password, byte* key) {
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Генерация ключа с помощью PBKDF2
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, AES::DEFAULT_KEYLENGTH, 0, 
                   (const byte*)password.data(), password.size(),
                   salt, sizeof(salt), 1000);
}

bool EncryptFile(const string& input_file, const string& output_file, const string& password) {
    try {
        byte key[AES::DEFAULT_KEYLENGTH];
        DeriveKey(password, key);
        
        AutoSeededRandomPool rnd;
        byte iv[AES::BLOCKSIZE];
        rnd.GenerateBlock(iv, sizeof(iv));
        
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        ofstream out_file(output_file, ios::binary);
        if (!out_file) {
            cerr << "Ошибка: не удается создать файл " << output_file << endl;
            return false;
        }
        
        out_file.write(reinterpret_cast<const char*>(iv), sizeof(iv));
        
        FileSource fs(input_file.c_str(), true,
            new StreamTransformationFilter(encryption,
                new FileSink(out_file),
                StreamTransformationFilter::PKCS_PADDING
            )
        );
        
        cout << "Файл зашифрован: " << output_file << endl;
        return true;
        
    } catch(const exception& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
        return false;
    }
}

bool DecryptFile(const string& input_file, const string& output_file, const string& password) {
    try {
        byte key[AES::DEFAULT_KEYLENGTH];
        DeriveKey(password, key);
        
            ifstream in_file(input_file, ios::binary);
        if (!in_file) {
            cerr << "Ошибка: не удается открыть файл " << input_file << endl;
            return false;
        }
        
        byte iv[AES::BLOCKSIZE];
        in_file.read(reinterpret_cast<char*>(iv), sizeof(iv));
        
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        
        FileSource fs(in_file, true,
            new StreamTransformationFilter(decryption,
                new FileSink(output_file.c_str()),
                StreamTransformationFilter::PKCS_PADDING
            )
        );
        
        cout << "Файл расшифрован: " << output_file << endl;
        return true;
        
    } catch(const exception& e) {
        cerr << "Ошибка расшифрования: " << e.what() << endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cout << "Использование: " << argv[0] << " <режим> <входной_файл> <выходной_файл> <пароль>" << endl;
        cout << "Режимы:" << endl;
        cout << "  encrypt - зашифровать файл" << endl;
        cout << "  decrypt - расшифровать файл" << endl;
        return 1;
    }
    
    string mode = argv[1];
    string input_file = argv[2];
    string output_file = argv[3];
    string password = argv[4];
    
    ifstream test_file(input_file);
    if (!test_file.is_open()) {
        cerr << "Ошибка: входной файл не существует: " << input_file << endl;
        return 1;
    }
    test_file.close();
    
    if (mode == "encrypt") {
        return EncryptFile(input_file, output_file, password) ? 0 : 1;
    } else if (mode == "decrypt") {
        return DecryptFile(input_file, output_file, password) ? 0 : 1;
    } else {
        cerr << "Ошибка: неизвестный режим '" << mode << "'" << endl;
        return 1;
    }
}