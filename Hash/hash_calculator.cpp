#include <iostream>
#include <fstream>
#include <string>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/files.h>

using namespace std;
using namespace CryptoPP;

string CalculateFileHash(const string& filename) {
    try {
        SHA256 hash;
        string digest;
        
        FileSource file(filename.c_str(), true, 
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest)
                )
            )
        );
        
        return digest;
    }
    catch(const exception& e) {
        cerr << "Ошибка при вычислении хэша: " << e.what() << endl;
        return "";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Использование: " << argv[0] << " <имя_файла>" << endl;
        cout << "Пример: " << argv[0] << " document.txt" << endl;
        return 1;
    }
    
    string filename = argv[1];
    
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Ошибка: не удается открыть файл " << filename << endl;
        return 1;
    }
    file.close();
    
    cout << "Вычисление SHA-256 хэша для файла: " << filename << endl;
    string hash = CalculateFileHash(filename);
    
    if (!hash.empty()) {
        cout << "Хэш: " << hash << endl;
    } else {
        cerr << "Не удалось вычислить хэш" << endl;
        return 1;
    }
    
    return 0;
}