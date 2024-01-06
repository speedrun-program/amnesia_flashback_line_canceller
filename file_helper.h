
#include <stdio.h>

class FileHelper {
public:
    FILE* f = nullptr;
    size_t bufferPosition = 0;
    size_t charactersRead = 0;
    unsigned char buffer[4096] = {};

    FileHelper(const FileHelper& fhelper) = delete;
    FileHelper& operator=(FileHelper other) = delete;
    FileHelper(FileHelper&&) = delete;
    FileHelper& operator=(FileHelper&&) = delete;


    FileHelper(const char* fileName) {
#ifdef _WIN32
        if (fopen_s(&f, fileName, "rb") != 0 || !f) {
#else
        if (!(_f = fopen(fileName, "rb"))) {
#endif
            printf("FileHelper couldn't open %s\n", fileName);
            return;
        }
    }


    ~FileHelper() {
        if (f) {
            fclose(f);
        }
    }


    bool getCharacter(char* ch) {
        if (bufferPosition == charactersRead) {
            bufferPosition = 0;
            charactersRead = fread(buffer, 1, sizeof(buffer), f);

            if (!charactersRead) {
                return false;
            }
        }

        *ch = buffer[bufferPosition];
        bufferPosition += 1;

        return true;
    }
};
