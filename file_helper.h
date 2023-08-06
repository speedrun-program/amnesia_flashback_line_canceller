
#include <cstdio>
#include <memory>
#include <stdexcept>

const size_t fhelperBufferSize = 8192;

template <typename T>
class FileHelper
{
public:
    FileHelper(const FileHelper& fhelper) = delete;
    FileHelper& operator=(FileHelper other) = delete;
    FileHelper(FileHelper&&) = delete;
    FileHelper& operator=(FileHelper&&) = delete;

    explicit FileHelper(const wchar_t* filename) // there isn't wfopen on linux
    {
#ifndef _WIN32
        throw std::runtime_error("FileHelper wchar_t* constructor only works on Windows");
#else
        if (_wfopen_s(&_f, filename, L"rb") != 0 || !_f)
        {
            printf("FileHelper couldn't open %ls\n", filename);
            throw std::runtime_error("FileHelper fopen failure in const wchar_t* constructor");
        }
#endif
    }

    explicit FileHelper(const char* filename)
    {
#ifdef _WIN32
        if (fopen_s(&_f, filename, "rb") != 0 || !_f)
#else
        if (!(_f = fopen(filename, "rb")))
#endif
        {
            printf("FileHelper couldn't open %s\n", filename);
            throw std::runtime_error("FileHelper fopen failure in const char* constructor");
        }
    }

    ~FileHelper()
    {
        if (_f)
        {
            fclose(_f);
        }
    }

    bool getCharacter(T& ch)
    {
        if (_bufferPosition == _charactersRead)
        {
            _bufferPosition = 0;
            _charactersRead = (int)fread(_buffer.get(), sizeof(T), fhelperBufferSize / sizeof(T), _f);

            if (!_charactersRead)
            {
                return false;
            }
        }

        ch = _buffer[_bufferPosition];
        _bufferPosition++;

        return true;
    }

    void resetFile()
    {
        if (fseek(_f, 0, SEEK_SET) != 0)
        {
            throw std::runtime_error("FileHelper fseek failure in resetFile");
        }

        _bufferPosition = 0;
        _charactersRead = 0;
    }

private:
    FILE* _f = nullptr;
    std::unique_ptr<T[]> _buffer = std::make_unique<T[]>(fhelperBufferSize / sizeof(T));
    int _bufferPosition = 0;
    int _charactersRead = 0;
};
