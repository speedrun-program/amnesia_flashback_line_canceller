
#ifndef DEBUG
#define stdprintf(...) (0)
#endif

static bool checkIfFileExists(const char* filename)
{
    FILE* fcheck = nullptr;

    try
    {
        bool exists = false;
#ifdef _WIN32
        fopen_s(&fcheck, filename, "rb");
#else
        fcheck = std::fopen(filename, "rb");
#endif

        if (fcheck)
        {
            std::fclose(fcheck);
            fcheck = nullptr;
            exists = true;
        }

        return exists;
    }
    catch (char const* e) // making sure fcheck gets closed if an error happens somehow
    {
        if (fcheck)
        {
            std::fclose(fcheck);
        }

        throw std::runtime_error(e);
    }
}

// char name[16 + 10 + 4 + 1] starts as "files_and_delays1.txt"
// 16: "files_and_delays"
// 10: number part
// 4: ".txt"
// 1: '\0'
static void findCorrectFileName(char* name)
{
    unsigned int fileNumber = 1;

    while (checkIfFileExists(name))
    {
        fileNumber++;
        auto [dottxt, ec] = std::to_chars(name + 16, name + 26, fileNumber);

        if (ec == std::errc::value_too_large || fileNumber == 0) // this probably won't ever happen
        {
            throw std::runtime_error("too many files_and_delays files");
        }

        dottxt[0] = '.'; dottxt[1] = 't'; dottxt[2] = 'x'; dottxt[3] = 't';
    }

    fileNumber--;
    auto [dottxt, _] = std::to_chars(name + 16, name + 26, fileNumber);
    // dottxt[4] might not be '\0'. for example, fileNumber decrements from 100 to 99
    dottxt[0] = '.'; dottxt[1] = 't'; dottxt[2] = 'x'; dottxt[3] = 't'; dottxt[4] = '\0';
}

class FileHelper
{
public:
    FileHelper(const FileHelper& fhelper) = delete;
    FileHelper& operator=(FileHelper other) = delete;
    FileHelper(FileHelper&&) = delete;
    FileHelper& operator=(FileHelper&&) = delete;

    explicit FileHelper(const char* filename)
    {
#ifdef _WIN32
        if (fopen_s(&_f, filename, "rb") != 0 || !_f)
#else
        if (!(_f = std::fopen(filename, "rb")))
#endif
        {
            stdprintf("ERROR: %s\n", filename);
            throw std::runtime_error("FileHelper fopen failure in constructor");
        }
    }

    ~FileHelper()
    {
        if (_f)
        {
            std::fclose(_f);
        }
    }

    bool getCharacter(wcharOrChar& ch)
    {
        if (_bufferPosition == _charactersRead)
        {
            _bufferPosition = 0;
            _charactersRead = (int)std::fread(_buffer.data(), sizeof(wcharOrChar), _buffer.size(), _f);

            if (!_charactersRead)
            {
                return false;
            }
        }

        ch = _buffer.at(_bufferPosition);
        _bufferPosition++;

        return true;
    }

    void resetFile() // used in tests
    {
        if (std::fseek(_f, 0, SEEK_SET) != 0)
        {
            throw std::runtime_error("FileHelper fseek failure in resetFile");
        }

        _bufferPosition = 0;
        _charactersRead = 0;
    }

private:
    FILE* _f = nullptr;
    std::vector<wcharOrChar> _buffer = std::vector<wcharOrChar>(8192 / sizeof(wcharOrChar));
    int _bufferPosition = 0;
    int _charactersRead = 0;
};

struct MapValue
{
    // delays[0] == -1 says to reset all MapValue.position to 0
    // delays ending with -1 says to reset at the end
    // delays ending with -2 says to NOT reset at the end
    std::unique_ptr<int[]> delays;
    size_t position = 0;
    size_t fullResetCheckNumber = 0;

    explicit MapValue(std::vector<int>& delaysVector) : delays(std::make_unique_for_overwrite<int[]>(delaysVector.size()))
    {
        std::memcpy(delays.get(), delaysVector.data(), delaysVector.size() * sizeof(int));
    }
};

struct KeyCmp
{
    using is_transparent = void;

    bool operator()(const uPtrType& cStr1, const uPtrType& cStr2) const
    {
        return cmpFunction(cStr1.get(), cStr2.get()) == 0;
    }

    bool operator()(const uPtrType& cStr, const svType sv) const
    {
        return cmpFunction(cStr.get(), sv.data()) == 0;
    }

    bool operator()(const svType sv, const uPtrType& cStr) const
    {
        return cmpFunction(sv.data(), cStr.get()) == 0;
    }
};

struct KeyHash
{
    using is_transparent = void;

    size_t operator()(const svType sv) const
    {
        return _hashObject(sv);
    }

    size_t operator()(const uPtrType& cStr) const
    {
        // if they add an easy way to do it, change this so it doesn't need to find the c-string length
        return _hashObject(svType(cStr.get()));
    }

private:
    std::hash<svType> _hashObject = std::hash<svType>();
};

using myMapType = std::unordered_map<uPtrType, MapValue, KeyHash, KeyCmp>;

class MapAndMutex
{
public:
    std::mutex mutexForMap;
    myMapType fileMap;

    MapAndMutex()
    {
        try
        {
            // intAsChars used in fillDelaysVector but made here so it doesn't need to be remade repeatedly
            std::vector<char> intAsChars;
            intAsChars.reserve(10);
            intAsChars.push_back('0'); // empty vector causes std::errc::invalid_argument
            vectorType keyVector;
            std::vector<int> delaysVector;
            char name[16 + 10 + 4 + 1] = "files_and_delays.txt";
            // 16: "files_and_delays"
            // 10: number part
            // 4: ".txt"
            // 1: '\0'

            if (checkIfFileExists("files_and_delays0.txt"))
            {
                char* nameEnd = name + 16;
                nameEnd[0] = '1'; nameEnd[1] = '.'; nameEnd[2] = 't'; nameEnd[3] = 'x'; nameEnd[4] = 't';
                findCorrectFileName(name);
            }

            FileHelper fhelper(name);
#ifdef _WIN32
            wchar_t byteOrderMark = '\0';

            if (!fhelper.getCharacter(byteOrderMark))
            {
                stdprintf(
                    "files_and_delays.txt byte order mark is missing\n\
make sure files_and_delays.txt is saved as UTF-16 LE\n"
);
            }
            else if (byteOrderMark != 0xFEFF) // not 0xFFFE due to how wchar_t is read
            {
                stdprintf(
                    "files_and_delays.txt byte order mark isn't marked as UTF-16 LE\n\
make sure files_and_delays.txt is saved as UTF-16 LE\n"
);
            }
#endif

            while (addMapPair(fileMap, keyVector, delaysVector, fhelper, intAsChars));
        }
        catch (const std::runtime_error& e)
        {
            char const* fixC4101Warning = e.what();
            stdprintf("%s\n", fixC4101Warning);
            fileMap.clear(); // clear map so failure is more obvious
        }
    }

    bool addMapPair(myMapType& fileMap, vectorType& keyVector, std::vector<int>& delaysVector, FileHelper& fhelper, std::vector<char>& intAsChars)
    {
        keyVector.clear();
        delaysVector.clear();
        wcharOrChar ch = '\0';
        bool stripWhitespace = false;
        bool textRemaining = fhelper.getCharacter(ch);

        if (ch == '/')
        {
            stripWhitespace = true;
            textRemaining = fhelper.getCharacter(ch);
        }
        else if (ch == ' ' || ch == '\f' || ch == '\r' || ch == '\t' || ch == '\v')
        {
            // don't include starting whitespace
            for (
                textRemaining = fhelper.getCharacter(ch);
                textRemaining && (ch == ' ' || ch == '\f' || ch == '\r' || ch == '\t' || ch == '\v');
                textRemaining = fhelper.getCharacter(ch));
        }

        while (ch != '\n' && ch != '/' && textRemaining)
        {
            keyVector.push_back(ch);
            textRemaining = fhelper.getCharacter(ch);
        }

        // don't include ending whitespace
        if (!stripWhitespace)
        {
            while (!keyVector.empty())
            {
                wcharOrChar endChar = keyVector.back();

                if (endChar == ' ' || endChar == '\f' || endChar == '\r' || endChar == '\t' || endChar == '\v')
                {
                    keyVector.pop_back();
                }
                else
                {
                    break;
                }
            }
        }

        if (textRemaining && ch == '/') // line didn't end abruptly
        {
            fillDelaysVector(textRemaining, delaysVector, fhelper, intAsChars);

            if (!keyVector.empty() && !delaysVector.empty())
            {
                if (delaysVector.back() != -1)
                {
                    delaysVector.push_back(-2);
                }

                keyVector.push_back('\0');
                uPtrType keyPtr = std::make_unique_for_overwrite<wcharOrChar[]>(keyVector.size());
                std::memcpy(keyPtr.get(), keyVector.data(), keyVector.size() * sizeof(wcharOrChar));
                fileMap.emplace(std::move(keyPtr), MapValue(delaysVector));
            }
        }

        return textRemaining;
    }

    // the -2 at the end is added in addMapPair when there isn't already a -1
    void fillDelaysVector(bool& textRemaining, std::vector<int>& delaysVector, FileHelper& fhelper, std::vector<char>& intAsChars)
    {
        wcharOrChar ch = '\0';
        int delay = 0;

        for (
            textRemaining = fhelper.getCharacter(ch);
            ch != '\n' && textRemaining;
            textRemaining = fhelper.getCharacter(ch))
        {
            if (ch >= '0' && ch <= '9')
            {
                intAsChars.push_back((char)ch);
            }
            else if (ch == '-')
            {
                delaysVector.push_back(-1);

                break;
            }
            else if (ch == '/')
            {
                auto [ptr, ec] = std::from_chars(intAsChars.data(), intAsChars.data() + intAsChars.size(), delay);

                if (ec == std::errc::result_out_of_range)
                {
                    throw std::runtime_error("delays can't be larger than INT_MAX1");
                }

                delaysVector.push_back(delay);
                intAsChars.clear();
                intAsChars.push_back('0'); // empty vector causes std::errc::invalid_argument
            }
        }

        if (delaysVector.empty() || delaysVector.back() != -1)
        {
            if (intAsChars.size() > 1)
            {
                auto [ptr, ec] = std::from_chars(intAsChars.data(), intAsChars.data() + intAsChars.size(), delay);

                if (ec == std::errc::result_out_of_range)
                {
                    throw std::runtime_error("delays can't be larger than INT_MAX2");
                }

                delaysVector.push_back(delay);
            }
        }

        intAsChars.clear();
        intAsChars.push_back('0');

        // make sure to go to end of line
        for (; ch != '\n' && textRemaining; textRemaining = fhelper.getCharacter(ch));
    }

    void delayFile(MapValue& fileMapValue)
    {
#ifndef DEBUG // this needs to be reset in the test, so it a global variable instead
        static size_t fullResetCount = 0;
#endif
        stdprintf("fullResetCount: %zu\n", fullResetCount);
        int delay = 0;

        {
            std::lock_guard<std::mutex> mutexForMapLock(mutexForMap);

            if (fileMapValue.fullResetCheckNumber < fullResetCount)
            {
                fileMapValue.position = 0;
                fileMapValue.fullResetCheckNumber = fullResetCount;
                stdprintf("this delay sequence reset due to prior full reset\n");
            }

            if (fileMapValue.delays[0] == -1)
            {
                if (fullResetCount == SIZE_MAX) // this probably won't ever happen
                {
                    fullResetCount = 0;

                    for (auto& [uPtrType, MapValue] : fileMap)
                    {
                        MapValue.fullResetCheckNumber = 0;
                    }

                    stdprintf("fullResetCount reset\n");
                }

                fullResetCount++;
                stdprintf("fullResetCount set to %zu, all sequences will be reset\n", fullResetCount);
            }
            else if (fileMapValue.delays[fileMapValue.position] == -1)
            {
                fileMapValue.position = 0;
                stdprintf("this delay sequence reset\n");
            }
            else if (fileMapValue.delays[fileMapValue.position] == -2)
            {
                stdprintf("delay sequence already finished\n");
            }

            if (fileMapValue.delays[fileMapValue.position] >= 0)
            {
                delay = fileMapValue.delays[fileMapValue.position];
                fileMapValue.position++;
            }

            stdprintf("delay is %d millisecond(s)\n\n", delay);
        }

        if (delay > 0)
        {
#ifndef DEBUG
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
#endif
        }
    }
};
