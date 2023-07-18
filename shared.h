
#include "file_helper.h"

#ifndef DEBUG
#define printf(...) (0)
#endif

struct MapValue
{
    // delays[0] == -1 says to reset all MapValue.position to 0
    // delays ending with -1 says to reset at the end
    // delays ending with -2 says to NOT reset at the end
    std::unique_ptr<int[]> delays;
    size_t position = 0;
    size_t fullResetCheckNumber = 0;

    explicit MapValue(std::vector<int>& delaysVector) : delays(std::make_unique<int[]>(delaysVector.size()))
    {
        memcpy(delays.get(), delaysVector.data(), delaysVector.size() * sizeof(int));
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
#ifdef _WIN32
        if (!pathSuccessfullySent)
        {
            return;
        }
#endif

        try
        {
            bool utf16WarningWritten = false;

            // intAsChars used in fillDelaysVector but made here so it doesn't need to be remade repeatedly
            std::vector<char> intAsChars;
            intAsChars.reserve(10);
            intAsChars.push_back('0'); // empty vector causes std::errc::invalid_argument
            vectorType keyVector;
            std::vector<int> delaysVector;

#ifdef _WIN32
            memcpy(&toolPath[toolPathLength], delaysFileName, sizeof(delaysFileName));
            FileHelper<wcharOrChar> fhelper(toolPath);
            memcpy(&toolPath[toolPathLength], logFileName, sizeof(logFileName));

            wchar_t byteOrderMark = L'\0';

            if (!fhelper.getCharacter(byteOrderMark))
            {
                dllLog(
                    "files_and_delays.txt byte order mark is missing\n\
make sure files_and_delays.txt is saved as UTF-16 LE"
);
                utf16WarningWritten = true;
            }
            else if (byteOrderMark != 0xFEFF) // not 0xFFFE due to how wchar_t is read
            {
                dllLog(
                    "files_and_delays.txt byte order mark isn't marked as UTF-16 LE\n\
make sure files_and_delays.txt is saved as UTF-16 LE"
);
                utf16WarningWritten = true;
            }
#else
            FileHelper<wcharOrChar> fhelper(delaysFileName);
#endif

            while (addMapPair(fileMap, keyVector, delaysVector, fhelper, intAsChars));

            if (!utf16WarningWritten)
            {
                dllLog("no errors detected");
            }
        }
        catch (const std::runtime_error& e)
        {
            char const* fixC4101Warning = e.what();
            dllLog(fixC4101Warning);
            fileMap.clear(); // clear map so failure is more obvious
        }
    }

    void dllLog(const char* logMessage)
    {
#ifdef _WIN32
        FILE* errorLogFile = nullptr;

        if (_wfopen_s(&errorLogFile, toolPath, L"w") != 0 || !errorLogFile)
#else
        if (!(errorLogFile = fopen(toolPath, "w")))
#endif
        {
            return;
        }

        char timeBuffer[32]{};
        std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::strftime(timeBuffer, sizeof(timeBuffer) - 1, "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        fprintf(
            errorLogFile,
            "This file isn't written to until the first time NtCreateFile is called after injection, so make sure the time below seems right.\n%s\n%s\n",
            timeBuffer,
            logMessage
        );
        fclose(errorLogFile);
    }

    bool addMapPair(myMapType& fileMap, vectorType& keyVector, std::vector<int>& delaysVector, FileHelper<wcharOrChar>& fhelper, std::vector<char>& intAsChars)
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
                uPtrType keyPtr = std::make_unique<wcharOrChar[]>(keyVector.size());
                memcpy(keyPtr.get(), keyVector.data(), keyVector.size() * sizeof(wcharOrChar));
                fileMap.emplace(std::move(keyPtr), MapValue(delaysVector));
            }
        }

        return textRemaining;
    }

    // the -2 at the end is added in addMapPair when there isn't already a -1
    void fillDelaysVector(bool& textRemaining, std::vector<int>& delaysVector, FileHelper<wcharOrChar>& fhelper, std::vector<char>& intAsChars)
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
#ifndef DEBUG // this needs to be reset in the test, so it's a global variable instead
        static size_t fullResetCount = 0;
#endif
        printf("fullResetCount: %zu\n", fullResetCount);
        int delay = 0;

        {
            std::lock_guard<std::mutex> mutexForMapLock(mutexForMap);

            if (fileMapValue.fullResetCheckNumber < fullResetCount)
            {
                fileMapValue.position = 0;
                fileMapValue.fullResetCheckNumber = fullResetCount;
                printf("this delay sequence reset due to prior full reset\n");
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

                    printf("fullResetCount reset\n");
                }

                fullResetCount++;
                printf("fullResetCount set to %zu, all sequences will be reset\n", fullResetCount);
            }
            else if (fileMapValue.delays[fileMapValue.position] == -1)
            {
                fileMapValue.position = 0;
                printf("this delay sequence reset\n");
            }
            else if (fileMapValue.delays[fileMapValue.position] == -2)
            {
                printf("delay sequence already finished\n");
            }

            if (fileMapValue.delays[fileMapValue.position] >= 0)
            {
                delay = fileMapValue.delays[fileMapValue.position];
                fileMapValue.position++;
            }

            printf("delay is %d millisecond(s)\n\n", delay);
        }

        if (delay > 0)
        {
#ifndef DEBUG
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
#endif
        }
    }
};
