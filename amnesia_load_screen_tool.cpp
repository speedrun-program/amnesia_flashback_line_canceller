
// to compile this, remember to add Wininet.lib to additional dependencies

// I won't be able to use C++ std features on Linux since everything is done in __attribute__((constructor)), so I'm not using them here either

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <wininet.h>

#include "file_helper.h"
#include "process_helper.h"

typedef LONG(__stdcall* NTFUNCTION)(HANDLE);


const char thisVersionDate[] = "2024-01-05";

unsigned char mainMenuDelayInstructions[52] = {
    0x68, 0x00, 0x00, 0x00, 0x00,                // push mainMenuDelay
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // call Sleep // this undoes the last push
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // altf4QuitBytes
    0xc3,                                        // ret
    0x68, 0x00, 0x00, 0x00, 0x00,                // push mainMenuDelay
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // call Sleep // this undoes the last push
    0x00, 0x00, 0x00, 0x00, 0x00,                // noSaveQuitBytes
    0xc3,                                        // ret
    0x68, 0x00, 0x00, 0x00, 0x00,                // push mainMenuDelay
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // call Sleep // this undoes the last push
    0x00, 0x00, 0x00, 0x00, 0x00,                // saveQuitBytes
    0xc3,                                        // ret
};


unsigned char mapDelayInstructions[124] = {
    // the commented out instructions are put in Amnesia instead of the extra memory
//  0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,          // jnz to loadFromMenuBytes
//  0x53,                                        // push ebx
//  0x53,                                        // push esi
//  0x57,                                        // push edi
//  0xbb, 0x00, 0x00, 0x00, 0x00,                // mov ebx, spacePerMapName
//  0x8b, 0x35, 0x00, 0x00, 0x00, 0x00,          // mov esi, dword ptr [strncmp pointer]
//  0x89, 0xf8,                                  // mov eax, edi // moving the map name std::string into eax
//  0xe9, 0x00, 0x00, 0x00, 0x00,                // jmp to map delay instructions
    
    // if the std::string is size 15 or less, the c-string is stored in the first 16 bytes of the std::string.
    // otherwise, the c-string is dynamically allocated and accessed through a pointer stored at the beginning of the std::string.
    0x83, 0x7f, 0x14, 0x10,                      // cmp dword ptr [edi + 20], 16
    0x72, 0x02,                                  // jb 2
    0x8b, 0x07,                                  // mov eax, dword ptr [edi]

    0xbf, 0x00, 0x00, 0x00, 0x00,                // mov edi, noMoreMapNamesAddress
    0x50,                                        // push eax (map name c-string)
    0x68, 0x00, 0x00, 0x00, 0x00,                // push firstMapNameAddress
    0x53,                                        // push ebx (spacePerMapName)
    0x50,                                        // push eax (map name c-string)
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8] (firstMapNameAddress)
    0x39, 0x3c, 0x24,                            // cmp dword ptr [esp], edi (noMoreMapNamesAddress)
    0x73, 0x1a,                                  // jnb to loop end
    
    // loop start
    0xff, 0xd6,                                  // call esi (strncmp)
    0x85, 0xc0,                                  // test eax, eax
    0x74, 0x16,                                  // jz to Sleep call
    0x83, 0xc4, 0x0c,                            // add esp, 12
    0x01, 0x1c, 0x24,                            // add dword ptr [esp], ebx
    0x53,                                        // push ebx (spacePerMapName)
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8] (map name c-string)
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8] (next map name to compare against)
    0x39, 0x3c, 0x24,                            // cmp dword ptr [esp], edi (noMoreMapNamesAddress) (precautionary check)
    0x72, 0xe6,                                  // jb to loop start
    // loop end

    0xeb, 0x0f,                                  // jmp to after Sleep call
    // Sleep call
    0x8b, 0x04, 0x24,                            // mov eax, dword ptr [esp]
    0xff, 0xb0, 0x00, 0x00, 0x00, 0x00,          // push dword ptr [eax + delay offset]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // call Sleep // this undoes the last push
    // after Sleep call

    0x83, 0xc4, 0x14,                            // add esp, 20
    0x5f,                                        // pop edi
    0x5e,                                        // pop esi
    0x5b,                                        // pop ebx
    0xeb, 0x14,                                  // jmp to the last 7 copied bytes from loadFromMenuBytes

    // entry point if quickloading
    0x00, 0x00, 0x00, 0x00, 0x00,                // the first 20 copied bytes from loadFromMenuBytes
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,                // remember to adjust the call offset at the last four bytes here
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // last 7 copied bytes from loadFromMenuBytes
    0xe9, 0x00, 0x00, 0x00, 0x00,                // jmp back to amnesia
    
    // int3 filler so this ends on a 64 byte boundary
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};


unsigned char flashbackSkipInstructions[160] = {
    // the cSoundHandler pointer should be in eax when these instructions are jumped to.
    // it needs to be back in eax when jumping back to amnesia

    // copied bytes from beforeFadeOutAllBytes
    // do this first so the cSoundHandler pointer is in eax
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x50,                                        // push eax (cSoundHandler pointer)
    0x53,                                        // push ebx
    0x56,                                        // push esi
    0x57,                                        // push edi
    0x8b, 0x1d, 0x00, 0x00, 0x00, 0x00,          // mov ebx, dword ptr [strncmp pointer]
    0x8b, 0x70, 0x00,                            // mov esi, dword ptr [eax + m_lstSoundEntries offset]
    0x8b, 0x3e,                                  // mov edi, dword ptr [esi] (first node, or the start of the list if it's empty)

    // the start of the m_lstSoundEntries list is used to indicate the end of the list
    0x39, 0xf7,                                  // cmp edi, esi
    0x74, 0x7a,                                  // jz to outer loop end

    // outer loop start
    0x8b, 0x4f, 0x00,                            // mov ecx, dword ptr [edi + nodeCSoundEntryOffset]
    0x85, 0xc9,                                  // test ecx, ecx (null pointer check)
    0x74, 0x6d,                                  // jz to inner loop end and past "add esp, 16"
    0x89, 0xc8,                                  // mov eax, ecx

    // the std::string object should be at the front of the cSoundEntry object
    
    // if the std::string is size 15 or less, the c-string is stored in the first 16 bytes of the std::string.
    // otherwise, the c-string is dynamically allocated and accessed through a pointer stored at the beginning of the std::string.
    0x83, 0x79, 0x14, 0x10,                      // cmp dword ptr [ecx + 20], 16
    0x72, 0x02,                                  // jb 2
    0x8b, 0x01,                                  // mov eax, dword ptr [ecx]

    // saving the cSoundEntry pointer and some arguments for the inner loop strncmp call
    0x51,                                        // push ecx (cSoundEntry object)
    0x68, 0x00, 0x00, 0x00, 0x00,                // push spacePerFlashbackName
    0x50,                                        // push eax (sound name c-string)

    // checking the prefix
    0x68, 0x00, 0x00, 0x00, 0x00,                // push lengthOfCommonPrefix
    0x50,                                        // push eax (sound name c-string)
    0x68, 0x00, 0x00, 0x00, 0x00,                // push commonPrefixAddress
    0xff, 0xd3,                                  // call ebx (strncmp)
    0x83, 0xc4, 0x0c,                            // add esp, 12
    0x81, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,    // add dword ptr [esp], lengthOfCommonPrefix
    0x68, 0x00, 0x00, 0x00, 0x00,                // push firstFlashbackNameAddress
    0x85, 0xc0,                                  // test eax, eax
    0x75, 0x39,                                  // jnz to inner loop end
    0x81, 0x3c, 0x24, 0x00, 0x00, 0x00, 0x00,    // cmp dword ptr [esp], noMoreFlashbackNamesAddress (precautionary check)
    0x73, 0x30,                                  // jnb to inner loop end

    // inner loop start
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0xd3,                                  // call ebx (strncmp)
    0x83, 0xc4, 0x0c,                            // add esp, 12
    0x85, 0xc0,                                  // test eax, eax
    0x75, 0x0b,                                  // jnz to after calling cSoundEntry::Stop

    // calling cSoundEntry::Stop
    0x8b, 0x4c, 0x24, 0x0c,                      // mov ecx, dword ptr [esp + 12] (cSoundEntry object)
    0xe8, 0x00, 0x00, 0x00, 0x00,                // call cSoundEntry::Stop
    0xeb, 0x10,                                  // jmp to inner loop end

    // preparing for the next inner loop
    0x81, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,    // add dword ptr [esp], spacePerFlashbackName
    0x81, 0x3c, 0x24, 0x00, 0x00, 0x00, 0x00,    // cmp dword ptr [esp], noMoreFlashbackNamesAddress
    0x72, 0xd0,                                  // jb to inner loop start
    // inner loop end

    0x83, 0xc4, 0x10,                            // add esp, 16
    0x8b, 0x3f,                                  // mov edi, dword ptr [edi]
    0x39, 0xf7,                                  // cmp edi, esi
    0x75, 0x86,                                  // jnz to outer loop start
    // outer loop end

    0x5f,                                        // pop edi
    0x5e,                                        // pop esi
    0x5b,                                        // pop ebx
    0x58,                                        // pop eax
    0xc3,                                        // ret

    // int3 filler
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};


unsigned char flashbackWaitInstructions[336] = {
    // entry point from cLuxMapHandler::CheckMapChange
    0xb1, 0x01,                                  // mov cl, 1
    0x86, 0x0d, 0x00, 0x00, 0x00, 0x00,          // xchg cl, byte ptr [waitForFlashbackByteLocation]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // copied bytes from beforeFadeOutAllBytes
    0xc3,                                        // ret

    // int3 filler
    // make sure entry point from cEngine::Run will be aligned by 16
    0xcc,


    // entry point from cEngine::Run
    0xe8, 0x00, 0x00, 0x00, 0x00,                // call cEngine::GetStepSize
    0xa0, 0x00, 0x00, 0x00, 0x00,                // mov al, byte ptr [waitForFlashbackByteLocation]
    0x84, 0xc0,                                  // test al, al
    0x75, 0x01,                                  // jnz over the ret
    0xc3,                                        // ret

    0x56,                                        // push esi
    0x57,                                        // push edi
    0x57,                                        // push edi // dummy push to save the float returned by cEngine::GetStepSize
    0xd9, 0x1c, 0x24,                            // fstp dword ptr [esp]
    0x31, 0xc0,                                  // xor eax, eax
    0x86, 0x05, 0x00, 0x00, 0x00, 0x00,          // xchg al, byte ptr [waitForFlashbackByteLocation]
    0xa1, 0x00, 0x00, 0x00, 0x00,                // mov eax, dword ptr [gpBaseLocation]
    0x8b, 0x30,                                  // mov esi, dword ptr [eax] (mpEngine)
    0x8b, 0x76, 0x00,                            // mov esi, dword ptr [esi + gpBaseMpSoundOffset]
    0x8b, 0x76, 0x00,                            // mov esi, dword ptr [esi + mpSoundHandlerOffset]
    0x8b, 0x76, 0x00,                            // mov esi, dword ptr [esi + m_lstSoundEntries offset]
    0x8b, 0x3e,                                  // mov edi, dword ptr [esi] (first node, or the start of the list if it's empty)

    // the start of the m_lstSoundEntries list is used to indicate the end of the list
    0x39, 0xf7,                                  // cmp edi, esi
    0x0f, 0x84, 0xf5, 0x00, 0x00, 0x00,          // jz to "fld dword ptr [esp]" near the jump back to amnesia

    0x53,                                        // push ebx
    0x8b, 0x1d, 0x00, 0x00, 0x00, 0x00,          // mov ebx, dword ptr [strncmp pointer]

    // making space for two doubles initialized to zero
    0x31, 0xc0,                                  // xor eax, eax
    0x50,                                        // push eax
    0x50,                                        // push eax
    0x50,                                        // push eax
    0x50,                                        // push eax

    // outer loop start
    0x8b, 0x4f, 0x00,                            // mov ecx, dword ptr [edi + nodeCSoundEntryOffset]
    0x85, 0xc9,                                  // test ecx, ecx (null pointer check)
    0x0f, 0x84, 0xa8, 0x00, 0x00, 0x00,          // jz to inner loop end and past the first "add esp, 16"
    0x89, 0xc8,                                  // mov eax, ecx

    // the std::string object should be at the front of the cSoundEntry object

    // if the std::string is size 15 or less, the c-string is stored in the first 16 bytes of the std::string.
    // otherwise, the c-string is dynamically allocated and accessed through a pointer stored at the beginning of the std::string.
    0x83, 0x79, 0x14, 0x10,                      // cmp dword ptr [ecx + 20], 16
    0x72, 0x02,                                  // jb 2
    0x8b, 0x01,                                  // mov eax, dword ptr [ecx]

    // saving the cSoundEntry pointer and some arguments for the inner loop strncmp call
    0x51,                                        // push ecx (cSoundEntry object)
    0x68, 0x00, 0x00, 0x00, 0x00,                // push spacePerFlashbackName
    0x50,                                        // push eax (sound name c-string)

    // checking the prefix
    0x68, 0x00, 0x00, 0x00, 0x00,                // push lengthOfCommonPrefix
    0x50,                                        // push eax (sound name c-string)
    0x68, 0x00, 0x00, 0x00, 0x00,                // push commonPrefixAddress
    0xff, 0xd3,                                  // call ebx (strncmp)
    0x83, 0xc4, 0x0c,                            // add esp, 12
    0x81, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,    // add dword ptr [esp], lengthOfCommonPrefix
    0x68, 0x00, 0x00, 0x00, 0x00,                // push firstFlashbackNameAddress
    0x85, 0xc0,                                  // test eax, eax
    0x75, 0x74,                                  // jnz to inner loop end
    0x81, 0x3c, 0x24, 0x00, 0x00, 0x00, 0x00,    // cmp dword ptr [esp], noMoreFlashbackNamesAddress (precautionary check)
    0x73, 0x6b,                                  // jnb to inner loop end

    // inner loop start
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0x74, 0x24, 0x08,                      // push dword ptr [esp + 8]
    0xff, 0xd3,                                  // call ebx (strncmp)
    0x83, 0xc4, 0x0c,                            // add esp, 12
    0x85, 0xc0,                                  // test eax, eax
    0x75, 0x46,                                  // jnz to after storing the remaining time

    // storing how much time is left for this flashback line to finish
    0x56,                                        // push esi
    0x57,                                        // push edi
    0x8b, 0x4c, 0x24, 0x14,                      // mov ecx, dword ptr [esp + 20] (cSoundEntry object)
    0x8b, 0x49, 0x00,                            // mov ecx, dword ptr [ecx + soundChannelOffset] (cSoundEntry's iSoundChannel object)
    0x85, 0xc9,                                  // test ecx, ecx (null pointer check)
    0x74, 0x35,                                  // jz to pop edi
    0x89, 0xce,                                  // mov esi, ecx
    0x8b, 0x3e,                                  // mov edi, dword ptr [esi] (iSoundChannel vtable)
    0x8a, 0x46, 0x00,                            // mov al, byte ptr [esi + getPausedOffset]
    0x22, 0x46, 0x00,                            // and al, byte ptr [esi + getLoopingOffset]
    0x75, 0x29,                                  // jnz to pop edi
    0xff, 0x57, 0x00,                            // call dword ptr [edi + isPlayingOffset]
    0x84, 0xc0,                                  // test al, al
    0x74, 0x22,                                  // jz to pop edi
    0x89, 0xf1,                                  // mov ecx, esi
    0xff, 0x57, 0x00,                            // call dword ptr [edi + getElapsedTimeOffset]
    0x89, 0xf1,                                  // mov ecx, esi
    0xdd, 0x5c, 0x24, 0x20,                      // fstp qword ptr [esp + 32]
    0xff, 0x57, 0x00,                            // call dword ptr [edi + getTotalTimeOffset]
    0xdc, 0x64, 0x24, 0x20,                      // fsub qword ptr [esp + 32]
    0xdd, 0x44, 0x24, 0x18,                      // fld qword ptr [esp + 24]
    0xdf, 0xf1,                                  // fcomip st(0), st(1)
    0x73, 0x06,                                  // jnb to fstp st(0) (already waiting for a different sound with more remaining time)
    0xdd, 0x5c, 0x24, 0x18,                      // fstp qword ptr [esp + 24]
    0xeb, 0x02,                                  // jmp to pop edi
    0xdd, 0xd8,                                  // fstp st(0)
    0x5f,                                        // pop edi
    0x5e,                                        // pop esi
    0xeb, 0x10,                                  // jmp to inner loop end

    // preparing for the next inner loop
    0x81, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,    // add dword ptr [esp], spacePerFlashbackName
    0x81, 0x3c, 0x24, 0x00, 0x00, 0x00, 0x00,    // cmp dword ptr [esp], noMoreFlashbackNamesAddress
    0x72, 0x95,                                  // jb to inner loop start
    // inner loop end

    0x83, 0xc4, 0x10,                            // add esp, 16
    0x8b, 0x3f,                                  // mov edi, dword ptr [edi]
    0x39, 0xf7,                                  // cmp edi, esi
    0x0f, 0x85, 0x43, 0xff, 0xff, 0xff,          // jnz to outer loop start

    // checking if any flashback lines are close enough to finishing to let the load screen end
    0xdd, 0x04, 0x24,                            // fld qword ptr [esp] (time remaining before flashback end)
    0xdd, 0x05, 0x00, 0x00, 0x00, 0x00,          // fld qword ptr [secondsRemainingBeforeUnwaitAddress] // this should be at least 0.001
    0xdf, 0xf1,                                  // fcomip st(0), st(1)
    0xdd, 0xd8,                                  // fstp st(0)
    0x73, 0x18,                                  // jnb to outer loop end
    0x6a, 0x01,                                  // push 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,          // call Sleep // this undoes the last push
    0x8b, 0x3e,                                  // mov edi, dword ptr [esi] (first node, or the start of the list if it's empty)
    
    // resetting the memory to store doubles to zero
    0x83, 0xc4, 0x10,                            // add esp, 16
    0x31, 0xc0,                                  // xor eax, eax
    0x50,                                        // push eax
    0x50,                                        // push eax
    0x50,                                        // push eax
    0x50,                                        // push eax
    0xe9, 0x1c, 0xff, 0xff, 0xff,                // jmp to outer loop start
    // outer loop end

    0x83, 0xc4, 0x10,                            // add esp, 16
    0x5b,                                        // pop ebx
    0xd9, 0x04, 0x24,                            // fld dword ptr [esp]
    0x5f,                                        // pop edi // dummy pop
    0x5f,                                        // pop edi
    0x5e,                                        // pop esi
    0xc3,                                        // ret

    // int3 filler
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};


const wchar_t steamName[] = L"Amnesia.exe";
const wchar_t noSteamName[] = L"Amnesia_NoSteam.exe";


struct InjectionInfo {
    // locations in Amnesia's memory
    uint32_t gpBaseLocation = 0;
    uint32_t cSoundEntryStopLocation = 0;
    uint32_t beforeFadeOutAllLocation = 0;
    uint32_t engineRunInjectionLocation = 0;
    uint32_t getStepSizeLocation = 0;
    uint32_t altf4QuitLocation = 0;
    uint32_t noSaveQuitLocation = 0;
    uint32_t saveQuitLocation = 0;
    uint32_t loadFromMenuLocation = 0;
    uint32_t DestroyMapLocation = 0; // this is called near loadFromMenuLocation
    uint32_t injectedInstructionsLocation = 0;
    uint32_t injectedDataLocation = 0;

    // info found by reading flashback_names.txt, maps_and_delays.txt, and amnesia_settings.txt
    uint32_t howManyFlashbackNames = 0;
    uint32_t lengthOfLongestFlashbackName = 0;
    uint32_t lengthOfCommonPrefix = 0;
    uint32_t howManyMapNames = 0;
    uint32_t lengthOfLongestMapName = 0;
    uint32_t mainMenuDelay = 0;
    uint32_t spaceForCommonPrefix = 0;
    uint32_t spacePerFlashbackName = 0;
    uint32_t sizeOfFlashbackNameArea = 0;
    uint32_t spacePerMapName = 0;
    uint32_t sizeOfMapsAndDelaysArea = 0;
    uint32_t spaceForInstructions = 0;
    bool skippingFlashBacks = false;
    unsigned char secondsRemainingBeforeUnwait[sizeof(double)] = {};

    // copied instructions from Amnesia's memory
    unsigned char sleepCallBytes[6] = {};
    unsigned char strncmpCallBytes[6] = {};
    unsigned char beforeFadeOutAllBytes[6] = {};
    unsigned char altf4QuitBytes[6] = {};
    unsigned char noSaveQuitBytes[5] = {};
    unsigned char saveQuitBytes[5] = {};
    unsigned char loadFromMenuBytes[27] = {};

    // offsets of data and virtual functions
    unsigned char gpBaseMpSoundOffset = 0;
    unsigned char mpSoundHandlerOffset = 0;
    unsigned char m_lstSoundEntriesOffset = 0;
    unsigned char nodeCSoundEntryOffset = 0;
    unsigned char soundChannelOffset = 0;
    unsigned char isPlayingOffset = 0;
    unsigned char getPausedOffset = 0;
    unsigned char getLoopingOffset = 0;
    unsigned char getTotalTimeOffset = 0;
    unsigned char getElapsedTimeOffset = 0;

    bool delayingMainMenu = false;
};


template <const size_t circularBufferSize>
class CircularBuffer {
public:
    static_assert(
        circularBufferSize && ((circularBufferSize & (circularBufferSize - 1)) == 0),
        "circular buffer size needs to be a power of two and greater than zero\n"
        );
    unsigned char buffer[circularBufferSize] = {};
    size_t start = 0;

    unsigned char operator[](const size_t idx) const {
        return buffer[(idx + start) & (sizeof(buffer) - 1)];
    }

    void addToEnd(const unsigned char newEndValue) {
        buffer[start] = newEndValue;
        start = (start + 1) & (sizeof(buffer) - 1);
    }

    void copyBytes(unsigned char* destination, const size_t startIdx, const size_t howManyBytes) const {
        for (size_t i = 0; i < howManyBytes; i++) {
            destination[i] = buffer[(start + i + startIdx) & (sizeof(buffer) - 1)];
        }
    }
};


void getExitInput(const bool succeeded) {
    int ch = 0;
    printf("%sPress Enter to exit\n", succeeded ? "Amnesia successfully injected\n" : "couldn't inject Amnesia\n");
    ch = getchar();
}


DWORD searchUsingSnapshotHandle(PROCESSENTRY32* processEntry, const HANDLE snapshot, bool* isSteamVersion) {
    if (!Process32First(snapshot, processEntry)) {
        printf("error when using Process32First: %d\n", GetLastError());
        return (DWORD)-1;
    }

    do {
        if ((*isSteamVersion = (wcscmp(processEntry->szExeFile, steamName) == 0)) || wcscmp(processEntry->szExeFile, noSteamName) == 0) {
            return processEntry->th32ProcessID;
        }
    } while (Process32Next(snapshot, processEntry));

    return (DWORD)-1;
}


DWORD findAmnesiaPid(bool* isSteamVersion) {
    DWORD amnesiaPid = (DWORD)-1;

    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);                // resource acquired
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("error when using CreateToolhelp32Snapshot: %d\n", GetLastError());
        return amnesiaPid;
    }
    amnesiaPid = searchUsingSnapshotHandle(&processEntry, snapshot, isSteamVersion);
    CloseHandle(snapshot);                                                            // resource released

    if (amnesiaPid == (DWORD)-1) {
        printf("couldn't find amnesia process PID\n");
    }

    return amnesiaPid;
}


bool findNtFunctions(NTFUNCTION* NtSuspendProcess, NTFUNCTION* NtResumeProcess) {
    HMODULE ntdllHandle = GetModuleHandle(L"ntdll.dll");
    if (!ntdllHandle) {
        printf("WARNING: error using GetModuleHandle to find ntdll.dll: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    *NtSuspendProcess = (NTFUNCTION)GetProcAddress(ntdllHandle, "NtSuspendProcess");
    if (!*NtSuspendProcess) {
        printf("WARNING: error using GetProcAddress to find NtSuspendProcess: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    *NtResumeProcess = (NTFUNCTION)GetProcAddress(ntdllHandle, "NtResumeProcess");
    if (!*NtResumeProcess) {
        printf("WARNING: error using GetProcAddress to find NtResumeProcess: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    return true;
}


char* determineYesOrNo(const char* s, bool* setting) {
    s += strcspn(s, " nNyY\n");
    if (*s == 'y' || *s == 'Y') {
        *setting = true;
    } else if (*s == 'n' || *s == 'N') {
        *setting = false;
    }

    return (char*)s;
}


bool readSettingsFile(
        bool* skippingFlashbacks,
        bool* delayMaps,
        bool* allowUnexpectedGameVersions,
        bool* checkForToolUpdates,
        bool* allowNotFullyUpdatedTool,
        double* secondsRemainingBeforeUnwait) {
    char buffer[256] = {}; // remember to null terminate this after reading from the file.
    const char defaultText[] = "skip flashbacks: n\r\n\
delay maps: y\r\n\
allow unexpected game versions: n\r\n\
check for tool updates: y\r\n\
allow not fully updated tool: n\r\n\
milliseconds remaining before unwait: 435\r\n";
    static_assert(sizeof(defaultText) < sizeof(buffer), "amnesia_settings.txt defaultText is too big for buffer\n");

    const char settingsFileName[] = "amnesia_settings.txt";

    const char nameOfSkipFlashbacksSetting[] = "skip flashbacks:";
    const char nameOfDelayMapsSetting[] = "delay maps:";
    const char nameOfAllowUnexpectedGameVersions[] = "allow unexpected game versions:";
    const char nameOfCheckForToolUpdates[] = "check for tool updates:";
    const char nameOfAllowNotFullyUpdatedTool[] = "allow not fully updated tool:";
    const char nameOfMillisecondsRemainingBeforeUnwait[] = "milliseconds remaining before unwait:";

    bool skipFlashbacksSettingFound = false;
    bool delayMapsSettingFound = false;
    bool allowUnexpectedGameVersionsSettingFound = false;
    bool checkForToolUpdatesSettingFound = false;
    bool allowNotFullyUpdatedToolSettingFound = false;

    FILE* f = nullptr;
    if (fopen_s(&f, settingsFileName, "rb") != 0 || !f) {    // resource acquired (1)
        printf("couldn't open %s\n", settingsFileName);
        return false;
    }
    size_t bytesRead = fread(buffer, 1, sizeof(buffer), f);
    fclose(f);                                               // resource released (1)
    f = nullptr;

    if (bytesRead == sizeof(buffer)) {
        printf("%s should be smaller than %zu bytes\nresetting %s\n", settingsFileName, sizeof(buffer), settingsFileName);
        if (fopen_s(&f, settingsFileName, "wb") != 0 || !f) { // resource acquired (2)
            printf("couldn't open %s\n", settingsFileName);
            return false;
        }
        fwrite(defaultText, 1, sizeof(defaultText) - 1, f);  // - 1 because the null character isn't needed
        fclose(f);                                           // resource released (2)
        return false;
    }

    char* bufferPtr = buffer;
    char* strtolStartPtr = nullptr;
    char* strtolEndPtr = nullptr;
    long millisecondsRemainingBeforeUnwait = 0;
    for (char* bufferPtr = buffer; bufferPtr != nullptr && *bufferPtr != '\0'; bufferPtr = strchr(bufferPtr, '\n')) {
        bufferPtr += strspn(bufferPtr, " \f\n\r\t\v");

        if (strncmp(bufferPtr, nameOfSkipFlashbacksSetting, sizeof(nameOfSkipFlashbacksSetting) - 1) == 0) {

            bufferPtr = determineYesOrNo(bufferPtr + sizeof(nameOfSkipFlashbacksSetting), skippingFlashbacks);
            skipFlashbacksSettingFound = (*bufferPtr != '\n' && *bufferPtr != '\0');

        } else if (strncmp(bufferPtr, nameOfDelayMapsSetting, sizeof(nameOfDelayMapsSetting) - 1) == 0) {

            bufferPtr = determineYesOrNo(bufferPtr + sizeof(nameOfDelayMapsSetting), delayMaps);
            delayMapsSettingFound = (*bufferPtr != '\n' && *bufferPtr != '\0');

        } else if (strncmp(bufferPtr, nameOfAllowUnexpectedGameVersions, sizeof(nameOfAllowUnexpectedGameVersions) - 1) == 0) {

            bufferPtr = determineYesOrNo(bufferPtr + sizeof(nameOfAllowUnexpectedGameVersions), allowUnexpectedGameVersions);
            allowUnexpectedGameVersionsSettingFound = (*bufferPtr != '\n' && *bufferPtr != '\0');

        } else if (strncmp(bufferPtr, nameOfCheckForToolUpdates, sizeof(nameOfCheckForToolUpdates) - 1) == 0) {

            bufferPtr = determineYesOrNo(bufferPtr + sizeof(nameOfCheckForToolUpdates), checkForToolUpdates);
            checkForToolUpdatesSettingFound = (*bufferPtr != '\n' && *bufferPtr != '\0');

        } else if (strncmp(bufferPtr, nameOfAllowNotFullyUpdatedTool, sizeof(nameOfAllowNotFullyUpdatedTool) - 1) == 0) {

            bufferPtr = determineYesOrNo(bufferPtr + sizeof(nameOfAllowNotFullyUpdatedTool), allowNotFullyUpdatedTool);
            allowNotFullyUpdatedToolSettingFound = (*bufferPtr != '\n' && *bufferPtr != '\0');

        } else if (strncmp(bufferPtr, nameOfMillisecondsRemainingBeforeUnwait, sizeof(nameOfMillisecondsRemainingBeforeUnwait) - 1) == 0) {

            strtolStartPtr = bufferPtr + sizeof(nameOfMillisecondsRemainingBeforeUnwait);
            millisecondsRemainingBeforeUnwait = strtol(strtolStartPtr, &strtolEndPtr, 10);
            bufferPtr = strtolEndPtr;

        }
    }

    if (strtolStartPtr == strtolEndPtr) {
        printf("couldn't read \"milliseconds remaining before unwait\" setting\n");
        millisecondsRemainingBeforeUnwait = 0;
    } else if (millisecondsRemainingBeforeUnwait < 0) {
        printf("milliseconds remaining before unwait can't be less than zero\n");
        millisecondsRemainingBeforeUnwait = 0;
    } else {
        // this is made at least 1 because I don't want to trust mpSound.GetTotalTime() - mpSound.GetElapsedTime() to always eventually equal zero
        millisecondsRemainingBeforeUnwait += (millisecondsRemainingBeforeUnwait == 0);
    }

    *secondsRemainingBeforeUnwait = millisecondsRemainingBeforeUnwait / 1000.0;

    if (!(
            skipFlashbacksSettingFound
            && delayMapsSettingFound
            && allowUnexpectedGameVersionsSettingFound
            && checkForToolUpdatesSettingFound
            && allowNotFullyUpdatedToolSettingFound
            && (millisecondsRemainingBeforeUnwait > 0)
        )) {
        printf("couldn't read all settings in %s\nresetting %s\n", settingsFileName, settingsFileName);
        if (fopen_s(&f, settingsFileName, "wb") != 0 || !f) { // resource acquired (3)
            printf("couldn't open %s\n", settingsFileName);
            return false;
        }
        fwrite(defaultText, 1, sizeof(defaultText) - 1, f);  // - 1 because the null character isn't needed
        fclose(f);                                           // resource released (3)
        return false;
    }
    
    return true;
}


bool isMostRecentVersion(HINTERNET* hInternet, HINTERNET* hConnection, HINTERNET* hData, bool* isMostRecentVersionResult) {
    char currentVersionDate[sizeof(thisVersionDate)] = {};

    *hInternet = InternetOpen(
        L"amnesia_load_screen_tool",
        INTERNET_OPEN_TYPE_PRECONFIG,
        nullptr,
        nullptr,
        0
    );
    if (*hInternet == nullptr) {
        printf("error when using InternetOpenA: %d\n", GetLastError());
        return false;
    }

    *hConnection = InternetConnect(
        *hInternet,
        L"raw.githubusercontent.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        nullptr,
        nullptr,
        INTERNET_SERVICE_HTTP,
        0,
        0
    );
    if (*hConnection == nullptr) {
        printf("error when using InternetConnectA: %d\n", GetLastError());
        return false;
    }

    *hData = HttpOpenRequest(
        *hConnection,
        nullptr,
        L"/speedrun-program/amnesia_load_screen_tool/main/readme.md",
        nullptr,
        nullptr,
        nullptr,
        INTERNET_FLAG_SECURE,
        0
    );
    if (*hData == nullptr) {
        printf("error when using HttpOpenRequestA: %d\n", GetLastError());
        return false;
    }

    if (!HttpSendRequest(*hData, nullptr, 0, nullptr, 0)) {
        printf("error when using HttpSendRequestA: %d\n", GetLastError());
        return false;
    }

    // windows API documentation says to call this in a loop
    DWORD bytesReadThisLoop = 0;
    DWORD totalBytesRead = 0;
    while (
        totalBytesRead < sizeof(currentVersionDate) - 1
        && InternetReadFile(*hData, &currentVersionDate[totalBytesRead], sizeof(currentVersionDate) - 1 - totalBytesRead, &bytesReadThisLoop)
        && bytesReadThisLoop != 0) {
        totalBytesRead += bytesReadThisLoop;
    }

    if (totalBytesRead < sizeof(currentVersionDate) - 1) {
        printf("couldn't determine the date of the most recent version of this tool using InternetReadFile. Error number: %d\n", GetLastError());
        return false;
    }

    *isMostRecentVersionResult = (strncmp(thisVersionDate, currentVersionDate, sizeof(currentVersionDate) - 1) == 0);

    if (!(*isMostRecentVersionResult)) {
        printf("a newer version of this tool released on %s is available. this version's date is %s.\n", currentVersionDate, thisVersionDate);
    }

    return true;
}


bool preprocessFlashbackNamesFile(
        uint32_t* howManyFlashbackNames,
        uint32_t* lengthOfLongestFlashbackName,
        uint32_t* lengthOfCommonPrefix,
        const uint32_t maxcommonPrefixSize, // this should be one less than the commonPrefix buffer size
        char* commonPrefix) {
    FileHelper fh("flashback_names.txt");
    if (!fh.f) {
        return false;
    }

    char ch = '\0';

    // the first name needs to be copied to commonPrefix
    for (bool keepReading = true; *howManyFlashbackNames == 0 && keepReading;) {
        while ((keepReading = fh.getCharacter(&ch))) {
            ch += (32 * (ch >= 'A' && ch <= 'Z')); // changing ch to lowercase because amnesia stores flashback names in lowercase
            if (ch == '\r') {
                continue;
            } else if (ch == '\n') {
                *howManyFlashbackNames += (*lengthOfLongestFlashbackName != 0);
                break;
            } else {
                if (*lengthOfLongestFlashbackName < maxcommonPrefixSize) {
                    commonPrefix[*lengthOfLongestFlashbackName] = ch;
                    *lengthOfCommonPrefix += 1;
                }
                *lengthOfLongestFlashbackName += 1;
            }
        }
    }
    commonPrefix[(*lengthOfLongestFlashbackName <= maxcommonPrefixSize) ? *lengthOfLongestFlashbackName : maxcommonPrefixSize] = '\0';

    uint32_t currentFlashbackNameLength = 0;

    while (fh.getCharacter(&ch)) {
        if (ch == '\r') {
            continue;
        } else if (ch == '\n') {
            if (currentFlashbackNameLength == 0) { // it was an empty line
                continue;
            }
            if (*lengthOfLongestFlashbackName < currentFlashbackNameLength) {
                *lengthOfLongestFlashbackName = currentFlashbackNameLength;
            }
            if (currentFlashbackNameLength < *lengthOfCommonPrefix) {
                commonPrefix[currentFlashbackNameLength] = '\0';
                *lengthOfCommonPrefix = currentFlashbackNameLength;
            }
            *howManyFlashbackNames += 1;
            currentFlashbackNameLength = 0;
        } else {
            if (currentFlashbackNameLength < *lengthOfCommonPrefix && commonPrefix[currentFlashbackNameLength] != ch) {
                commonPrefix[currentFlashbackNameLength] = '\0';
                *lengthOfCommonPrefix = currentFlashbackNameLength;
            }
            currentFlashbackNameLength += 1;
        }
    }

    // last line
    if (*lengthOfLongestFlashbackName < currentFlashbackNameLength) {
        *lengthOfLongestFlashbackName = currentFlashbackNameLength;
    }
    *howManyFlashbackNames += (currentFlashbackNameLength != 0);

    return true;
}


bool preprocessMapDelaysFile(uint32_t* howManyMapNames, uint32_t* lengthOfLongestMapName, bool* delayingMainMenu) {
    FileHelper fh("maps_and_delays.txt");
    if (!fh.f) {
        return false;
    }

    char ch = '\0';
    uint32_t currentMapNameLength = 0;

    while (fh.getCharacter(&ch)) {
        if (ch == '\r') {
            continue;
        } else if (ch == '/' || ch == '\n') {
            if (*lengthOfLongestMapName < currentMapNameLength) {
                *lengthOfLongestMapName = currentMapNameLength;
            }

            if (ch == '/' || currentMapNameLength == 0) {
                *delayingMainMenu = true;
            }

            *howManyMapNames += (currentMapNameLength != 0);
            currentMapNameLength = 0;

            while (ch != '\n' && fh.getCharacter(&ch)); // finishing reading the line
        } else {
            currentMapNameLength += 1;
        }
    }

    // last line
    if (*lengthOfLongestMapName < currentMapNameLength) {
        *lengthOfLongestMapName = currentMapNameLength;
    }
    *howManyMapNames += (currentMapNameLength != 0);

    return true;
}


bool findInstructions(InjectionInfo* ii, ProcessHelper* ph) {
    unsigned char b = 0;
    bool alreadyInjected = false;
    size_t instructionPatternsFound = 0;
    unsigned char locationCopyBytes[sizeof(uint32_t)] = {};
    CircularBuffer<128> memorySlice;

    for (size_t i = sizeof(memorySlice.buffer) - 1; i != 0; i--) {
        ph->getByte(&b);
        memorySlice.addToEnd(b);
    }

    // finding where to write to and copy from in amnesia's memory based on instruction byte patterns
    for (size_t currentMemoryAddress = ph->textSegmentLocation; ph->getByte(&b); currentMemoryAddress++) {
        memorySlice.addToEnd(b);

        if (memorySlice[0] == 0x4e && memorySlice[2] == 0x51 && memorySlice[3] == 0x8b && memorySlice[4] == 0x8e && memorySlice[9] == 0xe8 && memorySlice[14] == 0xd9) {

            if (memorySlice[28] == 0xe8) { // call
                alreadyInjected = true;
                break;
            }
            memorySlice.copyBytes(locationCopyBytes, 22, sizeof(locationCopyBytes));
            memcpy(&ii->gpBaseLocation, locationCopyBytes, sizeof(ii->gpBaseLocation));
            uint32_t beforeFadeOutAllLocation = currentMemoryAddress + 28;
            memcpy(&ii->beforeFadeOutAllLocation, &beforeFadeOutAllLocation, sizeof(ii->beforeFadeOutAllLocation));
            memorySlice.copyBytes(ii->beforeFadeOutAllBytes, 28, sizeof(ii->beforeFadeOutAllBytes));
            ii->gpBaseMpSoundOffset = ii->beforeFadeOutAllBytes[2];
            ii->mpSoundHandlerOffset = ii->beforeFadeOutAllBytes[5];
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0xd9 && memorySlice[4] == 0x8b && memorySlice[10] == 0x6a && memorySlice[11] == 0x05) {

            ii->engineRunInjectionLocation = currentMemoryAddress + 20;
            memorySlice.copyBytes(locationCopyBytes, 21, sizeof(locationCopyBytes));
            memcpy(&ii->getStepSizeLocation, locationCopyBytes, sizeof(ii->getStepSizeLocation));
            ii->getStepSizeLocation += ii->engineRunInjectionLocation + 5;

        } else if (memorySlice[0] == 0x8b && memorySlice[1] == 0x46 && memorySlice[3] == 0x8b && memorySlice[4] == 0x10 && memorySlice[5] == 0x3b && memorySlice[6] == 0xd0) {

            ii->m_lstSoundEntriesOffset = memorySlice[2];
            ii->nodeCSoundEntryOffset = memorySlice[19];
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x56 && memorySlice[1] == 0x8b && memorySlice[7] == 0x75 && memorySlice[9] == 0x80) {

            uint32_t cSoundEntryStopLocation = currentMemoryAddress;
            memcpy(&ii->cSoundEntryStopLocation, &cSoundEntryStopLocation, sizeof(ii->cSoundEntryStopLocation));
            ii->soundChannelOffset = memorySlice[17];
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0xd8 && memorySlice[1] == 0x80 && memorySlice[10] == 0x80) {
            
            ii->isPlayingOffset = memorySlice[37];
            ii->getPausedOffset = memorySlice[49];
            ii->getLoopingOffset = memorySlice[68];
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x05 && memorySlice[5] == 0x8b && memorySlice[12] == 0x17) {

            ii->getTotalTimeOffset = memorySlice[28];
            ii->getElapsedTimeOffset = memorySlice[55];
            instructionPatternsFound += 1;
            
        } else if (memorySlice[0] == 0x6a && memorySlice[1] == 0x0a && memorySlice[2] == 0xff && memorySlice[8] == 0x8b) {
            
            memorySlice.copyBytes(ii->sleepCallBytes, 2, sizeof(ii->sleepCallBytes));
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x6a && memorySlice[1] == 0x05 && memorySlice[7] == 0x53) {
            
            memorySlice.copyBytes(ii->strncmpCallBytes, 8, sizeof(ii->strncmpCallBytes));
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x46 && memorySlice[2] == 0x53 && memorySlice[3] == 0x50 && memorySlice[4] == 0x8b && memorySlice[6] == 0xe8) {
            
            if (memorySlice[73] == 0xe8) { // call
                alreadyInjected = true;
                break;
            }
            uint32_t altf4QuitLocation = currentMemoryAddress + 73;
            memcpy(&ii->altf4QuitLocation, &altf4QuitLocation, sizeof(ii->altf4QuitLocation));
            memorySlice.copyBytes(ii->altf4QuitBytes, 73, sizeof(ii->altf4QuitBytes));
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x75 && memorySlice[2] == 0x8b && memorySlice[3] == 0xcf && memorySlice[9] == 0x68) {
            
            if (memorySlice[25] == 0xe8) { // call
                alreadyInjected = true;
                break;
            }
            uint32_t noSaveQuitLocation = currentMemoryAddress + 25;
            memcpy(&ii->noSaveQuitLocation, &noSaveQuitLocation, sizeof(ii->noSaveQuitLocation));
            memorySlice.copyBytes(ii->noSaveQuitBytes, 25, sizeof(ii->noSaveQuitBytes));
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x8b && memorySlice[1] == 0x8a && memorySlice[11] == 0x68) {
            
            if (memorySlice[27] == 0xe8) { // call
                alreadyInjected = true;
                break;
            }
            uint32_t saveQuitLocation = currentMemoryAddress + 27;
            memcpy(&ii->saveQuitLocation, &saveQuitLocation, sizeof(ii->saveQuitLocation));
            memorySlice.copyBytes(ii->saveQuitBytes, 27, sizeof(ii->saveQuitBytes));
            instructionPatternsFound += 1;

        } else if (memorySlice[0] == 0x53 && memorySlice[1] == 0x68 && memorySlice[6] == 0xe8 && memorySlice[14] == 0x85) {
            
            if (memorySlice[16] == 0x0f) { // jnz
                alreadyInjected = true;
                break;
            }
            uint32_t loadFromMenuLocation = currentMemoryAddress + 16;
            memcpy(&ii->loadFromMenuLocation, &loadFromMenuLocation, sizeof(ii->loadFromMenuLocation));
            memorySlice.copyBytes(ii->loadFromMenuBytes, 18, sizeof(ii->loadFromMenuBytes));
            memorySlice.copyBytes(locationCopyBytes, 34, sizeof(locationCopyBytes));
            memcpy(&ii->DestroyMapLocation, locationCopyBytes, sizeof(ii->DestroyMapLocation));
            ii->DestroyMapLocation += currentMemoryAddress + 34 + 4;
            instructionPatternsFound += 1;

        }
    }

    if (alreadyInjected) {
        printf("amnesia is already injected\n");
        return false;
    }
    if (instructionPatternsFound > 12) {
        printf("duplicate instruction patterns were found\n");
        return false;
    }
    if (!(
        ii->gpBaseLocation != 0
        && ii->engineRunInjectionLocation != 0
        && ii->m_lstSoundEntriesOffset != 0
        && ii->cSoundEntryStopLocation != 0
        && ii->isPlayingOffset != 0
        && ii->getTotalTimeOffset != 0
        && ii->sleepCallBytes[0] == 0xff && ii->sleepCallBytes[1] == 0x15
        && ii->strncmpCallBytes[0] == 0xff && ii->strncmpCallBytes[1] == 0x15
        && ii->altf4QuitLocation != 0
        && ii->noSaveQuitLocation != 0
        && ii->saveQuitLocation != 0
        && ii->loadFromMenuLocation != 0
        )) {
        printf("couldn't find all instruction patterns\n");
        return false;
    }
    
    return true;
}


bool injectFlashbackNames(ProcessHelper* ph, const InjectionInfo* ii) {
    FileHelper fh("flashback_names.txt");
    if (!fh.f) {
        return false;
    }

    char ch = '\0';
    
    // base loop terminations on how many bytes have been written in case flashback_names.txt size was somehow changed
    bool keepReading = true;
    for (uint32_t namesWritten = 0; keepReading && namesWritten < ii->howManyFlashbackNames;) {
        uint32_t sectionPosition = 0;

        // going past the common prefix part
        if (ii->lengthOfCommonPrefix != 0) {
            for (uint32_t i = ii->lengthOfCommonPrefix; i != 0 && (keepReading = fh.getCharacter(&ch)) && ch != '\n'; i--);

            // line ended, probably because this is an empty line
            if (ch == '\n') {
                continue;
            }
        }

        // writing the flashback name past the common prefix
        while ((keepReading = fh.getCharacter(&ch)) && ch != '\n' && sectionPosition < ii->lengthOfLongestFlashbackName) {
            if (ch == '\r') {
                continue;
            }

            if (!ph->writeByte((unsigned char)ch)) {
                return false;
            }
            sectionPosition += 1;
        }

        // finishing reading the line
        while (ch != '\n' && (keepReading = fh.getCharacter(&ch)));

        // filling in the remaining space with 0x00 bytes
        // there should always be at least one 0x00 byte
        if (sectionPosition != 0 || ii->lengthOfCommonPrefix != 0) {
            for (; sectionPosition < ii->spacePerFlashbackName; sectionPosition++) {
                if (!ph->writeByte(0x00)) {
                    return false;
                }
            }
            namesWritten += 1;
        }
    }

    return true;
}


bool injectMapNamesAndDelays(ProcessHelper* ph, InjectionInfo* ii) {
    FileHelper fh("maps_and_delays.txt");
    if (!fh.f) {
        return false;
    }

    bool menuDelayWritten = false;
    char ch = '\0';
    
    // base loop terminations on how many bytes have been written in case maps_and_delays.txt size was somehow changed
    bool keepReading = true;
    for (uint32_t namesWritten = 0; keepReading && namesWritten < ii->howManyMapNames;) {
        uint32_t sectionPosition = 0;
        uint32_t delay = 0;

        // writing the map name
        while (sectionPosition < ii->lengthOfLongestMapName && (keepReading = fh.getCharacter(&ch)) && ch != '/' && ch != '\n') {
            if (ch == '\r') {
                continue;
            }

            if (!ph->writeByte((unsigned char)ch)) {
                return false;
            }

            sectionPosition += 1;
        }

        if (ch == '\n' && sectionPosition == 0) { // this was an empty line
            continue;
        }

        // going to the digits
        while (ch != '\n' && !(ch >= '0' && ch <= '9') && (keepReading = fh.getCharacter(&ch)));

        // determining the delay time
        if (ch >= '0' && ch <= '9') {
            do {
                delay *= 10;
                delay += ch - '0';

                if (delay > 0xffffff) { // ensure at least one byte stays 0 at the end of the extra memory
                    printf("map delays can't be more than 0xffffff\n");
                    return false;
                }
            } while ((keepReading = fh.getCharacter(&ch)) && (ch >= '0' && ch <= '9'));
        }

        // finishing reading the line
        while (ch != '\n' && (keepReading = fh.getCharacter(&ch)));

        if (sectionPosition == 0) { // this line had the main menu delay, so set ii->mainMenuDelay to delay
            ii->mainMenuDelay = delay;
            menuDelayWritten = true;
        } else {
            // filling in the remaining space with 0x00 bytes
            // there should always be at least one 0x00 byte
            for (; sectionPosition < ii->spacePerMapName - sizeof(uint32_t); sectionPosition++) {
                if (!ph->writeByte(0x00)) {
                    return false;
                }
            }

            // writing the delay
            for (size_t i = 0; i < sizeof(uint32_t); i++) {
                if (!ph->writeByte(((unsigned char*)(&delay))[i])) {
                    return false;
                }
            }

            namesWritten += 1;
        }
    }

    // the main menu delay wasn't found, probably because it's at the end
    while (ii->delayingMainMenu && !menuDelayWritten && keepReading) {
        fh.getCharacter(&ch); // getting the line's first character

        if (ch != '/') {
            while (ch != '\n' && (keepReading = fh.getCharacter(&ch))); // going to the next line
        } else {
            menuDelayWritten = true;

            // going to the digits
            while (ch != '\n' && !(ch >= '0' && ch <= '9') && (keepReading = fh.getCharacter(&ch)));

            // determining the delay time
            if (ch >= '0' && ch <= '9') {
                uint32_t delay = 0;

                do {
                    delay *= 10;
                    delay += ch - '0';

                    if (delay > 0xffffff) { // ensure at least one byte stays 0 at the end of the extra memory
                        printf("map delays can't be more than 0xffffff\n");
                        return false;
                    }
                } while ((keepReading = fh.getCharacter(&ch)) && (ch >= '0' && ch <= '9'));

                ii->mainMenuDelay = delay;
            }
        }
    }

    return true;
}


bool injectData(ProcessHelper* ph, InjectionInfo* ii, const char* commonPrefix) {
    // writing the common prefix
    for (size_t i = ii->lengthOfCommonPrefix; i != 0; i--) {
        if (!ph->writeByte(*commonPrefix)) {
            return false;
        }
        commonPrefix += 1;
    }

    if (ii->skippingFlashBacks) {
        // moving to the flashback names bytes
        for (size_t i = ii->spaceForCommonPrefix - ii->lengthOfCommonPrefix; i != 0; i--) {
            if (!ph->writeByte(0x00)) {
                return false;
            }
        }
    } else {
        // moving to the ii->secondsRemainingBeforeUnwait bytes
        for (size_t i = ii->spaceForCommonPrefix - ii->lengthOfCommonPrefix - sizeof(double); i != 0; i--) {
            if (!ph->writeByte(0x00)) {
                return false;
            }
        }

        // writing ii->secondsRemainingBeforeUnwait
        for (size_t i = 0; i < sizeof(ii->secondsRemainingBeforeUnwait); i++) {
            if (!ph->writeByte(ii->secondsRemainingBeforeUnwait[i])) {
                return false;
            }
        }
    }

    if (!injectFlashbackNames(ph, ii)) {
        return false;
    }

    if (ii->howManyMapNames != 0) {
        if (!injectMapNamesAndDelays(ph, ii)) {
            return false;
        }
    }

    // writing anything still in the buffer
    return ph->writeToProcess(ph->whereToReadOrWrite, ph->buffer, ph->bufferPosition) == ph->bufferPosition;
}


void prepareMainMenuDelayInstructions(const InjectionInfo* ii, unsigned char* instructionBufferPtr) {
    memcpy(instructionBufferPtr, mainMenuDelayInstructions, sizeof(mainMenuDelayInstructions));

    memcpy(&instructionBufferPtr[1], &ii->mainMenuDelay, sizeof(ii->mainMenuDelay));
    memcpy(&instructionBufferPtr[19], &ii->mainMenuDelay, sizeof(ii->mainMenuDelay));
    memcpy(&instructionBufferPtr[36], &ii->mainMenuDelay, sizeof(ii->mainMenuDelay));

    memcpy(&instructionBufferPtr[5], ii->sleepCallBytes, sizeof(ii->sleepCallBytes));
    memcpy(&instructionBufferPtr[23], ii->sleepCallBytes, sizeof(ii->sleepCallBytes));
    memcpy(&instructionBufferPtr[40], ii->sleepCallBytes, sizeof(ii->sleepCallBytes));

    memcpy(&instructionBufferPtr[11], &ii->altf4QuitBytes, sizeof(ii->altf4QuitBytes));
    memcpy(&instructionBufferPtr[29], &ii->noSaveQuitBytes, sizeof(ii->noSaveQuitBytes));
    memcpy(&instructionBufferPtr[46], &ii->saveQuitBytes, sizeof(ii->saveQuitBytes));
}


void prepareMapDelayInstructions(const InjectionInfo* ii, unsigned char* instructionBufferPtr) {
    instructionBufferPtr += sizeof(mainMenuDelayInstructions);

    memcpy(instructionBufferPtr, mapDelayInstructions, sizeof(mapDelayInstructions));

    uint32_t mapDelayInstructionsStart = ii->injectedInstructionsLocation + sizeof(mainMenuDelayInstructions);
    uint32_t firstMapNameAddress = ii->injectedDataLocation + ii->spaceForCommonPrefix + (ii->spacePerFlashbackName * ii->howManyFlashbackNames);
    uint32_t noMoreMapNamesAddress = firstMapNameAddress + (ii->spacePerMapName * ii->howManyMapNames);
    uint32_t delayOffset = ii->spacePerMapName - sizeof(uint32_t);
    uint32_t DestroyMapCallOffset = ii->DestroyMapLocation - (mapDelayInstructionsStart + 101);
    uint32_t backToAmnesiaOffset = (ii->loadFromMenuLocation + 2 + sizeof(ii->loadFromMenuBytes)) - (mapDelayInstructionsStart + 113);

    memcpy(&instructionBufferPtr[9], &noMoreMapNamesAddress, sizeof(noMoreMapNamesAddress));
    memcpy(&instructionBufferPtr[15], &firstMapNameAddress, sizeof(firstMapNameAddress));
    memcpy(&instructionBufferPtr[63], &delayOffset, sizeof(delayOffset));
    memcpy(&instructionBufferPtr[67], ii->sleepCallBytes, sizeof(ii->sleepCallBytes));
    memcpy(&instructionBufferPtr[81], ii->loadFromMenuBytes, sizeof(ii->loadFromMenuBytes));
    memcpy(&instructionBufferPtr[97], &DestroyMapCallOffset, sizeof(DestroyMapCallOffset));
    memcpy(&instructionBufferPtr[109], &backToAmnesiaOffset, sizeof(backToAmnesiaOffset));
}


void prepareFlashbackSkipInstructions(const InjectionInfo* ii, unsigned char* instructionBufferPtr) {
    instructionBufferPtr += sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions);

    memcpy(instructionBufferPtr, flashbackSkipInstructions, sizeof(flashbackSkipInstructions));

    uint32_t flashbackSkipInstructionsStart = ii->injectedInstructionsLocation + sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions);
    uint32_t commonPrefixAddress = ii->injectedDataLocation;
    uint32_t firstFlashbackNameAddress = commonPrefixAddress + ii->spaceForCommonPrefix;
    uint32_t noMoreFlashbackNamesAddress = firstFlashbackNameAddress + (ii->spacePerFlashbackName * ii->howManyFlashbackNames);
    uint32_t cSoundEntryStopOffset = ii->cSoundEntryStopLocation - (flashbackSkipInstructionsStart + 120);

    memcpy(&instructionBufferPtr[0], ii->beforeFadeOutAllBytes, sizeof(ii->beforeFadeOutAllBytes));
    memcpy(&instructionBufferPtr[12], &ii->strncmpCallBytes[2], sizeof(uint32_t));
    instructionBufferPtr[18] = ii->m_lstSoundEntriesOffset;
    instructionBufferPtr[27] = ii->nodeCSoundEntryOffset;
    memcpy(&instructionBufferPtr[44], &ii->spacePerFlashbackName, sizeof(ii->spacePerFlashbackName));
    memcpy(&instructionBufferPtr[50], &ii->lengthOfCommonPrefix, sizeof(ii->lengthOfCommonPrefix));
    memcpy(&instructionBufferPtr[56], &commonPrefixAddress, sizeof(commonPrefixAddress));
    memcpy(&instructionBufferPtr[68], &ii->lengthOfCommonPrefix, sizeof(ii->lengthOfCommonPrefix));
    memcpy(&instructionBufferPtr[73], &firstFlashbackNameAddress, sizeof(firstFlashbackNameAddress));
    memcpy(&instructionBufferPtr[84], &noMoreFlashbackNamesAddress, sizeof(noMoreFlashbackNamesAddress));
    memcpy(&instructionBufferPtr[116], &cSoundEntryStopOffset, sizeof(cSoundEntryStopOffset));
    memcpy(&instructionBufferPtr[125], &ii->spacePerFlashbackName, sizeof(ii->spacePerFlashbackName));
    memcpy(&instructionBufferPtr[132], &noMoreFlashbackNamesAddress, sizeof(noMoreFlashbackNamesAddress));
}


void prepareFlashbackWaitInstructions(const InjectionInfo* ii, unsigned char* instructionBufferPtr) {
    instructionBufferPtr += sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions);

    memcpy(instructionBufferPtr, flashbackWaitInstructions, sizeof(flashbackWaitInstructions));

    uint32_t flashbackWaitInstructionsStart = ii->injectedInstructionsLocation + sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions);
    uint32_t commonPrefixAddress = ii->injectedDataLocation;
    uint32_t firstFlashbackNameAddress = commonPrefixAddress + ii->spaceForCommonPrefix;
    uint32_t secondsRemainingBeforeUnwaitAddress = firstFlashbackNameAddress - sizeof(double);
    uint32_t waitForFlashbackByteLocation = secondsRemainingBeforeUnwaitAddress - 1;
    uint32_t noMoreFlashbackNamesAddress = firstFlashbackNameAddress + (ii->spacePerFlashbackName * ii->howManyFlashbackNames);
    uint32_t getStepSizeOffset = ii->getStepSizeLocation - (flashbackWaitInstructionsStart + 21);

    memcpy(&instructionBufferPtr[4], &waitForFlashbackByteLocation, sizeof(waitForFlashbackByteLocation));
    memcpy(&instructionBufferPtr[8], ii->beforeFadeOutAllBytes, sizeof(ii->beforeFadeOutAllBytes));
    memcpy(&instructionBufferPtr[17], &getStepSizeOffset, sizeof(getStepSizeOffset));
    memcpy(&instructionBufferPtr[22], &waitForFlashbackByteLocation, sizeof(waitForFlashbackByteLocation));
    memcpy(&instructionBufferPtr[41], &waitForFlashbackByteLocation, sizeof(waitForFlashbackByteLocation));
    memcpy(&instructionBufferPtr[46], &ii->gpBaseLocation, sizeof(ii->gpBaseLocation));
    instructionBufferPtr[54] = ii->gpBaseMpSoundOffset;
    instructionBufferPtr[57] = ii->mpSoundHandlerOffset;
    instructionBufferPtr[60] = ii->m_lstSoundEntriesOffset;
    memcpy(&instructionBufferPtr[74], &ii->strncmpCallBytes[2], sizeof(uint32_t));
    instructionBufferPtr[86] = ii->nodeCSoundEntryOffset;
    memcpy(&instructionBufferPtr[107], &ii->spacePerFlashbackName, sizeof(ii->spacePerFlashbackName));
    memcpy(&instructionBufferPtr[113], &ii->lengthOfCommonPrefix, sizeof(ii->lengthOfCommonPrefix));
    memcpy(&instructionBufferPtr[119], &commonPrefixAddress, sizeof(commonPrefixAddress));
    memcpy(&instructionBufferPtr[131], &ii->lengthOfCommonPrefix, sizeof(ii->lengthOfCommonPrefix));
    memcpy(&instructionBufferPtr[136], &firstFlashbackNameAddress, sizeof(firstFlashbackNameAddress));
    memcpy(&instructionBufferPtr[147], &noMoreFlashbackNamesAddress, sizeof(noMoreFlashbackNamesAddress));
    instructionBufferPtr[182] = ii->soundChannelOffset;
    instructionBufferPtr[193] = ii->getPausedOffset;
    instructionBufferPtr[196] = ii->getLoopingOffset;
    instructionBufferPtr[201] = ii->isPlayingOffset;
    instructionBufferPtr[210] = ii->getElapsedTimeOffset;
    instructionBufferPtr[219] = ii->getTotalTimeOffset;
    memcpy(&instructionBufferPtr[247], &ii->spacePerFlashbackName, sizeof(ii->spacePerFlashbackName));
    memcpy(&instructionBufferPtr[254], &noMoreFlashbackNamesAddress, sizeof(noMoreFlashbackNamesAddress));
    memcpy(&instructionBufferPtr[278], &secondsRemainingBeforeUnwaitAddress, sizeof(secondsRemainingBeforeUnwaitAddress));
    memcpy(&instructionBufferPtr[290], &ii->sleepCallBytes, sizeof(ii->sleepCallBytes));
}


bool injectJmpsAndCalls(const ProcessHelper* ph, const InjectionInfo* ii, bool* terminateAmnesia) {
    unsigned char call[16] = {0xe8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    unsigned char jmp[16] = {0xe9, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};

    uint32_t bytesWritten = 0;

    /////////////// injecting main menu delay calls ///////////////
    uint32_t fromAltf4QuitOffset = (ii->injectedInstructionsLocation + 0) - (ii->altf4QuitLocation + 5);
    uint32_t fromNoSaveQuitOffset = (ii->injectedInstructionsLocation + 18) - (ii->noSaveQuitLocation + 5);
    uint32_t fromSaveQuitOffset = (ii->injectedInstructionsLocation + 35) - (ii->saveQuitLocation + 5);

    if (ii->mainMenuDelay != 0) {
        memcpy(&call[1], &fromAltf4QuitOffset, sizeof(fromAltf4QuitOffset));
        bytesWritten = ph->writeToProcess(ii->altf4QuitLocation, call, sizeof(ii->altf4QuitBytes));
        if (bytesWritten != sizeof(ii->altf4QuitBytes)) {
            *terminateAmnesia = (bytesWritten != 0);
            return false;
        }

        memcpy(&call[1], &fromNoSaveQuitOffset, sizeof(fromNoSaveQuitOffset));
        bytesWritten = ph->writeToProcess(ii->noSaveQuitLocation, call, sizeof(ii->noSaveQuitBytes));
        if (bytesWritten != sizeof(ii->noSaveQuitBytes)) {
            *terminateAmnesia = (bytesWritten != 0);
            return false;
        }

        memcpy(&call[1], &fromSaveQuitOffset, sizeof(fromSaveQuitOffset));
        bytesWritten = ph->writeToProcess(ii->saveQuitLocation, call, sizeof(ii->saveQuitBytes));
        if (bytesWritten != sizeof(ii->saveQuitBytes)) {
            *terminateAmnesia = (bytesWritten != 0);
            return false;
        }
    }
    ///////////////////////////////////////////////////////////////

    ////////////////// injecting map delay jmps ///////////////////
    unsigned char loadFromMenuInjectedBytes[29] = {
        0x0f, 0x85, 0x00, 0x00, 0x00, 0x00,    // jnz to loadFromMenuBytes
        0x53,                                  // push ebx
        0x53,                                  // push esi
        0x57,                                  // push edi
        0xbb, 0x00, 0x00, 0x00, 0x00,          // mov ebx, spacePerMapName
        0x8b, 0x35, 0x00, 0x00, 0x00, 0x00,    // mov esi, dword ptr [strncmp pointer]
        0x89, 0xf8,                            // mov eax, edi // moving the map name std::string into eax
        0xe9, 0x00, 0x00, 0x00, 0x00,          // jmp to map delay instructions
        0xcc, 0xcc                             // int3 filler
    };

    uint32_t mapDelayInstructionsStart = ii->injectedInstructionsLocation + sizeof(mainMenuDelayInstructions);
    uint32_t fromQuickloadOffset = (mapDelayInstructionsStart + 81) - (ii->loadFromMenuLocation + 6);
    uint32_t fromNormalLoadOffset = (mapDelayInstructionsStart + 0) - (ii->loadFromMenuLocation + 27);

    memcpy(&loadFromMenuInjectedBytes[2], &fromQuickloadOffset, sizeof(fromQuickloadOffset));
    memcpy(&loadFromMenuInjectedBytes[10], &ii->spacePerMapName, sizeof(ii->spacePerMapName));
    memcpy(&loadFromMenuInjectedBytes[16], &ii->strncmpCallBytes[2], sizeof(uint32_t));
    memcpy(&loadFromMenuInjectedBytes[23], &fromNormalLoadOffset, sizeof(fromNormalLoadOffset));

    if (ii->howManyMapNames != 0) {
        bytesWritten = ph->writeToProcess(ii->loadFromMenuLocation, loadFromMenuInjectedBytes, sizeof(loadFromMenuInjectedBytes));
        if (bytesWritten != sizeof(loadFromMenuInjectedBytes)) {
            *terminateAmnesia = (bytesWritten != 0);
            return false;
        }
    }
    ///////////////////////////////////////////////////////////////

    ///// injecting flashback skip jmp or flashback wait call /////
    if (ii->howManyFlashbackNames != 0) {
        uint32_t flashbackSkipOrWaitInstructionsStart = ii->injectedInstructionsLocation + sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions);
        uint32_t fromBeforeFadeOutAllOffset = (flashbackSkipOrWaitInstructionsStart + 0) - (ii->beforeFadeOutAllLocation + 5);

        memcpy(&call[1], &fromBeforeFadeOutAllOffset, sizeof(fromBeforeFadeOutAllOffset));

        bytesWritten = ph->writeToProcess(ii->beforeFadeOutAllLocation, call, sizeof(ii->beforeFadeOutAllBytes));
        if (bytesWritten != sizeof(ii->beforeFadeOutAllBytes)) {
            *terminateAmnesia = (bytesWritten != 0);
            return false;
        }

        if (!ii->skippingFlashBacks) {
            uint32_t fromGetStepSizeCallLocationOffset = (flashbackSkipOrWaitInstructionsStart + 16) - (ii->engineRunInjectionLocation + 5);

            memcpy(&call[1], &fromGetStepSizeCallLocationOffset, sizeof(fromGetStepSizeCallLocationOffset));

            uint32_t expectedBytesWritten = 5; // overwriting a call instruction
            bytesWritten = ph->writeToProcess(ii->engineRunInjectionLocation, call, expectedBytesWritten);
            if (bytesWritten != expectedBytesWritten) {
                *terminateAmnesia = (bytesWritten != 0);
                return false;
            }
        }
    }
    ///////////////////////////////////////////////////////////////

    return true;
}


bool injectDataAndInstructions(ProcessHelper* ph, InjectionInfo* ii, const char* commonPrefix, bool* terminateAmnesia) {
    if (!injectData(ph, ii, commonPrefix)) {
        return false;
    }
    
    unsigned char instructionBuffer[512] = {};
    static_assert(
        sizeof(instructionBuffer) >= (sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions) + sizeof(flashbackWaitInstructions)),
        "instructionBuffer isn't big enough\n"
    );

    if (ii->mainMenuDelay != 0) {
        prepareMainMenuDelayInstructions(ii, instructionBuffer);
    }

    if (ii->howManyMapNames != 0) {
        prepareMapDelayInstructions(ii, instructionBuffer);
    }

    if (ii->howManyFlashbackNames != 0) {
        if (ii->skippingFlashBacks) {
            prepareFlashbackSkipInstructions(ii, instructionBuffer);
        } else {
            prepareFlashbackWaitInstructions(ii, instructionBuffer);
        }
    }

    ph->writeToProcess(ii->injectedInstructionsLocation, instructionBuffer, sizeof(instructionBuffer));

    DWORD mandatoryArgument = 0;
    if (!VirtualProtectEx(
        ph->processHandle,
        (LPVOID)ii->injectedInstructionsLocation,
        ii->spaceForInstructions,
        PAGE_EXECUTE,
        &mandatoryArgument)) {
        printf("error when giving the injected instructions area PAGE_EXECUTE protection with VirtualProtectEx: %d\n", GetLastError());
        return false;
    }

    // do this last in case anything else fails
    if (!injectJmpsAndCalls(ph, ii, terminateAmnesia)) {
        return false;
    }
    
    return true;
}


int main() {
    InjectionInfo ii;

    NTFUNCTION NtSuspendProcess = nullptr;
    NTFUNCTION NtResumeProcess = nullptr;
    bool ntFunctionsFound = findNtFunctions(&NtSuspendProcess, &NtResumeProcess);

    bool isSteamVersion = false;
    DWORD amnesiaPid = findAmnesiaPid(&isSteamVersion);
    if (amnesiaPid == (DWORD)-1){
        getExitInput(false);
        return EXIT_FAILURE;
    }

    const wchar_t* amnesiaName = isSteamVersion ? steamName : noSteamName;
    ProcessHelper ph(amnesiaPid, amnesiaName);
    if (ph.textSegmentLocation == 0) {
        getExitInput(false);
        return EXIT_FAILURE;
    }

    bool skippingFlashbacks = false;
    bool delayMaps = false;
    bool allowUnexpectedGameVersions = false;
    bool checkForToolUpdates = false;
    bool allowNotFullyUpdatedTool = false;
    double secondsRemainingBeforeUnwait = 0.0;

    if (!readSettingsFile(
        &skippingFlashbacks,
        &delayMaps,
        &allowUnexpectedGameVersions,
        &checkForToolUpdates,
        &allowNotFullyUpdatedTool,
        &secondsRemainingBeforeUnwait
        )) {
        getExitInput(false);
        return EXIT_FAILURE;
    }
    ii.skippingFlashBacks = skippingFlashbacks;

    // determining if this version of the tool is the most recent version //
    if (checkForToolUpdates) {
        printf("checking for updates. to skip this, change the \"check for tool updates\" setting to \"y\".\n");

        HINTERNET hInternet = nullptr;
        HINTERNET hConnection = nullptr;
        HINTERNET hData = nullptr;
        bool isMostRecentVersionResult = false;

        // resources acquired:
        // hInternet (1)
        // hConnection (2)
        // hData (3)
        if (!isMostRecentVersion(&hInternet, &hConnection, &hData, &isMostRecentVersionResult)) {
            printf("couldn't determine if this version of the tool is the most recent version\n");
        }

        if (hData != nullptr) {
            InternetCloseHandle(hData);          // hData released (3)
        }
        if (hConnection != nullptr) {
            InternetCloseHandle(hConnection);    // hConnection released (2)
        }
        if (hInternet != nullptr) {
            InternetCloseHandle(hInternet);      // hInternet released (1)
        }

        if (isMostRecentVersionResult) {
            printf("this is the most recent version of this tool\n");
        } else if (!allowNotFullyUpdatedTool) {
            printf("to use this tool when it isn't, or might not be, the most recent version, change the \"allow not fully updated tool\" setting to \"y\"\n");
            getExitInput(false);
            return EXIT_FAILURE;
        }
    }
    ////////////////////////////////////////////////////////////////////////

    if ((!isSteamVersion && ph.remainingBytesToRead != 6467584) || (isSteamVersion && ph.remainingBytesToRead != 6479872)) {
        printf(
            "\
WARNING: %ls's .text segment is %u bytes, but this tool was made for versions which are 6467584 bytes and 6479872 bytes.\n\
this tool might not work correctly with other versions of the game.%s\n",
            amnesiaName,
            ph.remainingBytesToRead,
            allowUnexpectedGameVersions ? "" : "\nto use this tool with other versions of Amnesia, change the \"allow unexpected game versions\" setting to \"y\"."
        );
        if (!allowUnexpectedGameVersions) {
            getExitInput(false);
            return EXIT_FAILURE;
        }
    }

    memcpy(&ii.secondsRemainingBeforeUnwait, &secondsRemainingBeforeUnwait, sizeof(double));

    uint32_t howManyFlashbackNames = 0;
    uint32_t lengthOfLongestFlashbackName = 0;
    uint32_t lengthOfCommonPrefix = 0;
    char commonPrefix[320] = {};

    if (!preprocessFlashbackNamesFile(
        &howManyFlashbackNames,
        &lengthOfLongestFlashbackName,
        &lengthOfCommonPrefix,
        sizeof(commonPrefix) - 1,
        commonPrefix
        )) {
        getExitInput(false);
        return EXIT_FAILURE;
    }

    uint32_t howManyMapNames = 0;
    uint32_t lengthOfLongestMapName = 0;
    bool delayingMainMenu = false;
    if (delayMaps) {
        if (!preprocessMapDelaysFile(&howManyMapNames, &lengthOfLongestMapName, &delayingMainMenu)) {
            getExitInput(false);
            return EXIT_FAILURE;
        }
    }

    if (!findInstructions(&ii, &ph)) {
        getExitInput(false);
        return EXIT_FAILURE;
    }

    ///// finding how much space to allocate in Amnesia /////
    // space for flashback name area
    // ii.secondsRemainingBeforeUnwait is also stored here at the last 8 bytes of the common prefix area
    // a byte used to check if a flashback might be happening is also stored in the common prefix area behind ii.secondsRemainingBeforeUnwait
    uint32_t spaceForCommonPrefix = lengthOfCommonPrefix + 1;
    spaceForCommonPrefix += (sizeof(ii.secondsRemainingBeforeUnwait) * (!skippingFlashbacks)) + (!skippingFlashbacks);
    spaceForCommonPrefix = ((spaceForCommonPrefix / 16) + ((spaceForCommonPrefix % 16) != 0)) * 16;
    uint32_t spacePerFlashbackName = lengthOfLongestFlashbackName - lengthOfCommonPrefix;
    spacePerFlashbackName = (((spacePerFlashbackName + 1) / 16) + (((spacePerFlashbackName + 1) % 16) != 0)) * 16;
    uint32_t sizeOfFlashbackNameArea = (spacePerFlashbackName * howManyFlashbackNames) + spaceForCommonPrefix;

    // space for maps and delays area
    uint32_t spacePerMapName = 0;
    uint32_t sizeOfMapsAndDelaysArea = 0;
    if (delayMaps) {
        spacePerMapName = (((lengthOfLongestMapName + 1 + sizeof(uint32_t)) / 16) + (((lengthOfLongestMapName + 1 + sizeof(uint32_t)) % 16) != 0)) * 16;
        sizeOfMapsAndDelaysArea = spacePerMapName * howManyMapNames;
    }

    // getting the page size
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    DWORD pageSize = sysInfo.dwPageSize;

    // space for instructions
    uint32_t sizeOfInstructionArea = sizeof(mainMenuDelayInstructions) + sizeof(mapDelayInstructions) + sizeof(flashbackWaitInstructions);
    uint32_t spaceForInstructions = ((sizeOfInstructionArea / pageSize) + ((sizeOfInstructionArea % pageSize) != 0)) * pageSize;

    // total space
    uint32_t totalSpaceNeeded = spaceForInstructions + sizeOfMapsAndDelaysArea + sizeOfFlashbackNameArea;
    /////////////////////////////////////////////////////////

    ii.howManyFlashbackNames = howManyFlashbackNames;
    ii.lengthOfLongestFlashbackName = lengthOfLongestFlashbackName;
    ii.lengthOfCommonPrefix = lengthOfCommonPrefix;
    ii.howManyMapNames = howManyMapNames;
    ii.lengthOfLongestMapName = lengthOfLongestMapName;
    ii.spaceForCommonPrefix = spaceForCommonPrefix;
    ii.spacePerFlashbackName = spacePerFlashbackName;
    ii.sizeOfFlashbackNameArea = sizeOfFlashbackNameArea;
    ii.spacePerMapName = spacePerMapName;
    ii.sizeOfMapsAndDelaysArea = sizeOfMapsAndDelaysArea;
    ii.spaceForInstructions = spaceForInstructions;
    ii.delayingMainMenu = delayingMainMenu;

    LPVOID extraMemoryPtr = VirtualAllocEx(
        ph.processHandle,
        nullptr,
        totalSpaceNeeded,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );                                                                          // resource acquired
    if (extraMemoryPtr == nullptr) {
        printf("error when using VirtualAllocEx: %d\n", GetLastError());
        return false;
    }
    ii.injectedInstructionsLocation = (uint32_t)extraMemoryPtr;
    ii.injectedDataLocation = ii.injectedInstructionsLocation + spaceForInstructions;

    bool terminateAmnesia = false; // terminate Amnesia is there's a partially written injected jmp or call

    // preparing ph for writing
    ph.whereToReadOrWrite = ii.injectedDataLocation;
    ph.bufferPosition = 0;
    
    if (!injectDataAndInstructions(&ph, &ii, commonPrefix, &terminateAmnesia)) {
        uint32_t lastErrorCode = GetLastError(); // saving the error from injectDataAndInstructions for TerminateProcess

        if (!VirtualFreeEx(ph.processHandle, extraMemoryPtr, 0, MEM_RELEASE)) { // resource released
            printf("WARNING: error when using VirtualFreeEx: %d\ncouldn't release VirtualAllocEx memory\n", GetLastError());
        }

        if (terminateAmnesia) {
            if (!TerminateProcess(ph.processHandle, lastErrorCode)) {
                printf(
                    "WARNING: error when using TerminateProcess to close %ls: %d\nCouldn't close %ls. This session of %ls may crash.\n",
                    amnesiaName,
                    GetLastError(),
                    amnesiaName,
                    amnesiaName
                );
            } else {
                printf("%ls closed to prevent it from crashing\n", amnesiaName);
            }
        }

        getExitInput(false);
        return EXIT_FAILURE;
    }

    getExitInput(true);

    return EXIT_SUCCESS;
}
