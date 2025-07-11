# Slack C2
This project was designed as a proof of concept/training ground for me to test the concepts I was learning in SEC670: Developing Windows Implants & Shellcode & C2, MalDev Academy, and other sources. Incredibly huge shoutout to Jonathan Reiter from SANS for developing a course for implant development.

![SlackC2](images/SlackC2.png)


# How can I test it?
You'll need to create a Slack App and assign OAuth tokens. I didn't do anything too fancy, and I just hardcoded my bot token in the implant located in the `Config.c`. You'll also need to assign the proper permissions on your bot token, like channel:read, etc. You can find more information on Slack's API documentation. This project was really just to challenge myself to become much more adept at C and general programming. This is just a simple framework that supports minimal commands, and should not actually be used for anything but R&D purposes if at all. 

# Lessons Learned
These are simply my thoughts, observations, and struggles as I went through this process. 

- Using a 3rd party platform for C2 can impose certain limitations
	
	- If you might not be able to upload/download files as easily if your 3rd party platform (Slack, Google Drive, etc) scans the files and prevents their upload based on their determination of the file. You already might have to fight running SharpUp on the target, but now you need to fight with the site hosting your files too.
	   
	- You might only be able to do X requests in a minute. Is that a problem? Maybe, maybe not. Do you have more than one implant? Then yea, probably need to implement a backoff function of some kind to throttle the requests.

- Global variables are super convenient, but you should try not using them. These are generally not thread safe, and concurrent read/writes might prove problematic

- Memory management in C can be hard. Previously, I only ever wrote shellcode loaders. That's pretty easy, since you generally know before hand the fixed size you need to allocate. But what happens when you need to obtain the command from your C2. Is the command "ls", or "ThisIsSomeReallyLongArbitraryCommandToProveAPoint"? Your implant sure doesn't know, and will need to dynamically allocate enough size to hold the command you're wanting to parse and execute. What about having a buffer that stores the result of the command? Is it a single line of text, "WALMART/sam.altman"? Or do you need to append to a buffer for each line of output while you're iterating through a process list? Again, your implant wont know, and will need to be prepared to dynamically allocate memory and also resize a larger buffer as needed. Once I made custom functions that could overwrite an existing buffer, or append to one, I started getting WAY less access violation bugs, and eventually stopped encountering them altogether. I would recommend anybody writing in pure C to make their own wrapper functions that safely (Or at least in a function that can be easily patches) to help with their memory management, especially for functions like VirtualAlloc().
  
- Make sure you design your implant with kill switches, or with an exit function. I made the mistake of running some implants that I couldn't kill because I was only developing in the context of having a single implant. That brings me to my next point:

- Design the implant with multiple being able to run at the same time. Originally, I designed an implant to parse the last X messages from a slack channel, ignore the ones with replies, and reply to each message in a thread with the results from executed command. This was great for a single implant per channel. I did not think about this when I was having X implants running at the same time fighting to respond first to a message as a "first come first serve" style of operation. Eventually, I had to make a new channel for each implant I compiled per host/user context.

- As a general programming philosophy, writing smaller functions that do simple things instead of larger functions that do lots of things is best. I wrote each command function (ps, upload, shell, username, etc) such that it would take in a struct that held ~5 elements. However, I was only accessing 2 in most of my functions, and it was unnecessary to parse out these values from a struct rather than accept only the parameters I wanted. 
```c
/*
This at the time seemed easier and more clean. After all, I'm only passing
one variable! How neat! However, I'd consider this to be a pretty bad practice
that negatively effects the readability of the code. I can't really infer what
the function is doing from the parameters, and I can't tell what members of the
slackCmd variable are important.
*/
ps(SlackCmd* slackCmd) {
  
  // Parse the value we want
  slackCmd->buffer
  slackCmd->bufferSize
  
  // Do things

}

/*
This second version of the code allows me to reuse this function in other programs.
If I were to try and use the function above in a new function, I'd have to untangle
the Slack-specific programming logic out of it.
*/
ps(char* buffer, DWORD* bufferSize) {
  
  // Do things

}

```

- Using AI was most helpful with writing functions that would have taken me way too long to write, and that I felt were not worth the time investment. For example, parsing JSON in C. I began to use cJSON library which helped a lot, but ChatGPT did a pretty good job of writing a custom JSON parser for me in C without the need to reference that external code.

- If this were to work on a Windows 7 machine (Don't ask) you need to do some extra work with forcing TLS 1.2 to be able to reach out to Slack. The default SSL won't cut it. 
