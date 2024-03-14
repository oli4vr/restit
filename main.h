#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/socket.h>

#define MAX_SCHEDS 1024
#define MAX_SCHEDN 1023

unsigned char securestr[]="7a`y%w6evZ_30fPlkXpTBDKp]?TFvoQ[AG}mt7|;U5e32lShqAPE8.B$%7{lyD]";

// Results are stored in a struct with 2 strings : string & value
typedef struct _result_record {
 unsigned char result_string[256];
 unsigned char result_value[32];
 unsigned char result_message[256];
} result_record;

// Struct for a command schedule entry (1 sensor)
typedef struct _cmdsched {
 unsigned char vault[256];
 unsigned char vaultfile[256];
 unsigned char keystring[256];
 unsigned char commands[8127];
 result_record results[256];
 unsigned char resultsnum;
 uint32_t seconds;
 pthread_t thread;
} cmdsched;

// Struct for general configuration parameters
typedef struct _cfgmain {
 int restport;
} cfgmain;

typedef struct _httpreq {
 unsigned char method[16];
 unsigned char path[512];
} httpreq;
