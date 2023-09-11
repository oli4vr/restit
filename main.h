#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#define MAX_SCHEDS 1024
#define MAX_SCHEDN 1023

unsigned char securestr[]="7a`y%w6evZ_30fPlkXpTBDKp]?TFvoQ[AG}mt7|;U5e32lShqAPE8.B$%7{lyD]";

typedef struct _result_record {
 unsigned char result_string[256];
 unsigned char result_value[32];
} result_record;

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

typedef struct _cfgmain {
 int restport;
} cfgmain;

