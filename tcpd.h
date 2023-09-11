#define MAXPENDING 64

typedef struct _tcpcc {
 int sock;
 void * data;
} tcpcc;

typedef struct _tcpd {
 void * (*hand)(void*);
 void * data;
 int port;
} tcpd;

void * tcpd_daemon(void *p);
