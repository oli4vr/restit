#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <inttypes.h>
#include "tcpd.h"

int CreateTCPServerSocket(int port)
{
 int sock;                        /* socket to create */
 struct sockaddr_in ServAddr; /* Local address */

 /* Create socket for incoming connections */
 if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
  return -1;
      
 /* Construct local address structure */
 memset(&ServAddr, 0, sizeof(ServAddr));   /* Zero out structure */
 ServAddr.sin_family = AF_INET;                /* Internet address family */
 ServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
 ServAddr.sin_port = htons(port);              /* Local port */

 /* Bind to the local address */
 if (bind(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr)) < 0)
  return -2;

 /* Mark the socket so it will listen for incoming connections */
 if (listen(sock, MAXPENDING) < 0)
  return -3;

 return sock;
}

int AcceptTCPConnection(int servSock)
{
 int clntSock;                    /* Socket descriptor for client */
 struct sockaddr_in ClntAddr; /* Client address */
 unsigned int clntLen;            /* Length of client address data structure */

 /* Set the size of the in-out parameter */
 clntLen = sizeof(ClntAddr);
    
 /* Wait for a client to connect */
 if ((clntSock = accept(servSock, (struct sockaddr *) &ClntAddr, &clntLen)) < 0)
  return -1;
    
 /* clntSock is connected to a client! */
    
 return clntSock;
}

void * tcpd_daemon(void *p) {
 int s,c;
 tcpcc *m;
 pthread_t thr;
 tcpd *t=(tcpd *)p;

 if (p==NULL) return NULL;

 while (1) {
  s=CreateTCPServerSocket(t->port);
  if (s<0) {
   sleep(5);
  } else {
  
   c=AcceptTCPConnection(s);
   while (c >= 0) {
    m=(tcpcc*)malloc(sizeof(tcpcc));
    m->sock=c;
    m->data=t->data;
    pthread_create(&thr, NULL, t->hand, m);
    pthread_detach(thr);
    usleep(1000);
    c=AcceptTCPConnection(s);
   }
   close(s);
   sleep(2);
  }
 }
}

