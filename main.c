/* main.c
by Olivier Van Rompuy

restit application main c file

*/

#include "main.h"
#include "entropy.h"
#include "inifind.h"
#include "tcpd.h"

#define TCP_BUF_SIZE 65536

unsigned char basepath[256]={0};

cmdsched *scheds[MAX_SCHEDS]={NULL};
int schedc=0;

cfgmain cfg;

unsigned char stopsrc=0;

cmdsched * manifest_nextsched(unsigned char ** inbuff, unsigned char * tpath, unsigned char mode) {
//Process 1 line in the manifest csv
//Mode 0 = Get script from file
//Mode 1 = Get script from manifest vault
//Returns NULL pointer if csv formatting is incorrect
//Returns pointer to cmdsched
    unsigned char tmp[256]={0};
    unsigned char vault[256]={0};
    unsigned char vaultfile[256]={0};
    unsigned char keystring[256]={0};
    unsigned char commands[8127]={0};
    uint32_t seconds;
    unsigned char * buffer=*inbuff;
    unsigned char * c=buffer, * p=buffer;
    long int offset;
    int rc,rb;
    cmdsched * rcsched;
    FILE* fp;

    while (*c=='\n') {c++;} ; p=c;
    while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(vault,p,256);
    snprintf(vaultfile,256,"%s/.restit.%s.manifest",tpath,vault);
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(keystring,p,256);
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(tmp,p,256);
    tmp[255]=0;
    seconds=atoi(tmp);
    if (seconds < 1) return NULL;
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    if (mode==0) {
        strncpy(tmp,p,256);
        tmp[255]=0;
        fp=fopen(tmp,"r+b");
        if (fp==NULL) return NULL;
        rc=fread(commands,1,8126,fp);
        if (rc<1) return NULL;
        fclose(fp);
    } else {
        offset=entropy_search(commands,keystring,securestr,vaultfile,2);
        if (offset<0) return NULL;
    }

    c++;*inbuff=c;

    rcsched=malloc(sizeof(cmdsched));

    memcpy(rcsched->vaultfile,vaultfile,256);
    memcpy(rcsched->vault,vault,256);
    memcpy(rcsched->keystring,keystring,256);
    memcpy(rcsched->commands,commands,8127);
    rcsched->seconds=seconds;
    rcsched->resultsnum=0;
    return rcsched;
}

void cleanup_manifesto() {
//Free dynamically allocated memory
    int n=0;
    cmdsched ** cp=scheds;
    for(;n<MAX_SCHEDS;n++) {
        if (*cp!=NULL) {free(*cp); *cp=NULL;}
        cp++;
    }
    schedc=0;
}

int generate_manifesto(unsigned char * fname, unsigned char * tpath) {
//Generate the manifesto vault files
    FILE * fp;
    int rc,n;
    unsigned char csvfile[MESSAGE_SIZE]={0};
    unsigned char buffer[MESSAGE_SIZE]={0};
    unsigned char *bp=buffer;
    unsigned char dvault[256];
    cmdsched * cp;
    mkdir(tpath,S_IRWXU);

    cleanup_manifesto();

    fp=fopen(fname,"r+b");
    if (fp==NULL) return -1;

    rc=fread(buffer,1,MESSAGE_SIZE,fp);
    fclose(fp);

    //fprintf(stderr,"%s\n",buffer);
    if (rc<1) return -2;
    buffer[MESSAGE_SIZE-1]=0;
    
    memcpy(csvfile,buffer,MESSAGE_SIZE);

    scheds[schedc]=manifest_nextsched(&bp,tpath,0);
    cp=scheds[schedc];
    schedc++;
    while (cp!=NULL) {
        cp=scheds[schedc];
        scheds[schedc]=manifest_nextsched(&bp,tpath,0);
        cp=scheds[schedc];
        schedc++;
    }
    schedc--;
    // Determine default vault file + remove existing + generate new one
    snprintf(dvault,256,"%s/.restit.default.manifest",tpath);
    remove(dvault);
    rc=entropy_append(csvfile,"manifest.csv",securestr,dvault,16);

    //Remove old vault files
    for(n=0;n<schedc;n++) {
        cp=scheds[n];
        remove(cp->vaultfile);
    }

    //Appending entries to vault files
    for(n=0;n<schedc;n++) {
        cp=scheds[n];
        //fprintf(stderr,"Appending %s %s \n",cp->vaultfile,cp->keystring);
        if (cp!=NULL)
            rc=entropy_append(cp->commands,cp->keystring,securestr,cp->vaultfile,2); 
    }
    return schedc;
}

int load_manifesto(unsigned char * spath) {
//Load the manifesto
    FILE * fp;
    int rc,n;
    long int offset;
    unsigned char buffer[MESSAGE_SIZE]={0};
    unsigned char *bp=buffer;
    unsigned char dvault[256];
    cmdsched * cp;

    cleanup_manifesto();

    snprintf(dvault,256,"%s/.restit.default.manifest",spath);

    offset=entropy_search(buffer,"manifest.csv",securestr,dvault,16);
    if (offset<0) return -1;

    buffer[MESSAGE_SIZE-1]=0;
    
    scheds[schedc]=manifest_nextsched(&bp,spath,1);
    cp=scheds[schedc];
    schedc++;
    while (cp!=NULL) {
        cp=scheds[schedc];
        scheds[schedc]=manifest_nextsched(&bp,spath,1);
        cp=scheds[schedc];
        schedc++;
    }
    schedc--;

    for(n=0;n<schedc;n++) {
        cp=scheds[n];
    }
    return schedc;
}

int exec_sched(cmdsched * c) {
    int rc;
    unsigned char buffer[MESSAGE_SIZE+1]={0};
    unsigned char *sp=buffer;
    unsigned char neof=1,nomsg=1;
    unsigned char *rcstr, *outstr, *outmsg;

    FILE * pipe;

    pipe=popen(c->commands,"r");
    if (pipe==NULL) return -1;
    rc=fread(buffer,1,MESSAGE_SIZE,pipe);
    pclose(pipe);
    c->resultsnum=0;
    while (neof) {
        rcstr=sp;
        while (*sp!=' ') {if (*sp==0) return 0; sp++;}
        outmsg=sp;
        *sp=0; sp++;
        outstr=sp;
        while (*sp!=10 && *sp!=0) {
            if (*sp==' ' && nomsg) {*sp=0;sp++;outmsg=sp;nomsg=0;}
            else {sp++;}
        }
        if (*sp==0) neof=0;
        *sp=0; sp++;

        strncpy(c->results[c->resultsnum].result_string,outstr,256);
        strncpy(c->results[c->resultsnum].result_value,rcstr,32);
        strncpy(c->results[c->resultsnum].result_message,outmsg,256);
        c->resultsnum++;
    }
    return (rc);
}

int ini_loadcfg(cfgmain * c,unsigned char * inifile) {
    int rc;
    unsigned char tmp[256];
    rc=findini(inifile,"General","RestPort",tmp);
    if (rc<1) {tmp[0]='0';tmp[1]=0;}
    c->restport=atoi(tmp);
    if (c->restport==0) c->restport=40480;
}

void * cmdthread(void * data) {
    int rc=0;
    cmdsched * c=data;
    sleep(rand()&7);
    while(!stopsrc) {
        rc=exec_sched(c);
        sleep(c->seconds);
    }
}

int buildjson(unsigned char * jsonout,httpreq *request) {
    int n,m,max,jsonpos=0,len;
    unsigned char * jsonpnt=jsonout,comma=0;
    cmdsched * c;
    // HTTP Header :
    strncpy(jsonpnt,"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"restit\":{\"results\":[",128);
    jsonpos+=strnlen(jsonpnt,256);
    jsonpnt+=jsonpos;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     //if (n>0 && c->resultsnum>0) {
/*     if (comma) {
      *jsonpnt=',';
       jsonpnt++;
       jsonpos++;
     }*/
     for(m=0;m<(c->resultsnum);m++) {
        if (*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) {
         if (comma) {
            *jsonpnt=',';
            jsonpnt++;
            jsonpos++;
         }
         comma=1;
         sprintf(jsonpnt,"{\"%s\":{\"%s\":{\"%s\":\"%s\",\"Message\":\"%s\"}}}",c->vault,c->keystring,c->results[m].result_string,c->results[m].result_value,c->results[m].result_message);
         len=strnlen(jsonpnt,256);
         jsonpos+=len;
         jsonpnt+=len;
        }

     }
    }
    jsonpnt--;
    if (*jsonpnt!=',') {jsonpnt++;}

    *jsonpnt=']';
    jsonpnt++;
    *jsonpnt='}';
    jsonpnt++;
    *jsonpnt='}';
    jsonpnt++;
    jsonpos+=3;
    *jsonpnt=0;
    return jsonpos;
}

unsigned char valuetypecheck(unsigned char *s) {
 unsigned char *c=s;
 unsigned char val=1;
 unsigned char dot=0;
 int n=0,l=strnlen(s,16);

 if (*c=='-') {c++;}
 for(;n<l&&val;n++) {
  if (*c=='.') {dot++;}
  else if (*c<'0' && *c>'9') {val=0;}
  c++;
 }
 if (val==1 && dot==1) {val=2;}
 if (dot>1) {val=0;}

 return val;
}

int buildprtg(unsigned char * jsonout,httpreq *request) {
    int n,m,max,jsonpos=0,len;
    unsigned valtype;
    unsigned char * jsonpnt=jsonout,comma=0;
    cmdsched * c;
    // HTTP Header :
    strncpy(jsonpnt,"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"prtg\":{\"result\":[",256);
    jsonpos+=strnlen(jsonpnt,256);
    jsonpnt+=jsonpos;
    comma=0;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     //if (n>0 && c->resultsnum>0) {
/*     if (comma) {
      *jsonpnt=',';
       jsonpnt++;
       jsonpos++;
     }*/
     for(m=0;m<(c->resultsnum);m++) {
        if (*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) {
         if (comma) {
            *jsonpnt=',';
            jsonpnt++;
            jsonpos++;
         }
	 comma=1;
	 valtype=valuetypecheck(c->results[m].result_value);
	 if (valtype==2) {
           sprintf(jsonpnt,"{\"channel\":\"%s\",\"value\":\"%0.02f\"",c->results[m].result_string,atof(c->results[m].result_value));

	 } else {
           sprintf(jsonpnt,"{\"channel\":\"%s\",\"value\":\"%s\"",c->results[m].result_string,c->results[m].result_value);
	 }
         len=strnlen(jsonpnt,256);
         jsonpos+=len;
         jsonpnt+=len;
         if (request->limitmode) {
	   if (valtype==2) {
             sprintf(jsonpnt,",\"float\":\"1\"");
             len=strnlen(jsonpnt,256);
             jsonpos+=len;
             jsonpnt+=len;
	   }
           sprintf(jsonpnt,",\"limitmode\":\"1\"");
           len=strnlen(jsonpnt,256);
           jsonpos+=len;
           jsonpnt+=len;
	   if (request->warnhigh<9999999999999) {
	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMaxWarning\":\"%0.02f\"",request->warnhigh); }
	     else {sprintf(jsonpnt,",\"LimitMaxWarning\":\"%0.00f\"",request->warnhigh);}
             len=strnlen(jsonpnt,256);
             jsonpos+=len;
             jsonpnt+=len;
	   }
	   if (request->crithigh<9999999999999) {
	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMaxError\":\"%0.02f\"",request->crithigh); }
	     else {sprintf(jsonpnt,",\"LimitMaxError\":\"%0.00f\"",request->crithigh);}
             len=strnlen(jsonpnt,256);
             jsonpos+=len;
             jsonpnt+=len;
	   }
	   if (request->warnlow>-9999999999999) {
	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMinWarning\":\"%0.02f\"",request->warnlow); }
	     else {sprintf(jsonpnt,",\"LimitMinWarning\":\"%0.00f\"",request->warnlow);}
             len=strnlen(jsonpnt,256);
             jsonpos+=len;
             jsonpnt+=len;
	   }
	   if (request->critlow>-9999999999999) {
	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMinError\":\"%0.02f\"",request->critlow); }
	     else {sprintf(jsonpnt,",\"LimitMinError\":\"%0.00f\"",request->critlow);}
             len=strnlen(jsonpnt,256);
             jsonpos+=len;
             jsonpnt+=len;
	   }
	 }

	 *jsonpnt='}';
	 jsonpnt++;
	 jsonpos++;
        }
     }
    }
    jsonpnt--;
    if (*jsonpnt!=',') {jsonpnt++;}

    if (m>0) {sprintf(jsonpnt,"],\"Text\":\"%s\"}}",c->results[m-1].result_message);}
    else {sprintf(jsonpnt,"]}}");}
    jsonpos+=strnlen(jsonpnt,256);
    jsonpnt+=strnlen(jsonpnt,256);
    *jsonpnt=0;
    return jsonpos;
}

//Process the http header and determine method and path
int str2httpreq(unsigned char * str, httpreq * request) {
 unsigned char * cc=str;
 unsigned char *c1, *c2, *c3;
 unsigned char *vars;
 unsigned char tmp[512]={0};
 unsigned char skipval=0;
 int n=0,c=0;
 if (request==NULL) return -1;
 for(;n<TCP_BUF_SIZE && c<2;n++) {
  if (*cc==' ') {*cc=0; c++; c2=c1; c1=cc+1;}
  cc++;
 }
 
 strncpy(request->method,str,16);
 strncpy(request->path,c2,512);

 strncpy(tmp,c2,512);

 // In case there is a ? character, split the string.
 cc=tmp;
 n=0;
 while (n<511 && *cc!='?' && *cc!=0) {cc++;n++;}
 vars=cc+(*cc=='?');
 *cc=0;

 // Process vars, if applicable
 request->warnhigh=9999999999999;
 request->warnlow=-9999999999999;
 request->crithigh=9999999999999;
 request->critlow=-9999999999999;
 request->warnon[0]=0;
 request->criton[0]=0;
 request->limitmode=0;
 if (*vars) {
  cc=vars;
  n=0;
  while (*cc!=0 && n<300) {
   c1=cc;
   while (n<300 && *cc!='=' && *cc!='&' && *cc!=0) {cc++;n++;}
   if (*cc=='=')  {
    *cc=0;
    cc++;
    c2=cc;
    while (n<300 && *cc!='&' && *cc!=0) {cc++;n++;}
    *cc=0;
    cc++;
   } else {
    *cc=0;
    c2=cc;
    cc++;
   }
   if (strncmp(c1,"warnhigh",16)==0) {
     request->warnhigh=atof(c2);
     request->limitmode=1;
   } else if (strncmp(c1,"warnlow",16)==0) {
     request->warnlow=atof(c2);
     request->limitmode=1;
   } else if (strncmp(c1,"crithigh",16)==0) {
     request->crithigh=atof(c2);
     request->limitmode=1;
   } else if (strncmp(c1,"critlow",16)==0) {
     request->critlow=atof(c2);
     request->limitmode=1;
   } else if (strncmp(c1,"warnon",16)==0) {
     strncpy(request->warnon,c2,64);
     request->warnon[63]=0;
   } else if (strncmp(c1,"criton",16)==0) {
     strncpy(request->criton,c2,64);
     request->warnon[63]=0;
   }
  }
  if (request->warnhigh>999999999999) {request->warnhigh=request->crithigh;}
  if (request->warnlow<-999999999999) {request->warnlow=request->critlow;}
 }

 // Process the path and get subitem 1/2/3
 cc=tmp;
 n=0;
 if (*cc == '/') {cc++;n++;}
 c1=cc;
 while (n<511 && *cc!='/' && *cc!=0) {cc++;n++;}
 *cc=0;cc++;c2=cc;
 while (n<511 && *cc!='/' && *cc!=0) {cc++;n++;}
 *cc=0;cc++;c3=cc;
 while (n<511 && *cc!='/' && *cc!=0) {cc++;n++;}
 *cc=0;

 strncpy(request->sitem1,c1,32);request->sitem1[31]=0;
 strncpy(request->sitem2,c2,32);request->sitem2[31]=0;
 strncpy(request->sitem3,c3,32);request->sitem3[31]=0;

 return 0;
}

void * http_handler(void *p) {
//Handle a single http request
 struct timeval tv;
 unsigned char out[4]={0};
 unsigned char buf[TCP_BUF_SIZE]={0};
 unsigned char jsonreply[65535];
 httpreq request;
 int jsonlen;
 int rc,l;
 tv.tv_sec=5;
 tv.tv_usec=0;

 tcpcc *m=(tcpcc*)p;

 if (p==NULL) return NULL;

 pthread_detach(pthread_self());
 l=recv(m->sock, buf, TCP_BUF_SIZE, 0);
 str2httpreq(buf,&request);
 if(strncmp(request.method,"GET",16)==0)
 {
  if (strncmp(request.sitem1,"test",4)==0) {
   strncpy(jsonreply,"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><pre>HTTP test request</pre></body></html>\n",256);
   jsonlen=strnlen(jsonreply,256);
  } else if (strncmp(request.sitem1,"prtg",4)==0) {
   jsonlen=buildprtg(jsonreply,&request); 
  } else {
   jsonlen=buildjson(jsonreply,&request);
  }
  send(m->sock, jsonreply, jsonlen, 0);
 }
 close(m->sock);
 free(m);
 m=NULL;
}

int main(int argc, char ** argv) {
    int rc;
    int n;
    pthread_t *thr;
    pthread_t thr_http;
    tcpd tcp_http;

    FILE * fp;
    unsigned char cfgpath[256]={0};

    unsigned char badsyntax=0;
    unsigned char * argp;
    unsigned char tmp[256];

    unsigned char runmode=0;
    // 0 normal daemon
    // 1 build manifest

    snprintf(basepath,256,"%s/.restit", getpwuid(getuid())->pw_dir);
    mkdir(basepath,S_IRWXU);
    snprintf(cfgpath,256,"%s/restit.cfg",basepath);


    if (fp=fopen(cfgpath,"r")) {
        fclose(fp);
    } else {
        fp=fopen(cfgpath,"w");
        fprintf(fp,"[General]\n");
        fprintf(fp,"RestPort = 40480\n");
        fclose(fp);
    }
    rc=ini_loadcfg(&cfg,cfgpath);

    argc--;argv++;  
    while(argc>0 && badsyntax==0) {
        argp=argv[0];
        if (*argp=='-') {
            switch (argp[1]) {
                case 'b':
                 runmode=1;
                 argc--;
                 argv++;
                 argp=argv[0];
                 if (argc<1) {badsyntax=1;}
                 else {
                    rc=generate_manifesto(argp, basepath);
                    if (rc<0) {
                        fprintf(stderr,"Error generating manifest\n");
                        return -1;
                    }
                    cleanup_manifesto();
                    fprintf(stderr,"Manifest file generated in %s\n",basepath);
                    return 0;
                 }
                 break;
                case 'h':
                 badsyntax=2;
                 break;
            }
        }
        argv++;
    }

    if (badsyntax>0) {
        fprintf(stderr,"restit\n by Olivier Van Rompuy\n\nSyntax :\n");
        fprintf(stderr,"restit [-b csv_file]\n");
        return 1;
    }

    fprintf(stderr,"%s\n",basepath);
    rc=load_manifesto(basepath);
    if (rc<1) {
        fprintf(stderr,"Error loading manifesto\n");
        return -2;
    }

    // Generate a separate scheduling thread for each configured cmdsched
    for(n=0;n<schedc;n++) {
        thr=&(scheds[n]->thread);
        pthread_create(thr,NULL,cmdthread,(void*) scheds[n]);
        pthread_detach(*thr);
    }

    tcp_http.port=cfg.restport;
    tcp_http.data=NULL;
    tcp_http.hand=http_handler;

    // Start the tcp listener as a separate thread    
    pthread_create(&thr_http, NULL, tcpd_daemon, (void*) &tcp_http);
    pthread_detach(thr_http);

    while (!stopsrc) {
        sleep(30);
    }

    pthread_exit(0);
    return 0;
}

