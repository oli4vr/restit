/* main.c
by Olivier Van Rompuy

restit application main c file

*/

#include "main.h"
#include "entropy.h"
#include "inifind.h"
#include "tcpd.h"
#include <signal.h>

#define TCP_BUF_SIZE 65536

unsigned char basepath[256]={0};
unsigned char localpath[256]={0};

unsigned char restit_cmd[256]={0};


cmdsched *scheds[MAX_SCHEDS]={NULL};
int schedc=0;

cfgmain cfg;

unsigned char stopsrc=0;

//manifest_nextsched
//Process 1 line in the manifest csv
//Mode 0 = Get script from file
//Mode 1 = Get script from manifest vault
//Returns NULL pointer if csv formatting is incorrect
//Returns pointer to cmdsched
cmdsched * manifest_nextsched(unsigned char ** inbuff, unsigned char * tpath, unsigned char mode) {
    unsigned char tmp[256]={0};
    unsigned char vault[256]={0};
    unsigned char vaultfile[256]={0};
    unsigned char keystring[256]={0};
    unsigned char commands[8127]={0};
    uint32_t seconds;
    unsigned char * buffer=*inbuff;
    unsigned char * c=buffer, * p=buffer;
    unsigned char sfname[256]={0};
    unsigned char shell[128]={0};
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
    strncpy(sfname,p,256);
    sfname[255]=0;
    c++;p=c; while (*c!=';') {if (*c==0) return NULL;c++;} ; *c=0;
    strncpy(shell,p,128);
    shell[127]=0;
    if (mode==0) {
        //strncpy(tmp,p,256);
        //tmp[255]=0;
        fp=fopen(sfname,"r+b");
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
    memcpy(rcsched->shell,shell,128);
    memcpy(rcsched->scriptname,sfname,64);
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

//Generate the manifesto vault files
int generate_manifesto(unsigned char * fname, unsigned char * tpath) {
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
        if (cp!=NULL)
            rc=entropy_append(cp->commands,cp->keystring,securestr,cp->vaultfile,2); 
    }
    return schedc;
}

//Load the manifesto
int load_manifesto(unsigned char * spath) {
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
    //unsigned char buffer[MESSAGE_SIZE+1]={0};
    unsigned char buffer[65535]={0};
    unsigned char cmdstr[256]={0};
    unsigned char *sp=buffer;
    unsigned char neof=1,nomsg=1;
    unsigned char *rcstr, *outstr, *outmsg;

    FILE * pipe;

    rc=sprintf(cmdstr,"%s run %s </dev/null\n",restit_cmd,c->scriptname);

//    pipe=popen(c->commands,"r");
    pipe=popen(cmdstr,"r");
    if (pipe==NULL) return -1;
    rc=fread(buffer,1,MESSAGE_SIZE,pipe);
    pclose(pipe);
    c->resultsnum=0;
    while (neof && c->resultsnum<MAX_RESULTS) {
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
        nomsg=1;
    }
    return (rc);
}

int exec_script(cmdsched * c) {
    int rc;
    unsigned char neof=1,nomsg=1;
    unsigned char *rcstr, *outstr, *outmsg;

    FILE * pipe;

    pipe=popen(c->shell,"w");
    if (pipe==NULL) return -1;
    rc=fwrite(c->commands,1,strnlen(c->commands,MESSAGE_SIZE),pipe);
    pclose(pipe);

    return (rc);
}

// Find specific cmdsched entry based on script name
// return NULL if not found
cmdsched * find_sched(unsigned char * sname) {
 int n=0;
 for(;n<schedc;n++) {
   if (scheds[n]!=NULL) {
    if (strncmp(scheds[n]->scriptname,sname,64)==0) {
        return scheds[n];
    }
   }
 }
 return NULL;
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
     for(m=0;m<(c->resultsnum);m++) {
     if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
         if (comma) {
            *jsonpnt=',';
            jsonpnt++;
            jsonpos++;
         }
         comma=1;
         sprintf(jsonpnt,"{\"%s\":{\"%s\":{\"%s\":\"%s\",\"Message\":\"%s\"}}}",c->vault,c->keystring,c->results[m].result_string,c->results[m].result_value,c->results[m].result_message);
         len=strnlen(jsonpnt,65000);
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

int buildprtg(unsigned char * jsonout,httpreq *request) {
    int n,m,max,jsonpos=0,len;
    size_t msglen=0;
    unsigned valtype;
    unsigned char * jsonpnt=jsonout,comma=0;
    unsigned char resmsg_combi[2000]={0};
    unsigned char *rmcp=resmsg_combi;
    unsigned char *crmp=resmsg_combi;
    cmdsched * c;
    // HTTP Header :
    strncpy(jsonpnt,"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"prtg\":{\"result\":[",256);
    jsonpos+=strnlen(jsonpnt,256);
    jsonpnt+=jsonpos;
    comma=0;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     for(m=0;m<(c->resultsnum);m++) {
      if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
       //Message combining
       crmp=c->results[m].result_message;
       if (*crmp!=0) {
        if (rmcp>resmsg_combi) {
          *rmcp=' '; rmcp++; *rmcp='|'; rmcp++; *rmcp=' '; rmcp++;
        }
        msglen=strnlen(crmp,256);
        strncpy(rmcp,crmp,msglen);
        rmcp+=msglen;
        *rmcp=0;
       }
       // ****
       if (comma) {
            *jsonpnt=',';
            jsonpnt++;
            jsonpos++;
       }
 	   comma=1;
 	   valtype=valuetypecheck(c->results[m].result_value);
 	   if (valtype==2) {
            sprintf(jsonpnt,"{\"channel\":\"%s\",\"value\":\"%0.02f\",\"text\":\"%s\"",c->results[m].result_string,atof(c->results[m].result_value),crmp);
 	   } else {
            sprintf(jsonpnt,"{\"channel\":\"%s\",\"value\":\"%s\",\"text\":\"%s\"",c->results[m].result_string,c->results[m].result_value,crmp);
 	   }
        len=strnlen(jsonpnt,65000);
        jsonpos+=len;
        jsonpnt+=len;
        if (request->limitmode) {
 	    if (valtype==2) {
           sprintf(jsonpnt,",\"float\":\"1\"");
           len=strnlen(jsonpnt,65000);
           jsonpos+=len;
           jsonpnt+=len;
 	    }
         sprintf(jsonpnt,",\"limitmode\":\"1\"");
         len=strnlen(jsonpnt,65000);
         jsonpos+=len;
         jsonpnt+=len;
 	    if (request->warnhigh<9999999999999) {
 	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMaxWarning\":\"%0.02f\"",request->warnhigh); }
 	     else {sprintf(jsonpnt,",\"LimitMaxWarning\":\"%0.00f\"",request->warnhigh);}
            len=strnlen(jsonpnt,65000);
            jsonpos+=len;
            jsonpnt+=len;
 	    }
 	    if (request->crithigh<9999999999999) {
 	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMaxError\":\"%0.02f\"",request->crithigh); }
 	     else {sprintf(jsonpnt,",\"LimitMaxError\":\"%0.00f\"",request->crithigh);}
             len=strnlen(jsonpnt,65000);
             jsonpos+=len;
             jsonpnt+=len;
 	    }
 	    if (request->warnlow>-9999999999999) {
 	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMinWarning\":\"%0.02f\"",request->warnlow); }
 	     else {sprintf(jsonpnt,",\"LimitMinWarning\":\"%0.00f\"",request->warnlow);}
             len=strnlen(jsonpnt,65000);
             jsonpos+=len;
             jsonpnt+=len;
 	    }
 	    if (request->critlow>-9999999999999) {
 	     if (valtype==2) {sprintf(jsonpnt,",\"LimitMinError\":\"%0.02f\"",request->critlow); }
 	     else {sprintf(jsonpnt,",\"LimitMinError\":\"%0.00f\"",request->critlow);}
             len=strnlen(jsonpnt,65000);
             jsonpos+=len;
             jsonpnt+=len;
 	    }
 	   }

 	   *jsonpnt='}';
 	   jsonpnt++;
 	   jsonpos++;
       } //query end
      } //result loop end
     } //cmdsched loop end
    jsonpnt--;
    if (*jsonpnt!=',') {jsonpnt++;}
    resmsg_combi[1999]=0;
    if (m>0) {sprintf(jsonpnt,"],\"Text\":\"%s\"}}",resmsg_combi);}
    else {sprintf(jsonpnt,"]}}");}
    jsonpos+=strnlen(jsonpnt,65000);
    jsonpnt+=strnlen(jsonpnt,65000);
    *jsonpnt=0;
    return jsonpos;
}

int buildtext(unsigned char * textout,httpreq *request) {
    int n,m,max,pos=0,len;
    unsigned char * txtpnt=textout;
    cmdsched * c;
    int maxwidth_cat=8,maxwidth_type=8,maxwidth_name=16,maxwidth_val=8,maxwidth_msg=32;
    unsigned char linebuf[65535];
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     for(m=0;m<(c->resultsnum);m++) {
      if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
       if (strlen(c->vault)>maxwidth_cat) maxwidth_cat=strlen(c->vault);
       if (strlen(c->keystring)>maxwidth_type) maxwidth_type=strlen(c->keystring);
       if (strlen(c->results[m].result_string)>maxwidth_name) maxwidth_name=strlen(c->results[m].result_string);
       if (strlen(c->results[m].result_value)>maxwidth_val) maxwidth_val=strlen(c->results[m].result_value);
       if (strlen(c->results[m].result_message)>maxwidth_msg) maxwidth_msg=strlen(c->results[m].result_message);
      }
     }
    }
    if (maxwidth_msg<7) maxwidth_msg=7;
    len=sprintf(txtpnt,"HTTP/1.1 200 OK\nContent-Type: text/plain\n\n%-*s  %-*s  %-*s  %-*s  %s\n",maxwidth_cat,"CATEGORY",maxwidth_type,"TYPE",maxwidth_name,"NAME",maxwidth_val,"VALUE","MESSAGE");
    pos+=len;
    txtpnt+=len;
//    len=sprintf(txtpnt,"%s  %s  %s  %s  %s\n",strncpy((char*)linebuf,"================",maxwidth_cat),strncpy((char*)linebuf,"================",maxwidth_type),strncpy((char*)linebuf,"================",maxwidth_name),strncpy((char*)linebuf,"================",maxwidth_val),"================");
//    pos+=len;
//    txtpnt+=len;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     for(m=0;m<(c->resultsnum);m++) {
      if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
       len=sprintf(txtpnt,"%-*s  %-*s  %-*s  %-*s  %s\n",maxwidth_cat,c->vault,maxwidth_type,c->keystring,maxwidth_name,c->results[m].result_string,maxwidth_val,c->results[m].result_value,c->results[m].result_message);
       pos+=len;
       txtpnt+=len;
      }
     }
    }
    return pos;
}

int buildhtml(unsigned char * htmlout,httpreq *request) {
    int n,m,max,pos=0,len;
    unsigned char * htmlpnt=htmlout;
    cmdsched * c;
    unsigned char trclass[16];
    int maxwidth_cat=8,maxwidth_type=8,maxwidth_name=16,maxwidth_val=8,maxwidth_msg=32;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     for(m=0;m<(c->resultsnum);m++) {
      if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
       if (strlen(c->vault)>maxwidth_cat) maxwidth_cat=strlen(c->vault);
       if (strlen(c->keystring)>maxwidth_type) maxwidth_type=strlen(c->keystring);
       if (strlen(c->results[m].result_string)>maxwidth_name) maxwidth_name=strlen(c->results[m].result_string);
       if (strlen(c->results[m].result_value)>maxwidth_val) maxwidth_val=strlen(c->results[m].result_value);
       if (strlen(c->results[m].result_message)>maxwidth_msg) maxwidth_msg=strlen(c->results[m].result_message);
      }
     }
    }
    if (maxwidth_msg<7) maxwidth_msg=7;
     unsigned char searchval[64];
      unsigned char searchform[512];
      unsigned char actionurl[256];
      if (request->sitem2[0]==0) {
       snprintf(actionurl,256,"/html/");
      } else {
       snprintf(actionurl,256,"/html/%s/",request->sitem2);
      }
      strncpy(searchval,request->search,64);
      searchval[63]=0;
      snprintf(searchform,512,"<form method='get' action='%s' style='margin:0;display:inline-block;'><input type='text' class='search-input' placeholder='Search...' value='%s' onkeypress='if(event.key===\"Enter\"){document.getElementById(\"searchHidden\").value=this.value;this.form.submit();}'><input type='hidden' name='search' id='searchHidden' value='%s'></form>",actionurl,searchval,request->search);
     len=sprintf(htmlpnt,"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>restit - Sensor Data</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto, Oxygen,Ubuntu,Cantarell,sans-serif;margin:0;padding:20px;background:#f5f7fa;color:#333;}h1{margin-bottom:20px;font-size:24px;text-align:center;}table{border-collapse:collapse;width:100%%;max-width:1600px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.08);}th,td{padding:12px 8px;text-align:left;border-bottom:1px solid #eee;}th{background:#6366f1;color:#fff;font-weight:600;position:sticky;top:0;}tr:hover{background:#f8fafc;}tr:nth-child(even){background:#fafafa;}td{font-size:13px;}tr:hover td{background:#f0f2ff;}@media(max-width:768px){table{display:block;overflow-x:auto;}}.empty{padding:60px 20px;text-align:center;color:#64748b;font-size:16px;}.search-container{float:right;}.search-input{padding:8px 12px;font-size:13px;border:1px solid #ddd;border-radius:6px;width:180px;max-width:200px;outline:none;transition:border-color 0.2s;}.search-input:focus{border-color:#6366f1;}.th-message{display:flex;justify-content:space-between;align-items:center;border-style:none;}</style></head><body><h1>📊 restit Sensor Data</h1><table><thead><tr><th width='12%%'>Category</th><th width='12%%'>Type</th><th width='22%%'>Name</th><th width='12%%'>Value</th><th width='*' class='th-message'><div>Message</div><div>%s</div></th></tr></thead><tbody>",searchform);
    pos+=len;
    htmlpnt+=len;
    for(n=0;n<schedc;n++) {
     c=scheds[n];
     max=(c->resultsnum)-1;
     for(m=0;m<(c->resultsnum);m++) {
      if ((*(request->sitem2)==0 || strncmp(request->sitem2,c->results[m].result_string,64) == 0 || strncmp(request->sitem2,c->vault,64)==0 || strncmp(request->sitem2,c->keystring,64)==0) && (strstr(c->results[m].result_string,request->search)!=NULL || request->search[0]==0)) {
       if ((n+m)%2==0) strncpy(trclass,"odd",16);
       else strncpy(trclass,"even",16);
       len=sprintf(htmlpnt,"<tr class='%s'><td>%s</td><td><span style='color:#64748b'>%s</span></td><td><strong>%s</strong></td><td><code>%s</code></td><td>%s</td></tr>",trclass,c->vault,c->keystring,c->results[m].result_string,c->results[m].result_value,c->results[m].result_message);
       pos+=len;
       htmlpnt+=len;
      }
     }
    }
    len=sprintf(htmlpnt,"</tbody></table>");
    pos+=len;
    htmlpnt+=len;
    if (schedc==0) {
     len=sprintf(htmlpnt,"<p class='empty'>No sensor data available</p>");
     pos+=len;
     htmlpnt+=len;
    }
    len=sprintf(htmlpnt,"</body></html>");
    pos+=len;
    return pos;
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
 request->maxval=100;
 request->minval=0;
 request->warnon[0]=0;
 request->criton[0]=0;
 request->search[0]=0;
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
   } else if (strncmp(c1,"maxval",16)==0) {
     request->maxval=atof(c2);
   } else if (strncmp(c1,"minval",16)==0) {
     request->minval=atof(c2);
   } else if (strncmp(c1,"warnon",16)==0) {
     strncpy(request->warnon,c2,64);
     request->warnon[63]=0;
   } else if (strncmp(c1,"criton",16)==0) {
 strncpy(request->criton,c2,64);
      request->warnon[63]=0;
    } else if (strncmp(c1,"search",16)==0) {
      unsigned char *src=c2,*dst=request->search;
      int i=0;
      while (*src && i<63) {
       if (*src=='%') {
        src++;
        if (*src>='0' && *src<='9') *dst=(*src-'0')<<4;
        else if (*src>='a' && *src<='f') *dst=(*src-'a'+10)<<4;
        else if (*src>='A' && *src<='F') *dst=(*src-'A'+10)<<4;
        src++;
        if (*src>='0' && *src<='9') *dst|=(*src-'0');
        else if (*src>='a' && *src<='f') *dst|=(*src-'a'+10);
        else if (*src>='A' && *src<='F') *dst|=(*src-'A'+10);
        src++;
       } else if (*src=='+') {
        *dst=' ';
        src++;
       } else {
        *dst=*src;
        src++;
       }
       dst++; i++;
      }
      *dst=0;
   }
  }
  if (request->warnhigh>999999999999) {request->warnhigh=request->crithigh;}
  if (request->warnlow<-999999999999) {request->warnlow=request->critlow;}
 }

 // Process the path and get subitem 1/2/3
 request->sitem1[0]=0;
 request->sitem2[0]=0;
 request->sitem3[0]=0;

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
 unsigned char jsonreply[65536];
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
    } else if (strncmp(request.sitem1,"json",4)==0) {
     jsonlen=buildprtg(jsonreply,&request); 
    } else if (strncmp(request.sitem1,"prtg",4)==0) {
     jsonlen=buildprtg(jsonreply,&request); 
    } else if (strncmp(request.sitem1,"text",4)==0) {
     jsonlen=buildtext(jsonreply,&request); 
    } else if (strncmp(request.sitem1,"html",4)==0) {
     jsonlen=buildhtml(jsonreply,&request); 
    } else if (*request.sitem1==0) {
     strncpy(jsonreply,"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<!DOCTYPE html><html><head><meta charset='UTF-8'><script>location.href='/html';</script></head><body></body></html>\n",256);
     jsonlen=strnlen(jsonreply,256);
    } else {
     jsonlen=buildhtml(jsonreply,&request);
    }
    send(m->sock, jsonreply, jsonlen, 0);
   }
 close(m->sock);
 free(m);
 m=NULL;
}

void sighandler(int sig) {
    (void)sig;
    stopsrc=1;
}

int main(int argc, char ** argv) {
    int rc;
    int n;
    pthread_t *thr;
    pthread_t thr_http;
    tcpd tcp_http;

    FILE * fp;
    unsigned char cfgpath[267]={0};

    unsigned char badsyntax=0;
    unsigned char * argp;
    unsigned char tmp[256];

    unsigned char runmode=0;
    // 0 normal daemon
    // 1 build manifest

    unsigned char exemode=0;

    const char *envpath = getenv("RESTIT_SVCNAME");

     signal(SIGINT,sighandler);
     signal(SIGTERM,sighandler);
     signal(SIGPIPE,SIG_IGN);

     strncpy(restit_cmd,argv[0],256);

    if (envpath==NULL) {
     snprintf(basepath,256,"%s/.restit", getpwuid(getuid())->pw_dir);
     snprintf(localpath,256,"./.restit");
    } else {
     snprintf(basepath,256,"%s/.%s", getpwuid(getuid())->pw_dir, envpath);
     snprintf(localpath,256,"./.%s",envpath);
    }
//    fprintf(stderr,"basepath = %s\n",basepath);
//    fprintf(stderr,"localpath = %s\n",localpath);
    mkdir(basepath,S_IRWXU);
    mkdir(localpath,S_IRWXU);
    snprintf(cfgpath,267,"%s/restit.cfg",basepath);

    if (fp=fopen(cfgpath,"r")) {
        fclose(fp);
    } else {
        fp=fopen(cfgpath,"w");
        fprintf(fp,"[General]\n");
        fprintf(fp,"RestPort = 40480\n");
        fclose(fp);
    }
    rc=ini_loadcfg(&cfg,cfgpath);

    if (argc==3) {
        if (strncmp(argv[1],"run",4)==0) {
            exemode=1;
        }
    }

    if (exemode==0) {
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
                     rc=generate_manifesto(argp, localpath);
                     if (rc<0) {
                         fprintf(stderr,"Error generating manifest\n");
                         return -1;
                     }
                     cleanup_manifesto();
                     fprintf(stderr,"Manifest file generated in %s\n",localpath);
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
    }

    if (badsyntax>0) {
        fprintf(stderr,"restit\n by Olivier Van Rompuy\n\nSyntax :\n");
        fprintf(stderr,"restit [-b csv_file]\n");
        return 1;
    }

    //fprintf(stderr,"%s\n",basepath);
    rc=load_manifesto(basepath);
    if (rc<1) {
        fprintf(stderr,"Error loading manifesto\n");
        return -2;
    }

    // run script with name
    if (exemode==1) {
        cmdsched * runcmd=find_sched(argv[2]);
        if (runcmd==NULL) {
            fprintf(stderr,"Error: Script not found in manifest\n");
            return -5;
        }
        return exec_script(runcmd);
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
        sleep(1);
    }

    pthread_cancel(thr_http);
    pthread_join(thr_http,NULL);
    
    for(n=0;n<schedc;n++) {
        pthread_cancel(scheds[n]->thread);
        pthread_join(scheds[n]->thread,NULL);
    }

    pthread_exit(0);
    return 0;
}

