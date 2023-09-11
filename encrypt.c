/* encrypt.c
 *
 * Custom encryption 
 * by Olivier Van Rompuy
 *
 * Per iteration/round the following is done to the data :
 * - 1st round only : Starting InvertXOR with 8192bit key
 * - Byte substitution (different translation tables per round)
 * - Leftway bitwise rotation *A (per 64bit words)
 * - InvertXOR with 8192bit key
 * - Rightway bitwise rotation *B (per 64bit words)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha512.h"

#define BUFFER_SIZE 65536

unsigned char key[1024]={0};
unsigned char ttable[256][256]={0};
unsigned char dtable[256][256]={0};
int rounds=4;

void sha_key(unsigned char * src,unsigned char * tgt) {
 unsigned char n=0;
 for (;n<16;n++) {
   SHA512(src,64,tgt);
   src+=64;
   tgt+=64;
 }
}

//We explode the keystring into a 1024byte key
//Then we obscure it with sha512
int buildkey(unsigned char * keystring) {
 int se=strnlen(keystring,1024),n=0;
 int sp1=0;
 int cval;
 unsigned char explode[1024];
 unsigned char * kp=explode;
 unsigned char last,cur1;

 if (keystring==NULL) return -1;

 last=keystring[se-1];
 cval=(last-keystring[0])&255;

 for(;n<1024;n++) {
  cur1=keystring[sp1];
  cval=((n>>8)+(n&255)^last^((n&1)?(cval+cur1+1)&255:(cval-cur1-127)))&255;
  *kp=cval;
  last=cur1;
  sp1=(sp1+1)%se;
  kp++;
 }
 sha_key(explode,key);
 return 0;
}

unsigned char tt_findchar(unsigned char input, int *table) {
 unsigned char found=1;
 unsigned char curr;
 int n;
 curr=input;
 while (found) {
  found=0;
  for(n=0;n<256;n++) {
   if (table[n]==curr) found=1;
  }
  if (found) {curr=(curr+1)&255;}
 }
 return curr;
}

//Build the translation tables for byte substitution
void buildtrans() {
 int n,m,kp=0;
 int ctable[256];
 unsigned char cval,curr,fval;
 cval=(key[1023]+key[0]-127);
 for(n=0;n<256;n++) {
  for(m=0;m<256;m++) {ctable[m]=-1;}
  for(m=0;m<256;m++) {
   curr=key[kp];
   cval=((n>>8)+(n&255)^((n&1)?(cval+curr+1)&255:(cval-curr-127)))&255;
   fval=tt_findchar(cval,ctable);
   ttable[n][m]=fval;
   dtable[n][fval]=m;
   ctable[m]=ttable[n][m];
   kp=(kp+1)&1023;
  }
 }
}

//Inverted XOR
int invertxor(unsigned char * string, int se) {
 int sp=0,kp=0;
 unsigned char * spp=string;
 uint64_t * sp64=(uint64_t *)spp;

 for(;sp<se-8;sp+=8) {
  *sp64=*sp64^*(uint64_t *)(key+kp)^0xffffffffffffffff;
  sp64++;
  kp=(kp+8)&1023;
 }
 spp=(unsigned char *)sp64;

 for(;sp<se;sp++) {
  *spp=*spp^*(key+kp)^0xff;
  kp=(kp+1)&1023;
  spp++;
 }

 return 0;
}

//Byte substitution forward
void translate_fw(unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * tt=ttable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=tt[*sp];
  sp++;
 }
}

//Byte substitution backward
void translate_bw(unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * dt=dtable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=dt[*sp];
  sp++;
 }
}

//Bit rotation forward
void obscure_fw(unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<8) return;
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)<<(tt[sc>>4]&63))|((*bp)>>(64-(tt[sc>>4]&63)));
 }
 bp=(uint64_t *)(str);
 *bp=((*bp)<<(tt[0]&63))|((*bp)>>(64-(tt[0]&63)));
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)<<(tt[1]&63))|((*bp)>>(64-(tt[1]&63)));
}

//Bit rotation backward
void obscure_bw(unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<8) return;
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)>>(tt[1]&63))|((*bp)<<(64-(tt[1]&63)));
 bp=(uint64_t *)(str);
 *bp=((*bp)>>(tt[0]&63))|((*bp)<<(64-(tt[0]&63)));
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)>>(tt[sc>>4]&63))|((*bp)<<(64-(tt[sc>>4]&63)));
 }
}

//Set up encryption
int init_encrypt(unsigned char * keystr,int nr_rounds) {
 rounds=nr_rounds;
 buildkey(keystr);
 buildtrans();
}

//Encrypt a buffer of n bytes
int encrypt_data(unsigned char * buffer,int len) {
 int n=0;
 invertxor(buffer,len);
 for(;n<rounds;n++) {
  translate_fw(buffer,len,key[n]);
  obscure_fw(buffer,len,key[n]);
  invertxor(buffer,len);
  obscure_bw(buffer,len,key[(n+512)&1023]);
 }
}

//Decrypt a buffer of n bytes
int decrypt_data(unsigned char * buffer,int len) {
 int n=rounds-1;
 for(;n>=0;n--) {
  obscure_fw(buffer,len,key[(n+512)&1023]);
  invertxor(buffer,len);
  obscure_bw(buffer,len,key[n]);
  translate_bw(buffer,len,key[n]);
 }
 invertxor(buffer,len);
}
