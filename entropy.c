/* entropy.c
 *
 * by Olivier Van Rompuy
 * 11/03/2023
 * 
 * Entropy Vault command line tool
 * 
 * Entropy vaults are cryptographically obscured files intended to store passwords and
 * other sensitive short strings. Every entry is stored as an encrypted entry that contains payload+hash.
 * To retrieve it the program must decrypt every possible entry in the "entropy vault file" to retrieve it.
 * 
 * The vault files are stored in ${HOME}/.entropy
 * 
 * */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include "sha512.h"
#include "encrypt.h"
#include "entropy.h"

unsigned char rnd_buff[RNDBUFF];

//Initialize the random buffer
void init_random() {
 unsigned char * end=rnd_buff+RNDBUFF;
 unsigned char * p = rnd_buff;
 int * i;
 srand(time(NULL)); 
 for(;p<end;p+=sizeof(int)) {
   i=(int*)p;
   *i=rand();
 }
}

//Print an sha512 hash -> Debug purposes
void print_hash(unsigned char * data) {
 unsigned char * end, *c;
 end=data+64;
 for(c=data;c<end;c++) {
  fprintf(stderr,"%02X",*c);
 }
 fprintf(stderr,"\n");
}

//Wipe a buffer by replacing it's content with random bytes
void wipe_buffer(unsigned char *buff)
{
 unsigned char * end=buff+PAYLOAD_SIZE;
 unsigned char * p = buff;
 int * i;
 srand(time(NULL)); 
 for(;p<end;p+=sizeof(int)) {
   i=(int*)p;
   *i=rand();
 }
}

//Search entry and return offset
long int entropy_search(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char buff2[BUFFER_SIZE];
 unsigned char cmp[64], *obp;
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 unsigned char * digest2 = buff2+PAYLOAD_SIZE;
 int len,rp,rn,n,rr;
 long int offset=0,offok=-1;
 uint16_t *obscure;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Input file not found\n");
  return -3;
 }

 fp=fopen(fname,"r+b");
 if (fp == NULL) {
  return -2;
 }

 rr=fread(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 memcpy(buff2,buff1,BUFFER_SIZE);
 while (rr>0) {
  init_encrypt(keystr,rounds);
  decrypt_data(buff2,BUFFER_SIZE);
  init_encrypt(pwd,rounds);
  decrypt_data(buff2,BUFFER_SIZE);
  SHA512(buff2,PAYLOAD_SIZE,cmp);
  if (memcmp(cmp,digest2,64)==0)
  {
   offok=offset-BUFFER_SIZE;
   obscure=(uint16_t *)buff2;
   obp=buff2+*obscure;
   len=strnlen(obp,MESSAGE_SIZE-*obscure);
   strncpy(buff,obp,len);
   return offok;
  }
  rr=fread(buff2,BUFFER_SIZE,1,fp);
  if (rr>0) offset+=BUFFER_SIZE;
  memcpy(buff1,buff2,BUFFER_SIZE);
 }
 fclose(fp);
 return offok;
}

//Append entry to the end of the file -> Obscure by adding random blocks before and after
long int entropy_append(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE, *obp;
 int rp,rn,n,len;
 uint16_t *obscure;
 long int offset=0;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -3;
 }

 fp=fopen(fname,"a+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for append\n");
  return -2;
 }

 wipe_buffer(buff1);
 len=strnlen(buff,MESSAGE_SIZE);
 obscure=(uint16_t *)buff1;
 *obscure=2+rand()%(MESSAGE_SIZE-1-len);  //Obscuring offset
 obp=buff1+*obscure;
 strncpy(obp,buff,len+1);
 SHA512(buff1,PAYLOAD_SIZE,digest1);
 init_encrypt(pwd,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 init_encrypt(keystr,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;

 fclose(fp); 
 return offset-BUFFER_SIZE;
}

//Replace -> Search entry in file and replace with new data
long int entropy_replace(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64], *obp;
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 uint16_t *obscure;
 int rp,rn,n,len;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -4;
 }

 fp=fopen(fname,"rw+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for write\n");
  return -2;
 }

 if (fseek(fp,offset,SEEK_SET)!=0) {
  fprintf(stderr," Error: Seek failed in file\n");
  return -3;
 }
 wipe_buffer(buff1);
 len=strnlen(buff,MESSAGE_SIZE);
 obscure=(uint16_t *)buff1;
 *obscure=2+rand()%(MESSAGE_SIZE-1-len);  //Obscuring offset
 obp=buff1+*obscure;
 strncpy(obp,buff,len+1);
 SHA512(buff1,PAYLOAD_SIZE,digest1);
 init_encrypt(pwd,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 init_encrypt(keystr,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 
 fclose(fp); 
 return offset-BUFFER_SIZE;
}

//Erase -> search entry and overwrite with random bytes
long int entropy_erase(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 int rp,rn,n;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -4;
 }

 fp=fopen(fname,"rw+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for write\n");
  return -2;
 }

 if (fseek(fp,offset,SEEK_SET)!=0) {
  fprintf(stderr," Error: Seek failed in file\n");
  return -3;
 }
 wipe_buffer(buff1);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 
 fclose(fp); 
 return offset-BUFFER_SIZE;
}

