/* encrypt.h
 *
 * Custom encryption 
 * by Olivier Van Rompuy
 *
 */

int init_encrypt(unsigned char * keystr,int nr_rounds);
int encrypt_data(unsigned char * buffer,int len);
int decrypt_data(unsigned char * buffer,int len);

