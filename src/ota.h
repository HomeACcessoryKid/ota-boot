#ifndef __OTA_H__
#define __OTA_H__

#define SECTORSIZE 4096
#define HIGHERCERTSECTOR 0xF6000
#define LOWERCERTSECTOR 0xF5000
#define BOOT0SECTOR 0x80000
#define HOST "github.com"
#define HTTPS_PORT 443
#define LOCAL_PORT_START 49152
#define FAILED "failed\n"
#define OK "OK\n"
#define REQUESTHEAD "GET /"
#define REQUESTTAIL " HTTP/1.1\r\nHost: "
#define CRLFCRLF "\r\n\r\n"
#define RECV_BUF_LEN 1025  // current length of amazon URL 724
#define RANGE "\r\nRange: bytes="
#define MAXVERSIONLEN 16
#define SNTP_SERVERS 	"0.pool.ntp.org", "1.pool.ntp.org", \
						"2.pool.ntp.org", "3.pool.ntp.org"

#define ECDSAKEYLENGTHMAX 128 //to be verified better, example is 120 bytes secP384r1
#define HASHSIZE  48  //SHA-384
#define SIGNSIZE 104  //ECDSA r+s in ASN1 format secP384r1
#define PKEYSIZE 120  //size of a pub key
#define KEYNAME "public-%d.key"
#define KEYNAMELEN 16 //allows for 9999 keys
typedef unsigned char byte;

typedef struct {
    byte hash[HASHSIZE];
    byte sign[SIGNSIZE];
} signature_t;

int active_cert_sector;
int backup_cert_sector;

void  ota_init();

int   ota_get_privkey();

int   ota_get_pubkey(int sector); //get the ecdsa key from the active_cert_sector

int   ota_verify_pubkey(void); //check if public and private key are a pair

void  ota_sign(int start_sector, int num_sectors, signature_t* signature);

int   ota_compare(char* newv, char* oldv);

int   ota_load_main_app(char * url, char * version, char * name);

void  ota_set_validate(int onoff);

char* ota_get_version(char * url);

int   ota_get_file(char * url, char * version, char * name, int sector); //number of bytes 

int   ota_get_newkey(char * url, char * version, char * name, signature_t* signature);

int   ota_get_hash(char * url, char * version, char * name, signature_t* signature);

int   ota_verify_hash(int address, signature_t* signature, int filesize);
    
int   ota_verify_signature(signature_t* signature);

void  ota_swap_cert_sector();

void  ota_write_status0();

void  ota_reboot();

#endif // __OTA_H__
