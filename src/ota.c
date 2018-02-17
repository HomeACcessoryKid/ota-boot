#include <stdlib.h>  //for printf
#include <stdio.h>
#include <string.h>

#include <lwip/sockets.h>
#include <lwip/api.h>
#include <esp8266.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>	    // needed by wolfSSL_check_domain_name()
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <ota.h>

#include <sntp.h>
//#include <time.h> //included in sntp.h
#include <spiflash.h>

static int validate;

DsaKey prvkey;
DsaKey pubkey;

WOLFSSL_CTX* ctx;

void MyLoggingCallback(const int logLevel, const char* const logMessage) {
/*custom logging function*/
    printf("loglevel: %d - %s\n",logLevel, logMessage);
}


void  ota_init() {
    printf("ota_init\n");
    //time support
    time_t ts;
    char *servers[] = {SNTP_SERVERS};
	sntp_set_update_delay(5*60000); //SNTP will request an update each 5 minutes
	const struct timezone tz = {1*60, 0}; //Set GMT+1 zone, daylight savings off
	sntp_initialize(&tz);
	sntp_set_servers(servers, sizeof(servers) / sizeof(char*)); //Servers must be configured right after initialization
    do {
        ts = time(NULL);
    } while (ts<1000000000);
    printf("TIME: %s", ctime(&ts));

    wolfSSL_Init();
    
    int ret;
    ret = wolfSSL_SetLoggingCb(MyLoggingCallback);
    if (ret != 0) {
        /*failed to set logging callback*/
        printf("error setting debug callback\n");
    }

    
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        //error
    }
    extern int active_cert_sector;
    extern int backup_cert_sector;
    //set active_cert_sector
    active_cert_sector=0xF6000; //tmp code
    backup_cert_sector=0xF5000; //tmp code
    ret=0;
    byte abyte[1];
    do {
        if (!spiflash_read(active_cert_sector+(ret++), (byte *)abyte, sizeof(abyte))) {
            printf("error reading flash\n");
            break;
        }
    } while (abyte[0]!=0xff); ret--;
    printf("certs size: %d\n",ret);
    byte *certs=malloc(ret);
    spiflash_read(active_cert_sector, (byte *)certs, ret);

    ret=wolfSSL_CTX_load_verify_buffer(ctx, certs, ret, SSL_FILETYPE_PEM);
    if ( ret != SSL_SUCCESS) {
        printf("failed, return %d\n", ret);
    }
    free(certs);
    ota_set_validate(1); //by default validate (although the first thing we do is switch it off...)
}

int ota_get_privkey() {
    printf("ota_get_privkey\n");
    
    byte buffer[DSAKEYLENGTHMAX];
    int ret;
    unsigned int idx;
    int i,j;
    
    if (!spiflash_read(0xF5000, (byte *)buffer, 4)) {
        printf("error reading flash\n");    return -1;
    }
    if (buffer[0]!=0x30 || buffer[1]!=0x82) return -2; //not a valid keyformat
    int length=256*buffer[2]+buffer[3]+4; //includes this header
    if (length>DSAKEYLENGTHMAX)             return -3; // too long to be valid 3072bit key
    
    if (!spiflash_read(0xF5000, (byte *)buffer, length)) {
        printf("error reading flash\n");    return -1;
    }
    wc_InitDsaKey(&prvkey); idx=0;
    ret=DsaPrivateKeyDecode(buffer,&idx,&prvkey,length);
    printf("ret: %d\n",ret);
    
    
    //some basic testing with DSA
    memset(buffer+length-31,0xff,31); //wipe out priv key
    if (buffer[length-33]==0x00) buffer[length-32]=0xff;
    if (buffer[length-33]==0x20) buffer[length-32]=0x7f;
    printf("tail:"); for (j=length-35;j<length;j++) printf(" %02x",buffer[j]); printf("\n");
    
    wc_InitDsaKey(&pubkey); idx=0;
    ret=DsaPrivateKeyDecode(buffer,&idx,&pubkey,length);
    printf("ret: %d\n",ret);
    pubkey.type=DSA_PUBLIC;
    
    WC_RNG rng;
    /*byte hash[SHA_DIGEST_SIZE];
    printf("DIGSIZE: %d",SHA_DIGEST_SIZE);

    for (j=0;j<20;j++){
        wc_RNG_GenerateBlock(&rng, hash, SHA_DIGEST_SIZE);
        printf("\nhash: ");
        for (i=0;i<20;i++) printf("%02x ",hash[i]);
    }*/
    byte hash[]=    {32,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    byte hashcopy[]={32,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    int answer;
    byte signature[64];

    printf("copy: ");
    for (i=0;i<32;i++) printf("%02x ",hashcopy[i]); printf("\n");

    
    wc_DsaSign(hashcopy, signature, &prvkey, &rng);
    
    printf("copy: "); for (i=0;i<32;i++) printf("%02x ",hashcopy[i]); printf("\n");
    printf("hash: "); for (i=0;i<32;i++) printf("%02x ",hash[i]); printf("\n");
    
    wc_DsaVerify(hash, signature, &pubkey, &answer);
    
    printf("answer: %d\nhash: ",answer); for (i=0;i<32;i++) printf("%02x ",hash[i]); printf("\n");
    printf("sign: "); for (i=0;i<64;i++) printf("%02x ",signature[i]); printf("\n");
    hash[1]=20;
    
    wc_DsaVerify(hash, signature, &pubkey, &answer);
    
    printf("answer: %d\nhash: ",answer); for (i=0;i<32;i++) printf("%02x ",hash[i]); printf("\n");
    printf("sign: "); for (i=0;i<64;i++) printf("%02x ",signature[i]); printf("\n");
    
    return ret;
}

int ota_get_pubkey(char * pubkey) { //get the dsa key from the active_cert_sector
    printf("ota_get_pubkey\n");
    return 0;
}

int ota_verify_pubkey(char* pubkey) { //check if public and private key are a pair
    printf("ota_verify_pubkey\n");
    return 0;
}

void ota_sign(int start_sector, int num_sectors) {
    printf("ota_sign\n");
}

int ota_compare(char* newv, char* oldv) { //(if equal,0) (if newer,1) (if pre-release or older,-1)
    printf("ota_compare\n");
    char* dot;
    int valuen=0,valueo=0;
    char news[MAXVERSIONLEN],olds[MAXVERSIONLEN];
    char * new=news;
    char * old=olds;
    
    if (strcmp(newv,oldv)) { //https://semver.org/#spec-item-11
        if (strchr(newv,'-')) return -1; //we cannot handle pre-releases in the 'latest version' concept
        //they should not occur since they will block finding a valid production version.
        //mark them properly as pre-release in github so they do now show up in releases/latest
        strncpy(new,newv,MAXVERSIONLEN-1);
        strncpy(old,oldv,MAXVERSIONLEN-1);
        if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
        if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
        printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
        if (valuen>valueo) return 1;
        if (valuen<valueo) return -1;
        valuen=valueo=0;
        if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
        if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
        printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
        if (valuen>valueo) return 1;
        if (valuen<valueo) return -1;
        valuen=atoi(new);
        valueo=atoi(old);
        printf("%d-%d\n",valuen,valueo);
        if (valuen>valueo) return 1;
        if (valuen<valueo) return -1;        
    } //they are equal
    return 0; //equal strings
}

static int ota_connect(char* host, int port, int *socket, WOLFSSL** ssl) {
    int ret;
    ip_addr_t target_ip;
    struct sockaddr_in sock_addr;
    static int local_port=LOCAL_PORT_START;

    do {
        ret = netconn_gethostbyname(host, &target_ip);
    } while(ret);
    printf("target IP is %d.%d.%d.%d\n", (unsigned char)((target_ip.addr & 0x000000ff) >> 0),
                                                (unsigned char)((target_ip.addr & 0x0000ff00) >> 8),
                                                (unsigned char)((target_ip.addr & 0x00ff0000) >> 16),
                                                (unsigned char)((target_ip.addr & 0xff000000) >> 24));
    //printf("create socket ......");
    *socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket < 0) {
        printf(FAILED);
        return -3;
    }
    //printf(OK);

    printf("bind socket %d......",local_port);
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(local_port++);
    if (local_port==65536) local_port=LOCAL_PORT_START;
    ret = bind(*socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        printf(FAILED);
        return -2;
    }
    printf(OK);

    printf("socket connect to remote ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = target_ip.addr;
    sock_addr.sin_port = htons(port);
    ret = connect(*socket, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        printf(FAILED);
        return -2;
    }
    printf(OK);
//wolfSSL_Debugging_ON();

    //printf("create SSL ......");
    *ssl = wolfSSL_new(ctx);
    if (!*ssl) {
        printf(FAILED);
        return -2;
    }
    //printf(OK);

    wolfSSL_set_fd(*ssl, *socket);

    if (validate) ret=wolfSSL_check_domain_name(*ssl, host);

    printf("SSL to %s port %d ......", host, port);
    ret = wolfSSL_connect(*ssl);
//wolfSSL_Debugging_OFF();
    if (ret != SSL_SUCCESS) {
        printf("failed, return [-0x%x]\n", -ret);
        ret=wolfSSL_get_error(*ssl,ret);
        printf("wolfSSL_send error = %d\n", ret);
        return -1;
    }
    printf(OK);
    return 0;

}

int   ota_load_main_app(char * url, char * version, char * name) {
    printf("ota_load_main_app\n");
    return 0;
}

void  ota_set_validate(int onoff) {
    printf("ota_set_validate...");
    if (onoff) {
        printf("ON\n");
        validate=1;
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        printf("OFF\n");
        validate=0;
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
}

char* ota_get_version(char * url) {
    printf("ota_get_version\n");
    
    char* version=NULL;
    int retc, ret=0;
    WOLFSSL*     ssl;
    int socket;
    //host=begin(url);
    //mid =end(url)+blabla+version
    char* location;
    char recv_buf[RECV_BUF_LEN];
    int  send_bytes; //= sizeof(send_data);
    
    strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),url),"/releases/latest"),REQUESTTAIL),HOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    //printf("%s\n",recv_buf);

    retc = ota_connect(HOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        printf("send request......");
        ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        if (ret > 0) {
            printf("OK\n\n");

            wolfSSL_shutdown(ssl); //by shutting down the connection before even reading, we reduce the payload to the minimum
            ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //error checking
                //printf("%s\n",recv_buf);

                location=strstr(recv_buf,"Location: ");
                strchr(location,'\r')[0]=0;
                //printf("%s\n",location);
                location=strstr(location,"tag/");
                version=malloc(strlen(location+4));
                strcpy(version,location+4);
                printf("%s@version:\"%s\"\n",url,version);
            } else {
                printf("failed, return [-0x%x]\n", -ret);
                ret=wolfSSL_get_error(ssl,ret);
                printf("wolfSSL_send error = %d\n", ret);
            }
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            ret=wolfSSL_get_error(ssl,ret);
            printf("wolfSSL_send error = %d\n", ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        wolfSSL_free(ssl);
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }

//     if (retc) return retc;
//     if (ret <= 0) return ret;

    return version;
}

int   ota_get_file(char * url, char * version, char * name, int sector) { //number of bytes
    printf("ota_get_file\n");
    
    int retc, ret=0, slash;
    WOLFSSL*     ssl;
    int socket;
    //host=begin(url);
    //mid =end(url)+blabla+version
    char* location;
    char recv_buf[RECV_BUF_LEN];
    int  recv_bytes = 0;
    int  send_bytes; //= sizeof(send_data);
    int  length=1;
    int  clength;
    int  collected=0;
    int  header;
    
    strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),url),"/releases/download/"),version),"/"),name),REQUESTTAIL),HOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    printf("%s\n",recv_buf);

    retc = ota_connect(HOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        printf("send request......");
        ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        if (ret > 0) {
            printf("OK\n\n");

            wolfSSL_shutdown(ssl); //by shutting down the connection before even reading, we reduce the payload to the minimum
            ret = wolfSSL_peek(ssl, recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //error checking, e.g. not result=206
                printf("%s\n",recv_buf);
                location=strstr(recv_buf,"HTTP/1.1 ");
                strchr(location,' ')[0]=0;
                location+=9; //flush "HTTP/1.1 "
                slash=atoi(location);
                printf("HTTP returns %d\n",slash);
                if (slash!=206) return -1;

                location[strlen(location)]=' '; //for further headers
                location=strstr(recv_buf,"Location: ");
                strchr(location,'\r')[0]=0;
                location+=18; //flush Location: https://
                //printf("%s\n",location);
            } else {
                printf("failed, return [-0x%x]\n", -ret);
                ret=wolfSSL_get_error(ssl,ret);
                printf("wolfSSL_send error = %d\n", ret);
            }
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            ret=wolfSSL_get_error(ssl,ret);
            printf("wolfSSL_send error = %d\n", ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        wolfSSL_free(ssl);
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }

    if (retc) return retc;
    if (ret <= 0) return ret;
    
    //process the Location
    strcat(location, REQUESTTAIL);
    slash=strchr(location,'/')-location;
    location[slash]=0; //cut behind the hostname
    char * host2=malloc(strlen(location));
    strcpy(host2,location);
    //printf("next host: %s\n",host2);

    retc = ota_connect(host2, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready

    strcat(strcat(location+slash+1,host2),RANGE); //append hostname and range to URI    
    location+=slash-4;
    memcpy(location,REQUESTHEAD,5);
    char * getlinestart=malloc(strlen(location));
    strcpy(getlinestart,location);
    //printf("request:\n%s\n",getlinestart);
    //if (!retc) {
    while (collected<length) {
        sprintf(recv_buf,"%s%d-%d%s",getlinestart,collected,collected+4095,CRLFCRLF);
        send_bytes=strlen(recv_buf);
        //printf("request:\n%s\n",recv_buf);
        printf("send request......");
        ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        recv_bytes=0;
        if (ret > 0) {
            printf("OK\n\n");

            header=1;
            memset(recv_buf,0,RECV_BUF_LEN);
            //wolfSSL_Debugging_ON();
            do {
                ret = wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 1);
                if (ret > 0) {
                    if (header) {
                        //printf("%s\n-------- %d\n", recv_buf, ret);
                        //parse Content-Length: xxxx
                        location=strstr(recv_buf,"Content-Length: ");
                        strchr(location,'\r')[0]=0;
                        location+=16; //flush Content-Length: //
                        clength=atoi(location);
                        location[strlen(location)]='\r'; //in case the order changes
                        //parse Content-Range: bytes xxxx-yyyy/zzzz
                        location=strstr(recv_buf,"Content-Range: bytes ");
                        strchr(location,'\r')[0]=0;
                        location+=21; //flush Content-Range: bytes //
                        location=strstr(location,"/"); location++; //flush /
                        length=atoi(location);
                        //verify if last bytes are crlfcrlf else slash--
                    } else {
                        recv_bytes += ret;
                        collected+=ret;
                        for (ret=0;ret<16;ret++) printf("%02x ", recv_buf[ret]); //write to flash
                        printf("\n");
                    }
                } else {
                    if (ret) {ret=wolfSSL_get_error(ssl,ret); printf("error %d\n",ret);}
                    if (!ret && collected<length) retc = ota_connect(host2, HTTPS_PORT, &socket, &ssl); //memory leak?
                    break;
                }
                header=0;
            } while(recv_bytes<clength);
            printf("so far collected %d bytes\n", collected);
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            ret=wolfSSL_get_error(ssl,ret);
            printf("wolfSSL_send error = %d\n", ret);
            if (ret==-308) {
                retc = ota_connect(host2, HTTPS_PORT, &socket, &ssl); //dangerous for eternal connecting? memory leak?
            }
        }
    }
    switch (retc) {
        case  0:
        case -1:
        wolfSSL_free(ssl);
        case -2:
        lwip_close(socket);
        case -3:
        default:
        ;
    }
    free(host2);
    free(getlinestart);
    return collected;
}

int   ota_get_hash(char * url, char * version, char * name, signature_t signature) {
    printf("ota_get_hash\n");
    return -1;
}

int   ota_verify_hash(int sector, byte* hash, int filesize) {
    printf("ota_verify_hash\n");
    return 0;
}

int   ota_verify_signature(signature_t signature) {
    printf("ota_verify_signature\n");
    return 0;
}

void  ota_swap_cert_sector() {
    printf("ota_swap_cert_sector\n");

}

void  ota_write_status0() {
    printf("ota_write_status0\n");

}

void  ota_reboot() {
    printf("ota_reboot\n");

}