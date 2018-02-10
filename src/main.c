/*
 * OTA-boot main app
 */

#include <stdlib.h>  //for printf and free
#include <stdio.h>
#include <esp/uart.h>
#include <esp8266.h>
#include <FreeRTOS.h>
#include <task.h>

//#include <stdlib.h>  // for printf

#include <wifi_config.h>
#include <string.h>  //for stdcmp

#include <ota.h> //stored at ../common

#define MYVERSION "1.2.6"
#define HOLDOFF_MULTIPLIER 3    //more like 20  -> 20s,400 (~6min),8000 (~2h),160000 (~2days)
#define HOLDOFF_MAX 50          //more like 604800 (1 week)
#define CERTFILE "certificates.sector"
//#define OTAURL  "HomeACcessoryKid/ota"
#define OTAURL  "HomeACcessoryKid/FOTAtest"
#define OTAFILE "ota.bin"
//#define SELFURL "HomeACcessoryKid/otaself"
#define SELFURL "HomeACcessoryKid/FOTAtest"
#define SELFFILE "otaself.bin"
#define SECTORSIZE 4096
#define BOOT0SECTOR 2

void ota_task(void *arg) {
    int holdoff_time=1; //32bit, in seconds
    char* main_url = "HomeACcessoryKid/FOTAtest";
    char* main_version = "1.0.4";
    char* main_file = "eagle.flash.bin";
    char*  new_version=NULL;
    char*  ota_version=NULL;
    char* self_version=NULL;
    signature_t signature;
    int active_cert_sector=0xF6000;
    int backup_cert_sector=0xF5000;
    int file_size; //32bit

    ota_init();

    if ( !ota_load_main_app(main_url, main_version, main_file)) { //if url/version/file configured
        for (;;) { //escape from this loop by continue (try again) or break (boots into slot 0)
            //printf("%d\n",sdk_system_get_time()/1000);
            //need for a protection against an electricity outage recovery storm
            vTaskDelay(holdoff_time*1000/portTICK_PERIOD_MS);
            holdoff_time*=HOLDOFF_MULTIPLIER; holdoff_time=(holdoff_time<HOLDOFF_MAX) ? holdoff_time : HOLDOFF_MAX;
            
            //do we still have a valid internet connexion? dns resolve github... should not be private IP
            
            ota_set_validate(0); //should work even with faked server
            if ( ota_version) free( ota_version);
            if ( new_version) free( new_version);
            if (self_version) free(self_version);
            ota_version=ota_get_version(OTAURL);
            ota_get_hash(OTAURL, ota_version, CERTFILE, signature);
            if (ota_verify_hash(active_cert_sector,signature.hash,SECTORSIZE)) { //seems we need to download certificates
                ota_get_file(OTAURL,ota_version,CERTFILE,backup_cert_sector);
                if (ota_verify_hash(backup_cert_sector,signature.hash,SECTORSIZE)|| ota_verify_signature(signature)) {
                    //trouble, so abort
                    break; //leads to boot=0
                }
                ota_swap_cert_sector();
            } //certificates are good now
            ota_set_validate(1); //reject faked server
            if (ota_get_hash(OTAURL, ota_version, CERTFILE, signature)) { //testdownload, if server is fake will trigger
                //report by syslog?  //trouble, so abort
                break; //leads to boot=0
            }
            if (ota_compare(ota_version,MYVERSION)>0) { //how to get version into code? or codeversion into github
                self_version=ota_get_version(SELFURL);
                ota_get_hash(SELFURL, ota_version, SELFFILE, signature);
                file_size=ota_get_file(SELFURL,self_version,SELFFILE,BOOT0SECTOR);
                if (file_size<=0) continue; //something went wrong, but now boot0 is broken so start over
                if (ota_verify_hash(BOOT0SECTOR,signature.hash,file_size)) continue; //download failed
                break; //leads to boot=0 and starts self-updater
            } //ota code is up to date
            new_version=ota_get_version(main_url);
            if (ota_compare(new_version,main_version)>0) { 
                ota_get_hash(main_url, new_version, main_file, signature);
                file_size=ota_get_file(main_url,new_version,main_file,BOOT0SECTOR);
                if (file_size<=0) continue; //something went wrong, but now boot0 is broken so start over
                if (ota_verify_hash(BOOT0SECTOR,signature.hash,file_size)) continue; //download failed
            } //nothing to update
            ota_write_status0(); //we have been successful, hurray!
            break; //leads to boot=0 and starts main app
        }
    }
    ota_reboot(0); //boot0 without erasing sector 1
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}

void on_wifi_ready() {
    xTaskCreate(ota_task,"ota",4096,NULL,1,NULL);
    printf("wifiready-done\n");
}

void user_init(void) {
//    uart_set_baud(0, 74880);
    uart_set_baud(0, 115200);

    wifi_config_init("OTA", NULL, on_wifi_ready); //need to expand it with setting repo-details
    printf("user-init-done\n");
}
