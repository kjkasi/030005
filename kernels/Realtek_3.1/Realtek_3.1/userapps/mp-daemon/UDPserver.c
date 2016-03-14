//=============================================================================
// Copyright (c) 2006 Realtek Semiconductor Corporation.	All Rights Reserved.
//
//	Title:
//		UDPserver.c
//	Desc:
//		UDP server : accepts MP commands from the client
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <fcntl.h>
#include <errno.h>

#include "cfg_schema.h"
#include "cfg_api.h"
#include "cfg_write.h"
#include "cfg_subjects.h"
#ifndef WIN32
#define __PACK__			__attribute__ ((packed))
#else
#define __PACK__
#endif


#define MYPORT 9034                    // the port users will be connecting to
#define BUFLEN 1024                      // length of the buffer
#define MP_TX_PACKET 0x8B71
#define MP_BRX_PACKET 0x8B73
#define MP_QUERY_STATS 	0x8B6D
#define RTL8190_IOCTL_WRITE_REG				0x89f3
#define RTL8190_IOCTL_READ_REG				0x89f4
#define MP_CONTIOUS_TX	0x8B66
#define MP_TXPWR_TRACK	0x8B6E
#define MP_QUERY_TSSI	0x8B6F
#define MP_QUERY_THER 0x8B77

#define FLASH_DEVICE_NAME		("/dev/mtd")
#define FLASH_DEVICE_NAME1		("/dev/mtdblock1")
#define HW_SETTING_HEADER_TAG		((char *)"hs")
#define HW_SETTING_OFFSET		0x6000
#define DEFAULT_SETTING_OFFSET		0x8000
#define CURRENT_SETTING_OFFSET		0xc000

#if 1
#define TAG_LEN					2
#define SIGNATURE_LEN			4
#define HW_SETTING_VER			3	// hw setting version
/* Config file header */
typedef struct param_header {
	unsigned char signature[SIGNATURE_LEN] __PACK__;  // Tag + version
	unsigned short len __PACK__;
} PARAM_HEADER_T, *PARAM_HEADER_Tp;
PARAM_HEADER_T hsHeader;
#endif

typedef enum {
        HW_WLAN0_TX_POWER_CCK_A,
	HW_WLAN0_TX_POWER_CCK_B,
        HW_WLAN0_TX_POWER_HT40_1S_A,
	HW_WLAN0_TX_POWER_HT40_1S_B,
	HW_WLAN0_TX_POWER_DIFF_HT40_2S,
	HW_WLAN0_TX_POWER_DIFF_HT20,
	HW_WLAN0_TX_POWER_DIFF_OFDM,
	HW_WLAN0_11N_XCAP,
	HW_WLAN0_11N_THER,
	HW_WLAN0_REG_DOMAIN,
} CONFIG_FIELDS_T;

#define MAX_PARAMS 10  //HW_NIC0_ADDR,HW_NIC1_ADDR are not in count 
#define BUF_LEN 128
struct WirelessCalibrations{
	char calibParam[MAX_PARAMS][BUF_LEN];
};
static struct WirelessCalibrations WirCalib;
static int thermal = 0;
#if 0
/* Do checksum and verification for configuration data */
#ifndef WIN32
static inline unsigned char CHECKSUM(unsigned char *data, int len)
#else
__inline unsigned char CHECKSUM(unsigned char *data, int len)
#endif
{
	int i;
	unsigned char sum=0;

	for (i=0; i<len; i++)
		sum += data[i];

	sum = ~sum + 1;
	return sum;
}
#ifndef WIN32
static inline int CHECKSUM_OK(unsigned char *data, int len)
#else
__inline int CHECKSUM_OK(unsigned char *data, int len)
#endif
{
	int i;
	unsigned char sum=0;

	for (i=0; i<len; i++)
		sum += data[i];

	if (sum == 0)
		return 1;
	else
		return 0;
}
void get_read_reg_value( FILE *fp, char *buf, int maxlen );
/////////////////////////////////////////////////////////////////////////////////
static int flash_read(char *buf, int offset, int len)
{
	int fh;
	int ok=1;

	fh = open(FLASH_DEVICE_NAME, O_RDWR);
	if ( fh == -1 )
		return 0;

	lseek(fh, offset, SEEK_SET);

	if ( read(fh, buf, len) != len)
		ok = 0;

	close(fh);

	return ok;
}


////////////////////////////////////////////////////////////////////////////////
static int flash_write(char *buf, int offset, int len)
{
	int fh;
	int ok=1;

	fh = open(FLASH_DEVICE_NAME, O_RDWR);

	if ( fh == -1 )
		return 0;

	lseek(fh, offset, SEEK_SET);

	if ( write(fh, buf, len) != len)
		ok = 0;

	close(fh);
	sync();

	return ok;
}

int ReadSinguture(void)
{
	int ver;
	char *buff;
	// Read hw setting
	if ( flash_read((char *)&hsHeader, HW_SETTING_OFFSET, sizeof(hsHeader))==0 ) {
		printf("Read hw setting header failed!\n");
		return NULL;
	}

	if ( sscanf(&hsHeader.signature[TAG_LEN], "%02d", &ver) != 1)
		ver = -1;

	if ( memcmp(hsHeader.signature, HW_SETTING_HEADER_TAG, TAG_LEN) || // invalid signatur
		(ver != HW_SETTING_VER)  ) { // length is less than current
		printf("Invalid hw setting signature or version number [sig=%c%c, ver=%d, len=%d]!\n", hsHeader.signature[0],
			hsHeader.signature[1], ver, hsHeader.len);
		return NULL;
	}
	//printf("hw setting signature or version number [sig=%c%c, ver=%d, len=%d]!\n", hsHeader.signature[0],	hsHeader.signature[1], ver, hsHeader.len);
	buff = calloc(1, hsHeader.len);
	if ( buff == 0 ) {
		printf("Allocate buffer failed!\n");
		return NULL;
	}
	if ( flash_read(buff, HW_SETTING_OFFSET+sizeof(hsHeader), hsHeader.len)==0 ) {
		printf("Read hw setting failed!\n");
		free(buff);
		return NULL;
	}
	if ( !CHECKSUM_OK(buff, hsHeader.len) ) {
		printf("Invalid checksum of hw setting!\n");
		free(buff);
		return NULL;
	}
	//printf("CS=%x\n",buff[hsHeader.len-1]);
}
#endif


static int get_field(char *buff)
{
	char *tmpBuf;
	//TODO
	if(!strncmp(buff,"HW_",3)) {
		//printf("started with HW_\n");
		return -1;
	}
	else 
		tmpBuf = (buff +10);
	if(!strncmp(tmpBuf, "HW_WLAN0_REG_DOMAIN", strlen("HW_WLAN0_REG_DOMAIN")))
		return HW_WLAN0_REG_DOMAIN;
	else if (!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_CCK_A", strlen("HW_WLAN0_TX_POWER_CCK_A")))
		return HW_WLAN0_TX_POWER_CCK_A;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_CCK_B", strlen("HW_WLAN0_TX_POWER_CCK_B")))
		return HW_WLAN0_TX_POWER_CCK_B;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_HT40_1S_A", strlen("HW_WLAN0_TX_POWER_HT40_1S_A")))
		return HW_WLAN0_TX_POWER_HT40_1S_A;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_HT40_1S_B", strlen("HW_WLAN0_TX_POWER_HT40_1S_B")))
		return HW_WLAN0_TX_POWER_HT40_1S_B;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_DIFF_HT40_2S", strlen("HW_WLAN0_TX_POWER_DIFF_HT40_2S")))
		return HW_WLAN0_TX_POWER_DIFF_HT40_2S;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_DIFF_HT20", strlen("HW_WLAN0_TX_POWER_DIFF_HT20")))
		return HW_WLAN0_TX_POWER_DIFF_HT20;
	else if(!strncmp(tmpBuf, "HW_WLAN0_TX_POWER_DIFF_OFDM", strlen("HW_WLAN0_TX_POWER_DIFF_OFDM")))
		return HW_WLAN0_TX_POWER_DIFF_OFDM;
	else if(!strncmp(tmpBuf, "HW_WLAN0_11N_THER",strlen("HW_WLAN0_11N_THER")))
		return HW_WLAN0_11N_THER;
	else if(!strncmp(tmpBuf, "HW_11N_THER",strlen("HW_11N_THER")))
	{
		thermal = 1;
		return HW_WLAN0_11N_THER;
	}
	else if(!strncmp(tmpBuf, "HW_WLAN0_11N_XCAP", strlen("HW_WLAN0_11N_XCAP")))
		return HW_WLAN0_11N_XCAP;
	/*else if(!strncmp(tmpBuf, "HW_WLAN0_WLAN_ADDR", strlen("HW_WLAN0_WLAN_ADDR")))
		return HW_WLAN0_WLAN_ADDR;
	else if(!strncmp(tmpBuf, "HW_NIC0_ADDR", strlen("HW_NIC0_ADDR")))
	//	return HW_NIC0_ADDR;
		return HW_WLAN0_WLAN_ADDR;
	else if(!strncmp(tmpBuf, "HW_NIC1_ADDR", strlen("HW_NIC1_ADDR")))
	//	return HW_NIC1_ADDR;
		return HW_WLAN0_WLAN_ADDR;*/
	else 
		return -1;
}

static void remove_special_char(char *src, char *target,char flag)
{
        int i = 0, j = 0,k = 0,int_data[14];
	char buf[32] = {0};
        char data[16] = {0};

	if(1 == flag)
	{
		if(!strchr(src,' '))
		{
			strcpy(target,src);
			return;
		}
		for(i = 0 ,j = 0 ,k = 0; i< 14 ;j++)
		{

			if((' ' == src[j]) || ('\0' == src[j]))
			{
				data[k] = '\0';
				k = 0;
				int_data[i++]=atoi(data);
				memset(data,'\0',16);
			}
			else
			{
				data[k++] = src[j];
			}
		}

			sprintf(buf,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",int_data[0],int_data[1],int_data[2],int_data[3],int_data[4],int_data[5],int_data[6],int_data[7],int_data[8],int_data[9],int_data[10],int_data[11],int_data[12],int_data[13]);
		strcpy(target,buf);
	}	
    else
	{
		while (src[i] != '\0') {
			if(src[i] == ' ') {
				i++;
				continue;
			} else {
				target[j] = src[i];
				i++;
				j++;
                	}
        }

        target[j] = '\0';
	}		
}

static int flash_write (char *buff, unsigned int len)
{
	char tmpBuf[200] = {0};
	int MPField = -1;
	char *tmp;
	


	if(buff){
                MPField = get_field(buff);
		if(-1 == MPField){
		//printf(" Nothing to be write  \n");
		return -1;}	
		}
        else {
                printf("NULL buffer received, Cann't process\n" );
                return -1;
        }
	tmp = buff;
	tmp = tmp +10;
	
	switch(MPField)
	{
		case HW_WLAN0_TX_POWER_CCK_A:
			tmp += sizeof("HW_WLAN0_TX_POWER_CCK_A");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_CCK_A],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_CCK_A],"flash set HW_WLAN0_TX_POWER_CCK_A %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_CCK_B:
			tmp += sizeof("HW_WLAN0_TX_POWER_CCK_B");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_CCK_B],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_CCK_B],"flash set HW_WLAN0_TX_POWER_CCK_B %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_HT40_1S_A:
			tmp += sizeof("HW_WLAN0_TX_POWER_HT40_1S_A");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_HT40_1S_A],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_HT40_1S_A],"flash set HW_WLAN0_TX_POWER_HT40_1S_A %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_HT40_1S_B:
			tmp += sizeof("HW_WLAN0_TX_POWER_HT40_1S_B");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_HT40_1S_B],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_HT40_1S_B],"flash set HW_WLAN0_TX_POWER_HT40_1S_B %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_DIFF_HT40_2S:
			tmp += sizeof("HW_WLAN0_TX_POWER_DIFF_HT40_2S");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_HT40_2S],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_HT40_2S],"flash set HW_WLAN0_TX_POWER_DIFF_HT40_2S %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_DIFF_HT20:
			tmp += sizeof("HW_WLAN0_TX_POWER_DIFF_HT20");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_HT20],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_HT20],"flash set HW_WLAN0_TX_POWER_DIFF_HT20 %s",tmpBuf);	 
			break;
		case HW_WLAN0_TX_POWER_DIFF_OFDM:
			tmp += sizeof("HW_WLAN0_TX_POWER_DIFF_OFDM");
			remove_special_char(tmp,tmpBuf,1);
			memset(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_OFDM],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_TX_POWER_DIFF_OFDM],"flash set HW_WLAN0_TX_POWER_DIFF_OFDM %s",tmpBuf);	 
			break;
		case HW_WLAN0_11N_THER:
			if(thermal)
			{
				thermal = 0;
				tmp += sizeof("HW_11N_THER");
				remove_special_char(tmp,tmpBuf,0);
				memset(WirCalib.calibParam[HW_WLAN0_11N_THER],0,BUF_LEN);
				sprintf(WirCalib.calibParam[HW_WLAN0_11N_THER],"flash set HW_11N_THER %s",tmpBuf);	 
			}
			else
			{
				tmp += sizeof("HW_WLAN0_11N_THER");
				remove_special_char(tmp,tmpBuf,0);
				memset(WirCalib.calibParam[HW_WLAN0_11N_THER],0,BUF_LEN);
				sprintf(WirCalib.calibParam[HW_WLAN0_11N_THER],"flash set HW_WLAN0_11N_THER %s",tmpBuf);	 
			}
			break;
		case HW_WLAN0_11N_XCAP:
			tmp += sizeof("HW_WLAN0_11N_XCAP");
			remove_special_char(tmp,tmpBuf,0);
			memset(WirCalib.calibParam[HW_WLAN0_11N_XCAP],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_11N_XCAP],"flash set HW_WLAN0_11N_XCAP %s",tmpBuf);	 
			break;
		case HW_WLAN0_REG_DOMAIN:
			tmp += sizeof("HW_WLAN0_REG_DOMAIN");
			remove_special_char(tmp,tmpBuf,0);
			memset(WirCalib.calibParam[HW_WLAN0_REG_DOMAIN],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_REG_DOMAIN],"flash set HW_WLAN0_REG_DOMAIN %s",tmpBuf);	 
			break;
		/*case HW_WLAN0_WLAN_ADDR:
			tmp += sizeof("HW_WLAN0_WLAN_ADDR");
			remove_special_char(tmp,tmpBuf,0);
			memset(WirCalib.calibParam[HW_WLAN0_WLAN_ADDR],0,BUF_LEN);
			sprintf(WirCalib.calibParam[HW_WLAN0_WLAN_ADDR],"flash set HW_WLAN0_WLAN_ADDR %s",tmpBuf);	 
			break;*/
	}


			//printf("WirCalib.calibParam[%d] = %s \n",MPField,WirCalib.calibParam[MPField]);
return 0;
}
static void flash_read (char *buff, unsigned int len)
{
	int i, j,read_size;
	char configParam[64] = {0},Param[64] = {0},line[128] = {0};
	char tmpBuf[100] = {0};
	int MPField = -1,  rVal;
	FILE *fp,*calibr_fp;


	if ((fp = fopen("/tmp/MP.txt", "w")) == NULL)
	{
		fprintf(stderr, "opening MP.txt failed !\n");
		return;
	}
	if(buff){
		MPField = get_field(buff);
		if(-1 == MPField){
			//printf(" Nothing to be read  \n");
			return;
		}
		
	}
	else {
		printf("NULL buffer received, Cann't process\n" );
		return;
	}

        

	switch(MPField) {
		case HW_WLAN0_TX_POWER_CCK_A:
			fprintf(fp, "HW_WLAN0_TX_POWER_CCK_A");
			break;
		case HW_WLAN0_TX_POWER_CCK_B:
			fprintf(fp, "HW_WLAN0_TX_POWER_CCK_B");
			break;
		case HW_WLAN0_TX_POWER_HT40_1S_A:
			fprintf(fp, "HW_WLAN0_TX_POWER_HT40_1S_A");
			break;
		case HW_WLAN0_TX_POWER_HT40_1S_B:
			fprintf(fp, "HW_WLAN0_TX_POWER_HT40_1S_B");
			break;
		case HW_WLAN0_TX_POWER_DIFF_HT40_2S:
			fprintf(fp, "HW_WLAN0_TX_POWER_DIFF_HT40_2S");
			break;
		case HW_WLAN0_TX_POWER_DIFF_HT20:
			fprintf(fp, "HW_WLAN0_TX_POWER_DIFF_HT20");
			break;
		case HW_WLAN0_TX_POWER_DIFF_OFDM:
			fprintf(fp, "HW_WLAN0_TX_POWER_DIFF_OFDM");
			break;
		case HW_WLAN0_REG_DOMAIN:
			fprintf(fp, "HW_WLAN0_REG_DOMAIN");
			break;
		/*case HW_WLAN0_WLAN_ADDR:
			fprintf(fp, "HW_WLAN0_WLAN_ADDR");
			rVal = 1;
			break;*/
		case HW_WLAN0_11N_THER: 
			if(thermal)
			{
				thermal = 0;
				fprintf(fp, "HW_11N_THER");
			}
			else	
			{
				fprintf(fp, "HW_WLAN0_11N_THER");

			}
			break;
		case HW_WLAN0_11N_XCAP:
			fprintf(fp, "HW_WLAN0_11N_XCAP");
			break;
		/*case HW_NIC0_ADDR:
			//fprintf(fp, "HW_NIC0_ADDR");
			fprintf(fp, "HW_WLAN0_WLAN_ADDR");
			rVal = 1;
			break;
		case HW_NIC1_ADDR:
			//fprintf(fp, "HW_NIC1_ADDR");
			fprintf(fp, "HW_WLAN0_WLAN_ADDR");
			rVal = 1;
		      	break;*/
	}

	calibr_fp = fopen("/WFIO/calibrate.bin","rb");
	if(NULL == calibr_fp )
	{
		printf(" Error in opening /WFIO/calibrate.bin file in read mode ! \n");
		fclose(fp);
		return;
	}
	else
	{
		memset(&WirCalib.calibParam[MPField],0,BUF_LEN);
		read_size = fread(&WirCalib.calibParam,sizeof(WirCalib),1,calibr_fp);
		//if(0 == read_size)
		//printf("Reading /WFIO/calibrate.bin is failed    &  sizeof(WirCalib) = %d \n",sizeof(WirCalib));
		//else 
		//printf("Read size = %d  \n",read_size);
		//printf("WirCalib.calibParam[%d] = %s \n",MPField,WirCalib.calibParam[MPField]);
		strcpy(line,WirCalib.calibParam[MPField]);
		//printf(" Line : %s \n",line);
	}
	
	strcpy(configParam,strrchr(line,' ')+1);
	
	if(!strcmp(configParam, "")) {
		printf("No Value\n");
		if(NULL != fp)
			fclose(fp);
		return;
	}
	if (1 == rVal) //to skip ':' 
	{
		for (i = 0,j = 0; configParam[i] != '\0'; i++) {
			if(':' != configParam[i]){
				tmpBuf[j] = configParam[i];
				j++;
			}
		}
		tmpBuf[j] = '\0';
		fprintf(fp, "=%s\n", tmpBuf);
	}
	else
	{
		fprintf(fp, "=%s\n", configParam);
	}
	
	if(NULL != calibr_fp){
		fflush(calibr_fp);
		fclose(calibr_fp);
	}
	if(NULL != fp){
		fflush(fp);	
		fclose(fp);
	}
}

/*
 * Wrapper to extract some Wireless Parameter out of the driver
 */
static inline int iw_get_ext(int skfd,    /* Socket to the kernel */
           			char *ifname,        	/* Device name */
           			int request,        		/* WE ID */
           			struct iwreq *pwrq)    /* Fixed part of the request */
{
  	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);	/* Set device name */
  	return(ioctl(skfd, request, pwrq));			/* Do the request */
}

int MP_get_ext(char *ifname, char *buf, unsigned int ext_num)
{
    	int skfd;
    	struct iwreq wrq;

    	skfd = socket(AF_INET, SOCK_DGRAM, 0);
    	wrq.u.data.pointer = (caddr_t)buf;
    	wrq.u.data.length = strlen(buf);

    	if (iw_get_ext(skfd, ifname, ext_num, &wrq) < 0) {
    		printf("MP_get_ext failed\n");
		return -1;
    	}
	
    	close(skfd);
    	return 0;
}
//the value is included in the 2nd line
//and need transfer to decimal from hex (match MP_TEST.exe's format)
void get_read_reg_value( FILE *fp, char *buf, int maxlen )
{
	int cget,value,start;
	unsigned char *p, *p2;

	p=strchr( buf, '\n' );
	if(p==NULL) return;
	p2=p;
		
	value=0;start=0;
	while( (cget=fgetc(fp))!=EOF )
	{
		//printf( "get=%c\n", cget );
		if( (cget=='\n') || (cget==' ') )
		{
			if(start) p2 += sprintf( p2, "%d ", value );
			//printf( "start=%d, value=%d, buf=(%s)\n", start, value, buf );
			value=0;
			start=0;			
		}else if( isxdigit(cget) )
		{
			start=1;
			//printf( "value=%d,", value );
			if( cget>='0' && cget<='9' )
				value=value*16+(cget-'0');
			else if( cget>='a' && cget<='f' )
				value=value*16+(10+cget-'a');
			else if( cget>='A' && cget<='F' )
				value=value*16+(10+cget-'A');
			//printf( "new value=%d\n", value );
		}else{
			//error
			sprintf( p, "\n", value );
			return;
		}
	}
	*p2=0;
}
int main(void) {
	int sockfd;                     				// socket descriptors
	struct sockaddr_in my_addr;     		// my address information
	struct sockaddr_in their_addr;  			// connector¡¦s address information
	int addr_len, numbytes,write_size;
	FILE *fp = NULL;
	char buf[BUFLEN], buf_tmp[BUFLEN], pre_result[BUFLEN];  // buffer that stores message
	static char cmdWrap[500];
	static int rwHW = 0, wHW = 0, rHW = 0, len = 0;
	FILE *tmp_file = NULL;
	
	// create a socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	my_addr.sin_family = AF_INET;         		// host byte order
	my_addr.sin_port = htons(MYPORT);     	// short, network byte order
	my_addr.sin_addr.s_addr = INADDR_ANY; 	// automatically fill with my IP
	memset(&(my_addr.sin_zero), '\0', 8); 	// zero the rest of the struct

	// bind the socket with the address
	if (bind(sockfd, (struct sockaddr *)&my_addr,
		sizeof(struct sockaddr)) == -1) {
		perror("bind");
		close(sockfd);
		exit(1);
	}

	addr_len = sizeof(struct sockaddr);

	printf("MP AUTOMATION daemon (ver 1.2)\n");
	//Self reading flash!!!
	#if 	0
	if(!ReadSinguture())
	{
		printf("HW Settting Error!!\n");
	}
	#endif	
	// main loop : wait for the client
	while (1) {
		//receive the command from the client
		memset(buf, 0, BUFLEN);
		memset(cmdWrap, 0, 500);
		rwHW = 0;
		if ((numbytes = recvfrom(sockfd, buf, BUFLEN, 0,
			(struct sockaddr *)&their_addr, &addr_len)) == -1) {
			fprintf(stderr,"Receive failed!!!\n");
			close(sockfd);
			exit(1);
		}
		
		//printf("received command (%s) from IP:%s\n", buf, inet_ntoa(their_addr.sin_addr));

		if(!memcmp(buf, "orf", 3)){
                        strcat(buf, " > /tmp/MP.txt");
                        system(buf);
                }
                if(!memcmp(buf, "irf", 3)){
                        strcat(buf, " > /tmp/MP.txt");
                        system(buf);
                }	
		if (!memcmp(buf, "ther", 4)) {
                        strcpy(buf, pre_result);
                }
		if (!memcmp(buf, "tssi", 4)) {
			strcpy(buf, pre_result);
		}
		if (!memcmp(buf, "query", 5)) {

			strcpy(buf, pre_result);
		}
		if(!memcmp(buf, "cat", 3)){

			strcat(buf, " > /tmp/MP.txt");
			system(buf);		
		}
	#if 1	
		if (!memcmp(buf, "iwpriv wlan0 mp_tssi", 20)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan0", buf_tmp, MP_QUERY_TSSI);
			strcpy(buf, buf_tmp);
			printf("buf= %s\n",buf);
			usleep(1000);
		}
		else if (!memcmp(buf, "iwpriv wlan0 mp_ther", 20)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan0", buf_tmp, MP_QUERY_THER);
			strcpy(buf, buf_tmp);
			printf("buf= %s\n",buf);
			usleep(1000);
		}
		else if (!memcmp(buf, "iwpriv wlan0 mp_query", 21)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan0", buf_tmp, MP_QUERY_STATS);
			strcpy(buf, buf_tmp);
			usleep(1000);
			printf("w0 2b= %s\n",buf);
		}
	#endif
	#if 0 	//wlan1 
		else if (!memcmp(buf, "iwpriv wlan1 mp_tssi", 20)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan1", buf_tmp, MP_QUERY_TSSI);
			strcpy(buf, buf_tmp);
			printf("buf= %s\n",buf);
			usleep(1000);
		}
		else if (!memcmp(buf, "iwpriv wlan1 mp_ther", 20)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan1", buf_tmp, MP_QUERY_THER);
			strcpy(buf, buf_tmp);
			printf("buf= %s\n",buf);
			usleep(1000);
		}
		else if (!memcmp(buf, "iwpriv wlan1 mp_query", 21)) {

			strcpy(buf, pre_result);
			MP_get_ext("wlan1", buf_tmp, MP_QUERY_STATS);
			strcpy(buf, buf_tmp);
			usleep(1000);
			printf("w1 2b= %s\n",buf);
		}
	#endif	
		else {


			if ( (!memcmp(buf, "flash read", 10)) ){
				if ((fp = fopen("/tmp/MP.txt", "r")) == NULL)
					fprintf(stderr, "opening MP.txt failed !\n");
	
				if (fp) {
				fgets(buf, BUFLEN, fp);
					buf[BUFLEN-1] = '\0';
					{	//fix read_reg bug
						char strread[]="wlan0     read_reg:\n";
						char strreadrf[]="wlan0     read_rf:\n";
						char strpsd[]="wlan0     mp_psd:\n";
						if( strncmp(buf,strread,strlen(strread) -1)==0 )
							get_read_reg_value( fp, buf, BUFLEN );
						if( strncmp(buf,strreadrf,strlen(strreadrf) -1)==0 )
							get_read_reg_value( fp, buf, BUFLEN );
						if( strncmp(buf,strpsd,strlen(strpsd) - 1)==0 ) {
							get_read_reg_value( fp, buf, BUFLEN );
						}
					}
					fclose(fp);
				}	
				sprintf(pre_result, "data:%s", buf);
				rwHW = 1;
			}
			//ack to the client
			else if (!memcmp(buf, "flash get", 9))
				sprintf(pre_result, "%s > /tmp/MP.txt ok", buf);
			else {
				sprintf(pre_result, "%s ok", buf);
				rwHW = 0;
			}
			
			if (!memcmp(buf, "iwpriv wlan0 mp_brx stop", 24)) {
				strcpy(buf, "stop");
				MP_get_ext("wlan0", buf, MP_BRX_PACKET);
			}
			else if (!memcmp(buf, "iwpriv wlan0 mp_tx", 18) && buf[18] == ' ') {
				memcpy(buf_tmp, buf+19, strlen(buf)-19);
				MP_get_ext("wlan0", buf_tmp, MP_TX_PACKET);
				strcpy(buf, buf_tmp);
			}
			
			else if (!memcmp(buf, "iwpriv wlan0 mp_ctx", 19) && buf[19] == ' ') {
				memcpy(buf_tmp, buf+20, strlen(buf)-20);
				MP_get_ext("wlan0", buf_tmp, MP_CONTIOUS_TX);
				strcpy(buf, buf_tmp);;
			}
			else if(!memcmp(buf, "iwpriv wlan0 read_reg", 21)){
				strcat(buf, " > /tmp/MP.txt");
				system(buf);
				
			}
			else if(!memcmp(buf, "iwpriv wlan0 efuse_get", 22)){
				strcat(buf, " > /tmp/MP.txt");
				system(buf);
				
			}
			else if(!memcmp(buf, "iwpriv wlan0 efuse_set", 22)){
                                strcat(buf, " > /tmp/MP.txt");
                                system(buf);
            		}
			else if(!memcmp(buf, "iwpriv wlan0 efuse_sync", 23)){
                                strcat(buf, " > /tmp/MP.txt");
                                system(buf);
            		}
            
#if 0  //wlan 1
			
			else if (!memcmp(buf, "iwpriv wlan1 mp_brx stop", 24)) {
				strcpy(buf, "stop");
				MP_get_ext("wlan1", buf, MP_BRX_PACKET);
			}
			else if (!memcmp(buf, "iwpriv wlan1 mp_tx", 18) && buf[18] == ' ') {
				memcpy(buf_tmp, buf+19, strlen(buf)-19);
				MP_get_ext("wlan1", buf_tmp, MP_TX_PACKET);
				strcpy(buf, buf_tmp);
			}
			
			else if (!memcmp(buf, "iwpriv wlan1 mp_ctx", 19) && buf[19] == ' ') {
				memcpy(buf_tmp, buf+20, strlen(buf)-20);
				MP_get_ext("wlan1", buf_tmp, MP_CONTIOUS_TX);
				strcpy(buf, buf_tmp);;
			}
			else if(!memcmp(buf, "iwpriv wlan1 read_reg", 21)){
				strcat(buf, " > /tmp/MP.txt");
				system(buf);
				
			}
			else if(!memcmp(buf, "iwpriv wlan1 efuse_get", 22)){
				strcat(buf, " > /tmp/MP.txt");
				system(buf);
				
			}
			else if(!memcmp(buf, "iwpriv wlan1 efuse_set", 22)){
                                strcat(buf, " > /tmp/MP.txt");
                                system(buf);
            		}
	else if(!memcmp(buf, "iwpriv wlan0 mp_psd", 19)){
				strcat(buf, " > /tmp/MP.txt");
				system(buf);		
			} 	
			else if(!memcmp(buf, "iwpriv wlan1 efuse_sync", 23)){
                                strcat(buf, " > /tmp/MP.txt");
                                system(buf);
            		}

#endif            
			else if (!memcmp(buf, "probe", 5))
				strcpy(buf, "ack");
			else if (!memcmp(buf, "verify_flw", 10)) {
				if ((fp = fopen("/tmp/MP.txt", "r")) == NULL)
					fprintf(stderr, "opening MP.txt failed !\n");
	
				if (fp) {
					fgets(buf, BUFLEN, fp);
					buf[BUFLEN-1] = '\0';
					fclose(fp);
				}
			}
			else {
#if 0
				if (!memcmp(buf, "flash get", 9))
					strcat(buf, " > /tmp/MP.txt");
#endif
					if (!memcmp(buf, "flash get", 9)){
					sprintf(cmdWrap, "flash gethw %s", buf+10);
					rHW = 1;
					rwHW = 0;
					////strcat(buf, " > /tmp/MP.txt");
					strcat(cmdWrap, " > /tmp/MP.txt");
				}
				if (!memcmp(buf, "flash set", 9)) {
					sprintf(cmdWrap, "flash sethw %s", buf+10);
					wHW = 1;
					rwHW = 0;
					//printf("1 sent command (pre_result = %s) to IP:%s   LINE = %d \n", pre_result, inet_ntoa(their_addr.sin_addr),__LINE__);
					if ((numbytes = sendto(sockfd, pre_result, strlen(pre_result), 0,
						(struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1) {
						fprintf(stderr, "send failed\n");
						close(sockfd);
						exit(1);
					}
					//printf("2 sent command (pre_result = %s) to IP:%s\n", pre_result, inet_ntoa(their_addr.sin_addr));
				}
				if(rHW == 1){
					len = strlen(buf);
					flash_read(buf, len);
					rHW = 0;
				} 
				else if (wHW == 1){
					len = strlen(buf);
					wHW = 0;
					if(0 == flash_write(buf, len))
					{
						// not writing for every command (optimising write operations)

						tmp_file = fopen("/WFIO/calibrate.bin","wb");
						if (!tmp_file) {
							printf("file open failed %d\n", errno);
						}
						else{
							write_size = fwrite(&WirCalib,sizeof(WirCalib),1,tmp_file);
							//	if(0 ==  write_size)
							//	 printf(" Failed in writeing \n");
							//	else
							//	printf(" Bytes Written = %d \n", write_size);
							if(tmp_file)
								fclose(tmp_file);
						}
					}
				}
				else {
					if(1 != rwHW){
						if(memcmp(buf,"iwpriv wlan1",12))
							system(buf);
						rwHW = 0;
					}
				}
				//delay
				//open(/tmp/abc.txt)
				
			}
			
			strcpy(buf_tmp, pre_result);
			strcpy(pre_result, buf);
			strcpy(buf, buf_tmp);
		}

		if (memcmp(buf, "flash set", 9) != 0) {
			//printf("1 sent command (buf= %s) to IP:%s   LINE = %d \n ", buf, inet_ntoa(their_addr.sin_addr),__LINE__);
			if ((numbytes = sendto(sockfd, buf, strlen(buf), 0,
				(struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1) {
				fprintf(stderr, "send failed\n");
				close(sockfd);
				exit(1);
			}
			//printf("2 sent command (buf= %s) to IP:%s\n", buf, inet_ntoa(their_addr.sin_addr));
		}
      }

	return 0;
}
