/*
 * This file has Netgear changes. Inorder to produce correct Crypt(which is treaed as correct by server) 
 * byte swap changes are done. It also contains syslog changes.
 */
#include <time.h>
#include "phupdate.h"
#include "log.h"
#include "blowfish.h"

#include "generate.h"
#include "lutil.h"
#include <stdlib.h>
/* Netgear Changes  Start Here*/ 
#include <syslog.h>

#if __BYTE_ORDER == __BIG_ENDIAN
extern inline unsigned int LongSwap (unsigned int i);
#endif

#define ORAY_CON_SUCCESS "Success"
#define ORAY_BAD_AUTH    "badauth"
/*
 * No host is not applicable for oray.com as username and password map to only one hostname
 */ 
/* #define ORAY_NO_HOST     "nohost" */
#define ORAY_CON_FAIL    "Failed"


static void set_persistent_ip(char *persist_cmd,char *ip_addr, char *status)
{
	char *ncmd = NULL;
	time_t update_tm;
	char new_status[1024];

	if(!persist_cmd){
		return;
	}

	memset(new_status, 0x0, sizeof(new_status));
	update_tm = time((time_t *) 0);
	if(!strcmp(status, ORAY_CON_SUCCESS)) {
		sprintf(new_status,"\"%s\"", status);
	} else {
		sprintf(new_status,"\"%s at %ld\"", status, update_tm);
	}
        /*
 	 *  3 - for 3 spaces in sprintf
 	 * 11 - for timer
 	 */
	ncmd = malloc(strlen(persist_cmd) + strlen(ip_addr) + 3 + 11 + strlen(new_status));
	if(!ncmd) {
		return;
	}
	sprintf(ncmd, "%s %s %ld %s", persist_cmd, 
		ip_addr, update_tm, new_status);
	system(ncmd);
	free(ncmd);
	return ;
}
/* Netgear Chnages Ends Here */

BOOL InitializeSockets(PHGlobal *phglobal)
{
	DestroySockets(phglobal);
	if (!phCreate(&(phglobal->m_tcpsocket),0,SOCK_STREAM,phglobal->szBindAddress))
	{
		return FALSE;
	}

	if (!phCreate(&(phglobal->m_udpsocket),0,SOCK_DGRAM,phglobal->szBindAddress))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL DestroySockets(PHGlobal *phglobal)
{
	phClose(&phglobal->m_tcpsocket);
	phClose(&phglobal->m_udpsocket);
	return TRUE;
}

BOOL BeginKeepAlive(PHGlobal *phglobal)
{
	if (!phConnect(phglobal->m_udpsocket, phglobal->szTcpConnectAddress,phglobal->nPort,&phglobal->nAddressIndex, NULL)) return FALSE;
	phglobal->nLastResponseID = time(0);
	return TRUE;
}

BOOL SendKeepAlive(PHGlobal *phglobal, int opCode)
{
	DATA_KEEPALIVE data;
	blf_ctx blf;
	char p1[KEEPALIVE_PACKET_LEN],p2[KEEPALIVE_PACKET_LEN];

	memset(&data,0,sizeof(data));
	data.lChatID = phglobal->nChatID;
	data.lID = phglobal->nStartID;
	data.lOpCode = opCode;
	data.lSum = 0 - (data.lID + data.lOpCode);
	data.lReserved = 0;

	if (!phglobal->bTcpUpdateSuccessed) return FALSE;

/* Netgear start */ 
        syslog(LOG_DEBUG,"SendKeepAlive() %d\n",opCode);
/* Netgear end */ 
	InitBlowfish(&blf, (unsigned char*)phglobal->szChallenge,phglobal->nChallengeLen);
	memcpy(p1,&data,KEEPALIVE_PACKET_LEN);
	memcpy(p2,&data,KEEPALIVE_PACKET_LEN);
	Blowfish_EnCode(&blf, p1+4,p2+4,KEEPALIVE_PACKET_LEN-4);
      
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        (*((unsigned int*)p2)) = LongSwap ((*((unsigned int*)p2)));
        (*((unsigned int*)(p2 + 4))) = LongSwap ((*((unsigned int*)(p2 + 4))));
        (*((unsigned int*)(p2 + 8)) ) = LongSwap ((*((unsigned int*)(p2 + 8))));
        (*((unsigned int*)(p2 + 12)) ) = LongSwap ((*((unsigned int*)(p2 + 12)))); 
        (*((unsigned int*)(p2 + 16)) ) = LongSwap ((*((unsigned int*)(p2 + 16))));
#endif
/* Netgear end */ 
	phSend(phglobal->m_udpsocket, p2, KEEPALIVE_PACKET_LEN,0);
	//RecvKeepaliveResponse();
	return TRUE;
}

int RecvKeepaliveResponse(PHGlobal *phglobal)
{
	char temp[100];
	DATA_KEEPALIVE_EXT rdata;
	DATA_KEEPALIVE data;
	blf_ctx blf;
	char p1[KEEPALIVE_PACKET_LEN],p2[KEEPALIVE_PACKET_LEN];

	if (!phglobal->bTcpUpdateSuccessed) return errorOccupyReconnect;

	//prevent the thread to be suspended while waiting for data
	if (phDataReadable(phglobal->m_udpsocket, 0)<=0) 
	{
		return okNoData;
	}
	//DATA_KEEPALIVE data;
	//if (m_udpsocket.Receive(&data,sizeof(DATA_KEEPALIVE),0)<=0) return FALSE;
	if (phReceive(phglobal->m_udpsocket, temp,sizeof(temp),0)<=0) return okNoData;
	memcpy(&rdata, temp, sizeof(DATA_KEEPALIVE_EXT));

	data = rdata.keepalive;

	InitBlowfish(&blf, (unsigned char*)phglobal->szChallenge,phglobal->nChallengeLen);


	memcpy(p1,&data,KEEPALIVE_PACKET_LEN);
	memcpy(p2,&data,KEEPALIVE_PACKET_LEN);

/* Netgear start */ 
#if __BYTE_ORDER == __BIG_ENDIAN
	(*((unsigned int*)p1)) = LongSwap ((*((unsigned int*)p1)));
	(*((unsigned int*)(p1 + 4))) = LongSwap ((*((unsigned int*)(p1 + 4))));
	(*((unsigned int*)(p1 + 8)) ) = LongSwap ((*((unsigned int*)(p1 + 8))));
	(*((unsigned int*)(p1 + 12)) ) = LongSwap ((*((unsigned int*)(p1 + 12)))); 
	(*((unsigned int*)(p1 + 16)) ) = LongSwap ((*((unsigned int*)(p1 + 16)))); 
	(*((unsigned int*)p2)) = LongSwap ((*((unsigned int*)p2)));
	(*((unsigned int*)(p2 + 4))) = LongSwap ((*((unsigned int*)(p2 + 4))));
	(*((unsigned int*)(p2 + 8)) ) = LongSwap ((*((unsigned int*)(p2 + 8))));
	(*((unsigned int*)(p2 + 12)) ) = LongSwap ((*((unsigned int*)(p2 + 12)))); 
	(*((unsigned int*)(p2 + 16)) ) = LongSwap ((*((unsigned int*)(p2 + 16)))); 
#endif
/* Netgear end */ 

	Blowfish_DeCode(&blf, p1+4,p2+4,KEEPALIVE_PACKET_LEN-4);
	memcpy(&data,p2,KEEPALIVE_PACKET_LEN);
	phglobal->nStartID = data.lID + 1;
	
/* Netgear start */ 
	syslog(LOG_DEBUG,"RecvKeepaliveResponse() Data comes, OPCODE:%d\n",data.lOpCode);
/* Netgear end */ 
	if (data.lID - phglobal->nLastResponseID > 3 && phglobal->nLastResponseID != -1)
	{
		return errorOccupyReconnect;
	}

	phglobal->nLastResponseID = data.lID;
	phglobal->tmLastResponse = time(0);

	phglobal->ip = rdata.ip;

	if (data.lOpCode == UDP_OPCODE_UPDATE_ERROR) return okServerER;
	//if (data.lOpCode == UDP_OPCODE_LOGOUT) return okNormal;
	
	return okKeepAliveRecved;
}

int ExecuteUpdate(PHGlobal *phglobal)
{
	char buffer[1024];
    
    char username[128] = "";
	char key[128] = "";
	char sendbuffer[256];
	
    char domains[255][255];
    char regicommand[255];
	int i,len, totaldomains;
	long challengetime = 0;

	char *chatid = NULL;
	char *startid = NULL;
	char *xmldata = NULL;
	int buflen = 0;

/* Netgear start */ 
	syslog(LOG_DEBUG,"ExecuteUpdate Connecting %s.\n",phglobal->szHost);
/* Netgear end */ 
	
	if (!phConnect(phglobal->m_tcpsocket, phglobal->szHost,phglobal->nPort,&phglobal->nAddressIndex,phglobal->szTcpConnectAddress))
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate errorConnectFailed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phglobal->nAddressIndex++;
		return errorConnectFailed;
	}
	//////////////////////////////////////////////////////////////////////////
	//Recv server hello string
	memset(buffer, 0, 128);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	if (len <=0 )
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Recv server hello string failed.\n");
		set_persistent_ip(phglobal->persist_cmd,"0.0.0.0",ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		phglobal->nAddressIndex++;
		return errorConnectFailed;
	}

/* Netgear start */ 
	syslog(LOG_DEBUG,"SEND AUTH REQUEST COMMAND...");
/* Netgear end */ 
	phSend(phglobal->m_tcpsocket, (char*)COMMAND_AUTH,sizeof(COMMAND_AUTH),0);
/* Netgear start */ 
        syslog(LOG_DEBUG,"OK.\n");
/* Netgear end */ 

	//////////////////////////////////////////////////////////////////////////
	//Recv server key string
	memset(buffer, 0, 128);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	if (len <=0 )
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Recv server key string failed.\n");
		set_persistent_ip(phglobal->persist_cmd,"0.0.0.0",ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return errorConnectFailed;
	}
/* Netgear start */ 
        syslog(LOG_DEBUG,"SERVER SIDE KEY \"%s\" RECEIVED.\n",buffer);
/* Netgear end */ 

	phglobal->nChallengeLen =  lutil_b64_pton(buffer+4, (unsigned char *)phglobal->szChallenge, 256);


	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//Generate encoded auth string
	len = GenerateCrypt(phglobal->szUserID, phglobal->szUserPWD, buffer+4, phglobal->clientinfo, phglobal->challengekey, sendbuffer);
	strcat(sendbuffer, "\r\n");
    //Generate ok.
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	
	//////////////////////////////////////////////////////////////////////////
	//send auth data
/* Netgear start */ 
	syslog(LOG_DEBUG,"SEND AUTH DATA...");
/* Netgear end */ 
	phSend(phglobal->m_tcpsocket, sendbuffer,strlen(sendbuffer),0);
/* Netgear start */ 
        syslog(LOG_DEBUG,"OK\n");
/* Netgear end */ 

	memset(buffer, 0, 128);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	buffer[3] = 0;

	if (len <=0 )
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Recv server auth response failed.\n");
		set_persistent_ip(phglobal->persist_cmd,"0.0.0.0",ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		//modified skyvense 2005/10/08, for server db conn lost bug
		//return errorAuthFailed;
		return errorConnectFailed;
	}
	if (strcmp(buffer,"250")!=0 && strcmp(buffer,"536")!=0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"CTcpThread::ExecuteUpdate auth failed.\n");
		set_persistent_ip(phglobal->persist_cmd,"0.0.0.0", ORAY_BAD_AUTH);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		
		if (strstr(buffer + 4, "Busy.") != NULL) return errorAuthBusy;
		return errorAuthFailed;
	}
	if (strcmp(buffer,"536") == 0) //find redirected server address, and let us connect again to new server
	{
		char *pos0 = strchr(buffer + 4, '<');
		if (pos0)
		{
			char *pos1 = strchr(pos0 + 1, '>');
			if (pos1)
			{
				*pos1 = '\0';
				strcpy(phglobal->szHost, pos0 + 1);
				
				phClose(&phglobal->m_tcpsocket);
				return okRedirecting;
			}
		}
		return errorAuthFailed;
	}
	if (strcmp(buffer,"250") == 0) //get user type level, 0(free),1(pro),2(biz)
	{
		char *pos0 = strchr(buffer + 4, '<');
		if (pos0)
		{
			char *pos1 = strchr(pos0 + 1, '>');
			if (pos1)
			{
				*pos1 = '\0';
				phglobal->nUserType = atoi(pos0 + 1);
			}
		}
	}
	
	//////////////////////////////////////////////////////////////////////////
	//list domains
	for (i=0,totaldomains=0;i<255;i++)
    {
        memset(domains[i], 0, 255);
        phReadOneLine(phglobal->m_tcpsocket, domains[i],255);
/* Netgear start */ 
        syslog(LOG_DEBUG,"ExecuteUpdate domain \"%s\"\n",domains[i]);
/* Netgear end */ 
        totaldomains++;
		strcpy(phglobal->szActiveDomains[i],domains[i]);
        if (domains[i][0] == '.') break;
    }
	if (totaldomains<=0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Domain List Failed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return errorDomainListFailed;
	}

	phglobal->cLastResult = okDomainListed;
	if (phglobal->cbOnStatusChanged) phglobal->cbOnStatusChanged(phglobal->cLastResult, 0);
	//::SendMessage(theApp.m_hWndController,WM_DOMAIN_UPDATEMSG,okDomainListed,(long)domains);
	//////////////////////////////////////////////////////////////////////////
	//send domain regi commands list
	for (i=0;;i++)
    {
        if (domains[i][0] == '.') break;
		memset(regicommand, 0, 128);
        strcpy(regicommand, COMMAND_REGI);
        strcat(regicommand, " ");
        strcat(regicommand, domains[i]);
        strcat(regicommand, "\r\n");
        //printf("%s",regicommand);
        phSend(phglobal->m_tcpsocket,regicommand,strlen(regicommand),0);
    }

	//////////////////////////////////////////////////////////////////////////
	//send confirm
/* Netgear start */ 
	syslog(LOG_DEBUG,"SEND CNFM DATA...");
/* Netgear end */ 
    phSend(phglobal->m_tcpsocket,(char*)COMMAND_CNFM,strlen(COMMAND_CNFM),0);
/* Netgear start */ 
    syslog(LOG_DEBUG,"OK\n");
/* Netgear end */ 
	
	for (i=0;i<totaldomains-1;i++)
    {
		memset(buffer, 0, 128);
		len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
		if (len <= 0)
		{
/* Netgear start */ 
			syslog(LOG_NOTICE,"ExecuteUpdate Recv server confirm response failed.\n");
/* Netgear end */ 
			phClose(&phglobal->m_tcpsocket);
			return errorDomainRegisterFailed;
		}
/* Netgear start */ 
		syslog(LOG_DEBUG,"ExecuteUpdate %s\n",buffer);
/* Netgear end */ 
		if (phglobal->cbOnDomainRegistered) phglobal->cbOnDomainRegistered(domains[i]);
    }
	
	memset(buffer, 0, 128);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	if (len <= 0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Recv server confirmed chatID response failed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return errorDomainRegisterFailed;
	}
/* Netgear start */ 
	syslog(LOG_DEBUG,"%s\n",buffer);
/* Netgear end */ 

	//////////////////////////////////////////////////////////////////////////
	//find chatid & startid
	chatid = buffer + 4;
	startid = NULL;
	
	for (i=4;i<strlen(buffer);i++)
	{
		if (buffer[i] == ' ')
		{
			buffer[i] = 0;
			startid = buffer + i + 1;
			break;
		}
	}
	phglobal->nChatID = atoi(chatid);
	if (startid) phglobal->nStartID = atoi(startid);
/* Netgear start */ 
	syslog(LOG_DEBUG,"ExecuteUpdate nChatID:%d, nStartID:%d\n",phglobal->nChatID,phglobal->nStartID);
/* Netgear end */ 
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//after confirm domain register, we begin to get user information
	phSend(phglobal->m_tcpsocket,(void *)COMMAND_STAT_USER,sizeof(COMMAND_STAT_USER),0);
	memset(buffer, 0, 1024);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	buffer[3] = 0;
	if (len <= 0 || strcmp(buffer,"250")!=0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"CTcpThread::ExecuteUpdate Recv server confirmed stat user response failed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return errorStatDetailInfoFailed;
	}
	
	buflen = MAX_PATH;
	xmldata = (char *)malloc(buflen);
	memset(xmldata, 0, buflen);
	
	for (;;)
	{
		memset(buffer, 0, 1024);
        len = phReadOneLine(phglobal->m_tcpsocket, buffer,1024);
        if (buffer[0] == '.' || len <= 0) break;
		if (buflen < strlen(xmldata) + len)
		{
			buflen += MAX_PATH;
			xmldata = realloc(xmldata, buflen);
			memset((xmldata + buflen) - MAX_PATH, 0, MAX_PATH);
		}
		strncat(xmldata, buffer, len);
	}
/* Netgear start */ 
	syslog(LOG_DEBUG,"userinfo: \r\n%s\r\n", xmldata);
/* Netgear end */ 
	if (phglobal->cbOnUserInfo) phglobal->cbOnUserInfo(xmldata, strlen(xmldata));
	free(xmldata);
	buflen = 0;
	

	phSend(phglobal->m_tcpsocket,(void *)COMMAND_STAT_DOM,sizeof(COMMAND_STAT_DOM),0);
	memset(buffer, 0, 1024);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	buffer[3] = 0;
	if (len <= 0 || strcmp(buffer,"250")!=0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"CTcpThread::ExecuteUpdate Recv server confirmed stat user response failed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return errorStatDetailInfoFailed;
	}
	
	buflen = MAX_PATH;
	xmldata = (char *)malloc(buflen);
	memset(xmldata, 0, buflen);

	for (;;)
	{
		memset(buffer, 0, 1024);
        len = phReadOneLine(phglobal->m_tcpsocket, buffer,1024);
        if (buffer[0] == '.' || len <= 0) break;
		if (buflen < strlen(xmldata) + len)
		{
			buflen += MAX_PATH;
			xmldata = realloc(xmldata, buflen);
			memset((xmldata + buflen) - MAX_PATH, 0, MAX_PATH);
		}
		strncat(xmldata, buffer, len);
	}
/* Netgear start */ 
	syslog(LOG_DEBUG,"domaininfo: \r\n%s\r\n", xmldata);
/* Netgear end */ 
	if (phglobal->cbOnAccountDomainInfo) phglobal->cbOnAccountDomainInfo(xmldata, strlen(xmldata));
	free(xmldata);
	buflen = 0;

	//////////////////////////////////////////////////////////////////////////
	//good bye!
/* Netgear start */ 
    syslog(LOG_DEBUG,"SEND QUIT COMMAND...");
/* Netgear end */ 
	phSend(phglobal->m_tcpsocket,(char*)COMMAND_QUIT,sizeof(COMMAND_QUIT),0);
/* Netgear start */ 
    syslog(LOG_DEBUG,"OK.\n");
/* Netgear end */ 
	
    memset(buffer, 0, 128);
	len = phReadOneLine(phglobal->m_tcpsocket, buffer,sizeof(buffer));
	if (len <= 0)
	{
/* Netgear start */ 
		syslog(LOG_NOTICE,"ExecuteUpdate Recv server goodbye response failed.\n");
		set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
		phClose(&phglobal->m_tcpsocket);
		return okDomainsRegistered;
	}
/* Netgear start */ 
	syslog(LOG_DEBUG,"%s\n",buffer);                               
	set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_SUCCESS);
/* Netgear end */ 
	phClose(&phglobal->m_tcpsocket);
	return okDomainsRegistered;
}

int phddns_step(PHGlobal *phglobal)
{
	int ret = 0;
	if (phglobal->bNeed_connect)
	{
		strcpy(phglobal->szActiveDomains[0],".");
		
		phglobal->cLastResult = okConnecting;
		
		if (phglobal->cbOnStatusChanged) phglobal->cbOnStatusChanged(phglobal->cLastResult, 0);
		
		if (!InitializeSockets(phglobal))
		{
/* Netgear start */ 
			syslog(LOG_NOTICE,"InitializeSockets failed, waiting for 5 seconds to retry...\n");
			set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
			phglobal->cLastResult = errorConnectFailed;
			if (phglobal->cbOnStatusChanged) phglobal->cbOnStatusChanged(phglobal->cLastResult, 0);
			return 5;
		}
		
		ret = ExecuteUpdate(phglobal);
		phglobal->cLastResult = ret;
		if (phglobal->cbOnStatusChanged) phglobal->cbOnStatusChanged(phglobal->cLastResult, ret == okDomainsRegistered ? phglobal->nUserType : 0);
		if (ret == okDomainsRegistered) 
		{
			//OnUserInfo(phglobal->szUserInfo);
			//OnAccountDomainInfo(phglobal->szDomainInfo);
/* Netgear start */ 
			syslog(LOG_DEBUG,"ExecuteUpdate OK, BeginKeepAlive!\n");
/* Netgear end */ 
			phglobal->bTcpUpdateSuccessed = TRUE;
			phglobal->tmLastResponse = time(0);
			phglobal->bNeed_connect = FALSE;
			BeginKeepAlive(phglobal);
			phglobal->lasttcptime = phglobal->tmLastSend = time(0);
		}
		else 
		{
			if (ret == okRedirecting)
			{
				phglobal->bTcpUpdateSuccessed = FALSE;
				phglobal->bNeed_connect = TRUE;
/* Netgear start */ 
				syslog(LOG_DEBUG,"Need redirect, waiting for 5 seconds...\n");
/* Netgear end */ 
				return 5;
			}
			
/* Netgear start */ 
			syslog(LOG_NOTICE,"ExecuteUpdate failed, waiting for 30 seconds to retry...\n");
                	//set_persistent_ip("0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
			return 30;
		}
		phglobal->nLastResponseID = -1;
	}
	else
	{
		if (time(0) - phglobal->tmLastSend > (phglobal->nUserType >= 1 ? 30 : 60))
		{
			SendKeepAlive(phglobal, UDP_OPCODE_UPDATE_VER2);
			phglobal->tmLastSend = time(0);
		}
		ret = RecvKeepaliveResponse(phglobal);
		if (ret != okNormal && ret != okNoData) phglobal->cLastResult = ret;
		if (ret == errorOccupyReconnect)
		{
/* Netgear start */ 
                        syslog(LOG_NOTICE, "RecvKeepaliveResponse failed, waiting for 30 seconds to reconnect...\n");
			set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
			phglobal->bNeed_connect = TRUE;
			phglobal->bTcpUpdateSuccessed = FALSE;
			return 30;
		}
		else
		{
			if (ret == okKeepAliveRecved)
			{
				struct in_addr t;
				t.s_addr = phglobal->ip;
/* Netgear start */ 
				syslog(LOG_DEBUG,"Keepalive response received, client ip: %s\n",inet_ntoa(t));
/* Netgear end */ 
				if (phglobal->cbOnStatusChanged) phglobal->cbOnStatusChanged(phglobal->cLastResult, phglobal->ip);
			}
		}
		if (time(0) - phglobal->tmLastResponse > (phglobal->nUserType >= 1 ? 160 : 320) && phglobal->tmLastResponse != -1)
		{
/* Netgear start */ 
			syslog(LOG_NOTICE,"No response from server for %d seconds, reconnect immediately...\n", (phglobal->nUserType == 1 ? 160 : 320));
			set_persistent_ip(phglobal->persist_cmd, "0.0.0.0", ORAY_CON_FAIL);
/* Netgear end */ 
			phglobal->bTcpUpdateSuccessed = FALSE;
			phglobal->bNeed_connect = TRUE;
			return 1;
		}
	}
	return 1;
}

void phddns_stop(PHGlobal *phglobal)
{
	SendKeepAlive(phglobal, UDP_OPCODE_LOGOUT);
	phglobal->tmLastSend = time(0);
	sleep(1); //ensure data sent
	DestroySockets(phglobal);
}
