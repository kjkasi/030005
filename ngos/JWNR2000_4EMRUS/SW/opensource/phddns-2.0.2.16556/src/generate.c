/*
 * This file has Netgear changes. Inorder to produce correct Crypt(which is treaed as correct by server) 
 * byte swap changes are done.
 */

#include <stdio.h> 
#include <memory.h>
#include "md5.h"
#include "generate.h"
#include "lutil.h"

/* Netgear start */ 
#if __BYTE_ORDER == __BIG_ENDIAN
inline unsigned int LongSwap (unsigned int i)
{
  unsigned char b1, b2, b3, b4;

  b1 = i & 0xff;
  b2 = ( i >> 8 ) & 0xff;
  b3 = ( i>>16 ) & 0xff;
  b4 = ( i>>24 ) & 0xff;

  return ((unsigned int)b1 << 24) + ((unsigned int)b2 << 16) + ((unsigned int)b3 << 8) + b4;
}
#endif
/* Netgear end */

//__stdcall
int GenerateCrypt(char *szUser, 
							 char *szPassword, 
							 char *szChallenge64, 
                                                         long clientinfo,
                                                         long embkey,
							 char *szResult)
{
	unsigned char szDecoded[256];
	unsigned char szKey[256];
	unsigned char szAscii[256];

	unsigned int nDecodedLen;
	long challengetime = 0;
	int nMoveBits;
	long challengetime_new = 0;
	long a, b, c, d;
	unsigned int nKey;
	int nUser;
	unsigned int nEncoded;

	//Base64 解码
	nDecodedLen =  lutil_b64_pton(szChallenge64, szDecoded, 256);
	memcpy(&challengetime, szDecoded + 6, 4);
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        challengetime = LongSwap(challengetime);
#endif
/* Netgear end */	
	//取反进行或运算
	challengetime |= ~embkey;

	//得到循环移位位数
	nMoveBits = challengetime % 30;
	//完成32位的循环位移
	a = challengetime << ((32 - nMoveBits) % 32);
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        a = LongSwap(a);
#endif
/* Netgear end */
	b = challengetime >> (((unsigned int )nMoveBits) % 32);
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        b = LongSwap(b);
#endif
/* Netgear end */
	c = ~(0xffffffff << ((32 - nMoveBits) % 32));
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        c = LongSwap(c);
#endif
/* Netgear end */
	d = b & c;
	challengetime_new = a | d;

	//KEY-MD5
	nKey = KeyMD5Encode(szKey, (unsigned char*)szPassword, strlen((char*)szPassword), (unsigned char*)szDecoded, nDecodedLen);
	szKey[nKey] = 0;
	
	nUser = strlen((char *)szUser);
	memcpy(szAscii, szUser, nUser);
	szAscii[nUser] = ' ';
	memcpy(szAscii+nUser+1, &challengetime_new,4);
/* Netgear start */
#if __BYTE_ORDER == __BIG_ENDIAN
        clientinfo = LongSwap(clientinfo);
#endif
/* Netgear end */
	memcpy(szAscii+nUser+1+4,&clientinfo,4);
	memcpy(szAscii+nUser+1+4+4, szKey, nKey);
	//base64 编码
	nEncoded =  lutil_b64_ntop((unsigned char *)szAscii, nUser + 1 + 4 + 4 + nKey, szResult, 256);
	return nEncoded;
}
