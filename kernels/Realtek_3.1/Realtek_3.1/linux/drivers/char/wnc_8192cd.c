
//WNC_JH


#include "../net/wireless/rtl8192cd/8192c_reg.h"
#include "../net/wireless/rtl8192cd/8192d_reg.h"
#include "../net/wireless/rtl8192cd/8192cd.h"
#include "../net/wireless/rtl8192cd/8192cd_cfg.h"
#include "../net/wireless/rtl8192cd/8192cd_util.h"


extern struct rtl8192cd_priv * g_rtl8192cd_priv;

void WNC_8192CE_gpio10_input_init(void)
{
	int iValue = 0;

	struct rtl8192cd_priv *priv = g_rtl8192cd_priv;

	if(NULL == g_rtl8192cd_priv)	return;

	//set 8192CE GPIO10 to gpio input mode
	iValue =(RTL_R32(GPIO_MUXCFG) & 0xEBffffff);//bit 28,26 to 0

	RTL_W32(GPIO_MUXCFG, iValue);
}

void WNC_8192CE_gpio5_output_init(void)
{
	int iValue = 0;

	struct rtl8192cd_priv *priv = g_rtl8192cd_priv;

	if(NULL == g_rtl8192cd_priv)	return;

	//set 8192CE GPIO5 to gpio output mode
	iValue =(RTL_R32(GPIO_PIN_CTRL) & 0xdfffffff) | (1<<21);//bit 29 to 0, 21 to 1

	RTL_W32(GPIO_PIN_CTRL, iValue);
}

void WNC_8192CE_gpio5_off(void)
{
	int iValue = 0;

	struct rtl8192cd_priv *priv = g_rtl8192cd_priv;

	if(NULL == g_rtl8192cd_priv)	return;

	//set 8192CE GPIO5 to led off
	iValue = RTL_R32(GPIO_PIN_CTRL) | (1<<13);

	RTL_W32(GPIO_PIN_CTRL, iValue);
}

void WNC_8192CE_gpio5_on(void)
{

	int iValue = 0;

	struct rtl8192cd_priv *priv = g_rtl8192cd_priv;

	if(NULL == g_rtl8192cd_priv)	return;

	iValue = RTL_R32(GPIO_PIN_CTRL);

	//set 8192CE GPIO5 to led on
	iValue = iValue & 0xffffdfff;//bit 13 to 0
	//iValue = iValue & !((1<<13) & 0xffffffff); //special note:when use shift to do &, will cause wrong value

	RTL_W32(GPIO_PIN_CTRL, iValue);
}
int WNC_8192CE_read_gpio10_input(void)
{
	int iValue = 0;

	struct rtl8192cd_priv *priv = g_rtl8192cd_priv;

	if(NULL == g_rtl8192cd_priv)	return;
        iValue = (RTL_R32(GPIO_MUXCFG) & (1 << 18));//Reading 18th bit for gpio10 value; gpio_in[11:8]----[19:16]
	//set 8192CE GPIO10 to gpio input mode
	return iValue;
	
}


//----------------------------------------------------------------------
EXPORT_SYMBOL(WNC_8192CE_gpio10_input_init);
EXPORT_SYMBOL(WNC_8192CE_gpio5_output_init);
EXPORT_SYMBOL(WNC_8192CE_gpio5_off);
EXPORT_SYMBOL(WNC_8192CE_gpio5_on);
EXPORT_SYMBOL(WNC_8192CE_read_gpio10_input);
