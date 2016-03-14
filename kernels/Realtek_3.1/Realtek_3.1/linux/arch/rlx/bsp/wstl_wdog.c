/*
 ********************************************************************************
 *
 * Copyright 2007 Westell, Inc.  All rights reserved.
 *
 * FILE NAME:            wstl_wdog.c
 *
 * DESCRIPTION:          Keep the watchdog happy long enough to boot
 *
 ********************************************************************************
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <bcm_map_part.h>
#include <bcm_hwdefs.h>

/* Possible types of Watchdog
 */
#define BCM6348_INTERNAL 1
#define BCM6348_GPIO16 2
#define BCM6348_GPIO3 3

/* Pick one of the above for the target board
 */
#define BOARD_WATCHDOG_METHOD BCM6348_INTERNAL

extern void kerSysSetWdTimer(ulong);

void WstlKickDog(void)
{
	/* If this routine is called that means the bootloader started kicking the dog
	 * Therefore will assume everything is setup and only need to perform the kick action
	 * normally would have to protect the xor of the GPIO bit but at this point nothing
	 * else is running that would prempt or interrupt this operation
	 */

#if (BOARD_WATCHDOG_METHOD == BCM6348_INTERNAL)
	/* printk("%s: Kicking the dog INTERNAL\n", __FUNCTION__); */
	kerSysSetWdTimer(0x7fffffff);
#elif (BOARD_WATCHDOG_METHOD == BCM6348_GPIO16)
    {
	unsigned long gpiobit = 0x00010000;
	unsigned long gpiovalue;
	/* printk("%s: Kicking the dog GPIO16\n", __FUNCTION__); */
	gpiovalue = GPIO->GPIOio;
	if (gpiovalue & gpiobit)
		gpiovalue &= ~gpiobit;
	else
		gpiovalue |= gpiobit;
	GPIO->GPIOio = gpiovalue;
    }
#elif (BOARD_WATCHDOG_METHOD == BCM6348_GPIO3)
    {
	unsigned long gpiobit = 0x00000008;
	unsigned long gpiovalue;
	/* printk("%s: Kicking the dog GPIO3\n", __FUNCTION__); */
	gpiovalue = GPIO->GPIOio;
	if (gpiovalue & gpiobit)
		gpiovalue &= ~gpiobit;
	else
		gpiovalue |= gpiobit;
	GPIO->GPIOio = gpiovalue;
    }
#endif
}

void kerSysSetWdTimerInterval(ulong image)
{
	TIMER->WatchDogDefCount = image;
}

ulong kerSysGetWdTimerInterval(void)
{
	return ((ulong) (TIMER->WatchDogDefCount));
}

void kerSysDisableWdTimer(void)
{
	TIMER->WatchDogCtl = 0xEE00;
	TIMER->WatchDogCtl = 0x00EE;
}

void kerSysSetWdTimer(ulong timeUs)
{
	TIMER->WatchDogDefCount = timeUs * (FPERIPH/1000000);
	TIMER->WatchDogCtl = 0xFF00;
	TIMER->WatchDogCtl = 0x00FF;
}

EXPORT_SYMBOL(kerSysSetWdTimer);
EXPORT_SYMBOL(kerSysDisableWdTimer);
EXPORT_SYMBOL(kerSysGetWdTimerInterval);
EXPORT_SYMBOL(kerSysSetWdTimerInterval);
