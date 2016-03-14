/*
 ********************************************************************************
 *
 * Copyright 2007 Westell, Inc.  All rights reserved.
 *
 * FILE NAME:            wstl_cmdline.c
 *
 * DESCRIPTION:          Create/use command line passed into kernel by
 *                       the Westell bootloader.
 *
 ********************************************************************************
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/bootinfo.h>

/*
 * Westell bootload commandline
 */
int prom_argc;
int *_prom_argv;
int *_prom_envp;
#define prom_envp(index) ((char *)(long)_prom_envp[(index)])
#define prom_argv(index) ((char *)(long)_prom_argv[(index)])

#ifdef CONFIG_RAM_ROOTFS
char *RAMrootfs;
unsigned int RAMrootfs_sz;
EXPORT_SYMBOL(RAMrootfs);
EXPORT_SYMBOL(RAMrootfs_sz);
extern int WSTL_find_rootfs(void);
#endif

void  __init prom_init_cmdline(int arg0, int *arg1, int *arg2)
{
    char *cp;
    int i = 0;

    prom_argc = arg0;
    _prom_argv = arg1;
    _prom_envp = arg2;
    printk("in wstlcmdline\n");
    /* Copy what the bootloader passed to us into the kernel command line
     */
    cp = &(arcs_cmdline[0]);

#ifdef CONFIG_WSTL_FLASH
    /* Hard-code the flash block that holds the root filesystem
     */
 #ifdef CONFIG_RAM_ROOTFS
    if (WSTL_find_rootfs() == 0)
    	strcpy(cp, " console=ttyS0,115200 root=/dev/mtdblock4 ro bootmode=ftm init=/sbin/init "); /* boot straight to FTM */
    else
 #endif
    strcpy(cp, " console=ttyS0,115200 root=/dev/mtdblock1 ro init=/sbin/init ");
    cp += strlen(cp);
#endif
    
	while (prom_envp(i)) {
		if(*(prom_envp(i))) /* check for non-NULL env name str */
		{
#ifdef CONFIG_RAM_ROOTFS
			if (RAMrootfs_sz && (strcmp(prom_envp(i), "bootmode") == 0))
			{
				printk("skip bootmode=%s\n", prom_envp(i+1)); /* ignore the bootloaders bootmode */
				i += 2;
				continue;
			}
#endif /* CONFIG_RAM_ROOTFS */
			*cp++ = ' ';
			strcpy(cp, prom_envp(i));
			cp += strlen(prom_envp(i));
			*cp++ = '=';
			strcpy(cp, prom_envp(i + 1));
			cp += strlen(prom_envp(i + 1));
		}
		i += 2;
	}
    *cp = '\0';
printk("arcs_cmdline = %s\n", arcs_cmdline);
}

char * __init prom_getcmdline(void)
{
    return &(arcs_cmdline[0]);
}

char *prom_getenv(char *envname)
{
	/*
     * Return a pointer to the given environment variable.
     * In 64-bit mode: we're using 64-bit pointers, but all pointers
     * in the PROM structures are only 32-bit, so we need some
     * workarounds, if we are running in 64-bit mode.
     */
	int i, index=0;

	i = strlen(envname);

	while (prom_envp(index)) {
		if(strncmp(envname, prom_envp(index), i) == 0) {
			return(prom_envp(index+1));
		}
		index += 2;
	}
	
	return NULL;
}

unsigned int getNumberofFlashBanks(void)
{
    char *str;
    unsigned int uiBanks;

    str = prom_getenv("flashsize");
    if ( !str )
    {
        printk("flashsize not set in boot prom, set default banks to 1\n");
        uiBanks = 1;
    }
    else
    {
        uiBanks = simple_strtol(str, NULL, 0) & 0x0f;
        if (uiBanks == 0)
        {
            uiBanks = 1;
        }
    }
    return(uiBanks);
}

int getWatchdogState(void)
{
	char *wdog_str;
	int state;

	wdog_str = prom_getenv("wdog");
	if (!wdog_str) {
		printk("No Watchdog State from bootloader defaulting to OFF\n");
		state = 0;
	} else {
		if (!strcmp(wdog_str, "on")) {
			printk("Bootloader Watchdog State ON\n");
			state = 1;
		}
		else {
			state = 0;
		}
	}
	return (state);
}

static inline unsigned char str2hexnum(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return 0; /* foo */
}

static inline void str2eaddr(unsigned char *ea, unsigned char *str)
{
	int i;

	for (i = 0; i < 6; i++) {
		unsigned char num;

		if((*str == '.') || (*str == ':'))
			str++;
		num = str2hexnum(*str++) << 4;
		num |= (str2hexnum(*str++));
		ea[i] = num;
	}
}


unsigned long getMemorySize(void)
{
        char *memsize_str;
        unsigned long memsize;

        memsize_str = prom_getenv("memsize");
        if (!memsize_str) {
                printk("memsize not set in boot prom, set to default (16Mb)\n");
                memsize = 0x01000000;
        } else {
                memsize = simple_strtol(memsize_str, NULL, 0);
        }
    return (memsize);
}




int get_ethernet_addr(char *ethernet_addr)
{
	char *ethaddr_str;

	ethaddr_str = prom_getenv("ethaddr");
	if (!ethaddr_str) {
		printk("ethaddr not set in boot prom\n");
		return -1;
	}
	str2eaddr(ethernet_addr, ethaddr_str);

	if (1) {
		int i;
		printk("get_ethernet_addr: ");
		for (i=0; i<5; i++)
			printk("%02x:", (unsigned char)*(ethernet_addr+i));
		printk("%02x\n", (unsigned char)*(ethernet_addr+i));
	}

	return 0;
}

