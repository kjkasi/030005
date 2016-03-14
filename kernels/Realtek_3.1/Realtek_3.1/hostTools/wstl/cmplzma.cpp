/*
<:copyright-broadcom 
 
 Copyright (c) 2002 Broadcom Corporation 
 All Rights Reserved 
 No portions of this material may be reproduced in any form without the 
 written permission of: 
          Broadcom Corporation 
          16215 Alton Parkway 
          Irvine, California 92619 
 All information contained in this document is Broadcom Corporation 
 company private, proprietary, and trade secret. 
 
:>
*/

/* Copyright (c) 2006 Westell, Inc. - all rights reserved */

/***************************************************************************
 * File Name  : cmplzma.c
 *
 * Description: Reads information from ELF kernel, and prepends bootloader
 *              header to an (already) lzma compressed binary kernel file.
 *
 * Updates    : 04/2006 - ewind@westell.com 
 *                    - modified to work with standalong lzma encoder
 *                    - dumped unused brcm features
 *
 ***************************************************************************/

/* Includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

// elf structs and defines from CFE

/* p_type */
#define	PT_NULL		0		/* Program header table entry unused */
#define PT_LOAD		1		/* Loadable program segment */
#define PT_DYNAMIC	2		/* Dynamic linking information */
#define PT_INTERP	3		/* Program interpreter */
#define PT_NOTE		4		/* Auxiliary information */
#define PT_SHLIB	5		/* Reserved, unspecified semantics */
#define PT_PHDR		6		/* Entry for header table itself */
#define PT_LOPROC	0x70000000	/* Processor-specific */
#define PT_HIPROC	0x7FFFFFFF	/* Processor-specific */

#define CFE_ERR_NOTELF		-11
#define CFE_ERR_NOT32BIT 	-12
#define CFE_ERR_WRONGENDIAN -13
#define CFE_ERR_BADELFVERS 	-14
#define CFE_ERR_NOTMIPS 	-15
#define CFE_ERR_BADELFFMT 	-16
#define CFE_ERR_BADADDR 	-17

/* e_indent */
#define EI_MAG0		 0		/* File identification byte 0 index */
#define EI_MAG1		 1		/* File identification byte 1 index */
#define EI_MAG2		 2		/* File identification byte 2 index */
#define EI_MAG3		 3		/* File identification byte 3 index */
#define EI_CLASS	 4		/* File class */

#define ELFCLASSNONE 0		 /* Invalid class */
#define ELFCLASS32	 1		 /* 32-bit objects */
#define ELFCLASS64	 2		 /* 64-bit objects */
#define EI_DATA		 5		/* Data encoding */

#define ELFDATANONE	 0		 /* Invalid data encoding */
#define ELFDATA2LSB	 1		 /* 2's complement, little endian */
#define ELFDATA2MSB	 2		 /* 2's complement, big endian */
#define EI_VERSION	 6		/* File version */
#define EI_PAD		 7		/* Start of padding bytes */

#define ELFMAG0		0x7F	/* Magic number byte 0 */
#define ELFMAG1		'E'		/* Magic number byte 1 */
#define ELFMAG2		'L'		/* Magic number byte 2 */
#define ELFMAG3		'F'		/* Magic number byte 3 */

typedef unsigned short	Elf32_Half;
typedef unsigned int	Elf32_Word;
typedef signed int	Elf32_Sword;
typedef unsigned int	Elf32_Off;
typedef unsigned int	Elf32_Addr;
typedef unsigned char	Elf_Char;
/*
 * ELF File Header 
 */
#define EI_NIDENT	16
typedef struct {
    Elf_Char	e_ident[EI_NIDENT];
    Elf32_Half	e_type;
    Elf32_Half	e_machine;
    Elf32_Word	e_version;
    Elf32_Addr	e_entry;
    Elf32_Off	e_phoff;
    Elf32_Off	e_shoff;
    Elf32_Word	e_flags;
    Elf32_Half	e_ehsize;
    Elf32_Half	e_phentsize;
    Elf32_Half	e_phnum;
    Elf32_Half	e_shentsize;
    Elf32_Half	e_shnum;
    Elf32_Half	e_shstrndx;
} Elf32_Ehdr;

/*
 * Program Header 
 */
typedef struct {
  Elf32_Word	p_type;			/* Identifies program segment type */
  Elf32_Off	    p_offset;		/* Segment file offset */
  Elf32_Addr	p_vaddr;		/* Segment virtual address */
  Elf32_Addr	p_paddr;		/* Segment physical address */
  Elf32_Word	p_filesz;		/* Segment size in file */
  Elf32_Word	p_memsz;		/* Segment size in memory */
  Elf32_Word	p_flags;		/* Segment flags */
  Elf32_Word	p_align;		/* Segment alignment, file & memory */
} Elf32_Phdr;

/***************************************************
 * Check the elf file validity and extract 
 * the program entry and text start address
 ***************************************************/
int getElfInfo(char *elfFile, Elf32_Addr *eEntry, Elf32_Addr *pVaddr)
{
    Elf32_Ehdr *ep;
    Elf32_Phdr *phtab = 0;
    unsigned int nbytes;
    int i;
    Elf32_Ehdr ehdr;
    FILE *hInput;

    if ((hInput = fopen(elfFile, "rb")) == NULL)
    {
        printf("Error open file: %s\n", elfFile);
        return -1;
    }

    if (fread((char *) &ehdr, sizeof(char), sizeof(ehdr), hInput) != sizeof(ehdr))
    {
        printf("Error reading file: %s\n", elfFile);
        return -1;
	}

    ep = &ehdr;

    *eEntry = ep->e_entry;

    /* check header validity */
    if (ep->e_ident[EI_MAG0] != ELFMAG0 ||
        ep->e_ident[EI_MAG1] != ELFMAG1 ||
	    ep->e_ident[EI_MAG2] != ELFMAG2 ||
	    ep->e_ident[EI_MAG3] != ELFMAG3) 
    {
        printf("Not ELF file\n");
	    return CFE_ERR_NOTELF;
	}

    if (ep->e_ident[EI_CLASS] != ELFCLASS32) 
    {
        printf("Not 32 bit elf\n");
        return CFE_ERR_NOT32BIT;
    }
    
#ifdef B_ENDIAN
    if (ep->e_ident[EI_DATA] != ELFDATA2MSB) 
#else
    if (ep->e_ident[EI_DATA] != ELFDATA2LSB) 
#endif
    {
        printf("Wrong endian\n");
        return CFE_ERR_WRONGENDIAN;
    }

    /* Is there a program header? */
    if (ep->e_phoff == 0 || ep->e_phnum == 0)
    {
        printf("No program header? Wrong elf file\n");
	    return CFE_ERR_BADELFFMT;
	}

    /* Load program header */
#ifdef B_ENDIAN
    ep->e_phnum = htons(ep->e_phnum);
    ep->e_phoff = htonl(ep->e_phoff);
#endif
    nbytes = ep->e_phnum * sizeof(Elf32_Phdr);
    phtab = (Elf32_Phdr *) malloc(nbytes);
    if (!phtab) 
    {
	    printf("Failed to malloc memory!\n");
        return -1;
	}

    if (fseek(hInput, ep->e_phoff, SEEK_SET)!= 0)
    {
	    free(phtab);
        printf("File seek error\n");
	    return -1;
	}
    if (fread((unsigned char *)phtab, sizeof(char), nbytes, hInput) != nbytes)
    {
	    free(phtab);
        printf("File read error\n");
	    return -1;
	}

	for (i = 0; i < ep->e_phnum; i++)
    {
	    Elf32_Off lowest_offset = ~0;
	    Elf32_Phdr *ph = 0;
        ph = &phtab[i];
#ifdef B_ENDIAN
        phtab[i].p_offset = htonl(phtab[i].p_offset);
        phtab[i].p_type = htonl(phtab[i].p_type);
#endif
	    if ((phtab[i].p_type == PT_LOAD) && (phtab[i].p_offset < lowest_offset)) 
        {
	        ph = &phtab[i];
	        lowest_offset = ph->p_offset;
            *pVaddr = ph->p_vaddr;      // found the text start address
            return 0;
	    }
    }
    printf("No text start address found! Wrong elf file ?\n");
    return -1;
}

/*************************************************************
 * Function Name: main
 ************************************************************/
int main (int argc, char **argv)
{
    FILE *hInput = NULL, *hOutput = NULL;
    struct stat StatBuf;
    char *inputElfFile = NULL, *inputLZFile = NULL, *outputFile = NULL;
    unsigned int lzlen = 0, swappedlen;
    unsigned char *lzdata = NULL;
    Elf32_Addr entryPoint;
    Elf32_Addr textAddr;
	int retval = -1;

    if (argc != 4)
	{
		fprintf(stderr, "Usage: %s vmlinux vmlinux.lz vmlinux.pkg\n", argv[0]);
		return -1;
	}

	inputElfFile = argv[1];
    inputLZFile = argv[2];
    outputFile = argv[3];

    if (getElfInfo(inputElfFile, &entryPoint, &textAddr) != 0)
        return -1;

    printf("Code text starts: textAddr=0x%08X  Program entry point: 0x%08X,\n", 
#ifdef B_ENDIAN
        (unsigned int)(htonl(textAddr)), (unsigned int)(htonl(entryPoint)));
#else
        (unsigned int)(textAddr), (unsigned int)(entryPoint));
#endif

	/* Open input file */
    if ((stat(inputLZFile, &StatBuf ) != 0) || (hInput = fopen(inputLZFile, "rb" )) == NULL)
    {
        printf( "Error opening input file %s.\n\n", inputLZFile);
		goto out;
    }

    /* Open output file. */
    if ((hOutput = fopen(outputFile, "w+" )) == NULL)
    {
        printf ("Error opening output file %s.\n\n", outputFile);
		goto out;
    }

    lzlen = StatBuf.st_size;
    lzdata = (unsigned char *) malloc(lzlen);

    if (!lzdata)
    {
        printf("Memory allocation error\n");
		goto out;
    }

    if (fread(lzdata, sizeof(char), lzlen, hInput) != lzlen)
    {
        printf( "Error read input file %s.\n\n", inputLZFile);
		goto out;
    }


	/* lzma puts in an 8-byte length header that our bootloader
	 * doesn't want to see.
	 */
	lzlen -= 8;

	/* Write our header:
	 *  1. text address (address in RAM to place decompressed blob)
	 *  2. entry point  (address to jump to after decompressing)
	 *  3. length       (size of compressed data)
	 */
#ifdef B_ENDIAN
        swappedlen = htonl(lzlen);
#else
        swappedlen = lzlen;
#endif
	if (fwrite(&textAddr, sizeof(Elf32_Addr), 1, hOutput) != 1 || 
		fwrite(&entryPoint, sizeof(Elf32_Addr), 1, hOutput) != 1 || 
		fwrite(&swappedlen, sizeof(swappedlen), 1, hOutput) != 1)
	{
		printf( "Error writing output header.\n\n" );
		goto out;
	}

	/* Write 5 bytes, skip 8 (unwanted length header), write rest */
	if ((fwrite(lzdata, sizeof(char), 5, hOutput) != 5) ||
		(fwrite(lzdata + 8 + 5, sizeof(char), lzlen - 5, hOutput) != lzlen - 5))
	{
		printf( "Error writing output data.\n\n" );
		goto out;
	}

	retval = 0;

  out:
	if (lzdata) free(lzdata);
	if (hInput) fclose(hInput);
    if (hOutput) fclose(hOutput);
    return(0);
}


