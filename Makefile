# Example makefile for CPE464 program 1
#
#  Remember to add /opt/csw/lib to your path in order to execute your program
#  under Solaris.  Putting something like:
#     [ -e "/opt/csw/lib" ] && export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/csw/lib
#  in your ~/.mybashrc file should do the trick

CC = gcc
CFLAGS = -g -Wall -Werror
OS =Linux

all: trace

trace: trace.c main.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -lpcap -o $@ trace.c checksum.c main.c

clean:
	rm -f *~
