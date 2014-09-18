/*
aprocdump - Android Process Dumper
Copyright (C) 2014  George Nicolaou (george({at})silensec({dot})com)

This file is part of (aprocdump) Android Process Dumper.

aprocdump is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

aprocdump is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with aprocdump.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef APROCDUMP_H_
#define APROCDUMP_H_

#define PROC_PATH_SIZE 256
#define DEFAULT_CHUNK_SIZE 4096

typedef enum usage_type { USAGE_TITLE=0, USAGE_OPTION=1 } usage_type_t;

typedef struct usage {
	enum usage_type type;
	char * str;
	int options_ptr;
} usage_t;

typedef enum perm_flags {
	//Used internally
	PERM_READ =		0x0001,
	PERM_WRITE =	0x0002,
	PERM_EXEC =		0x0004,
	PERM_PRIV = 	0x0008,
	PERM_SHR =		0x0010,

	READ_ANY =	0x0001,
	WRITE_ANY =	0x0002,
	EXEC_ANY =	0x0004,
	PRIV_ANY = 	0x0008,
	SHR_ANY =	0x0010,

	READ_MUST = 	0x0020,
	WRITE_MUST =	0x0040,
	EXEC_MUST =		0x0080,
	PRIV_MUST =		0x0100,
	SHR_MUST =		0x0200,

	READ_NOT =	0x0400,
	WRITE_NOT =	0x0800,
	EXEC_NOT =	0x1000,
	PRIV_NOT =	0x2000,
	SHR_NOT =	0x4000
} perm_flags_t;

#define MUST_MASK 0x3E0

typedef int ( write_function_t )( unsigned char *, int );
typedef void ( close_function_t )( void );

typedef struct _writer_t {
	int bytes_written;
	write_function_t * mywrite;
} writer_t;

typedef struct procdump_opts {
	char * output_file;
	char * tcp_host;
	int tcp_port;
	int verbose;
	char ** modules;
	short permissions; // 16 bits - [rwxp/s][rwxp/s][rwxp/s]
	long chunk_size;
	off64_t addr_start;
	off64_t addr_end;
	write_function_t * writer;
	close_function_t * close;
} procdump_opts_t;

#define PERM_ANY 0
#define PERM_MUST 5
#define PERM_NOT 10

#define dprint( flag, str, ... ) \
	if( flag ) { \
		printf( "DEBUG:" str "\n", ##__VA_ARGS__ ); \
	}

extern int tcp_write( char * data, int len );
extern int tcp_setup( char * host, int port );
extern int file_write( char * data, int len );
extern int file_setup( char * filepath );
extern int stdout_write( char * data, int len );
extern void tcp_close();
extern void file_close();
#endif /* APROCDUMP_H_ */
