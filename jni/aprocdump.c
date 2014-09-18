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
#define _LARGEFILE64_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>

#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include "aprocdump.h"



static char glob_buf[4096];

static const char * opt_string = "o:i:p:vhs:lm:f:";

const struct option opts[] = {
		{ "output-file",	1, 0, 'o' 	},
		{ "tcp-host",		1, 0, 'i' 	},
		{ "tcp-port",		1, 0, 'p' 	},
		{ "verbose",		0, 0, 'v' 	},
		{ "help",			0, 0, 'h' 	},
		{ "chunk-size",		1, 0, 's' 	},
		{ "list-maps",		0, 0, 'l'	},
		{ "module",			1, 0, 'm'	},
		{ "permissions",	1, 0, 'f'	},
		{ "region-start",	1, 0, 1 	},
		{ "region-end",		1, 0, 2 	},

};

static const struct usage usage_options[] = {
		{ USAGE_TITLE, "General Options:" },
		{ USAGE_OPTION, "Output to file (default stdout)", 0 },
		{ USAGE_OPTION, "Output to listening host", 1 },
		{ USAGE_OPTION, "Listening host TCP port", 2 },
		{ USAGE_OPTION, "Verbose", 3 },
		{ USAGE_OPTION, "This help text", 4 },
		{ USAGE_TITLE, "Miscellaneous Options:" },
		{ USAGE_OPTION,"Limit memory read chunk size to minimize footprints "
						"*(N/A)",5},
		{ USAGE_OPTION, "List process maps (/proc/x/maps file)", 6 },
		{ USAGE_TITLE, "Filtering options:" },
		{ USAGE_OPTION, "Dump only specified module(s) comma separated: "
							"eg: module1,module2", 7 },
		{ USAGE_OPTION, "Filter based on permissions (rwxp/s):\n "
							"\t\t\tOptions: [any]+[must have]-[must not have]\n"
							"\t\t\t\tExample: r+wp-x\n"
							"\t\t\t\tExplanation:\n"
							"\t\t\t\t 1. Can have read permissions\n"
							"\t\t\t\t 2. Must have write permissions and "
								"be privately allocated\n"
							"\t\t\t\t 3. Must not have execute permissions", 8
		},
		{ USAGE_OPTION, "Dump from address start point (rounded down)", 9 },
		{ USAGE_OPTION, "Dump to address end point (rounded up)", 10 },
};

int usage( char * filename ) {
	int i;
	printf( "Android Process Memory Dumper\nUsage: %s [OPTIONS] pid [pid ...]\n",
			filename );
	printf( "Author: George Nicolaou (george[at]silensec[dot]com)\n" );
	for( i = 0; i < sizeof( usage_options ) / sizeof( struct usage ); i++ ) {
		if( usage_options[i].type == USAGE_TITLE ) {
			printf( "%s\n", usage_options[i].str );
		}
		else if( usage_options[i].type == USAGE_OPTION ) {
			if( opts[usage_options[i].options_ptr].val > 10 ) {
				printf( " -%c, --%s\t%s\n",
					opts[usage_options[i].options_ptr].val,
					opts[usage_options[i].options_ptr].name,
					usage_options[i].str );
			}
			else {
				printf( " --%s\t%s\n", opts[usage_options[i].options_ptr].name,
					usage_options[i].str );
			}
		}
	}
	return EXIT_SUCCESS;
}

static struct procdump_opts pd_options = {0};

int dump_memory(int fd, off64_t start, off64_t end)
{
	char buf[4096];
	int bread;
	/*
	if( pd_options.chunk_size != (long)NULL ) {
		if( ( buf = malloc( pd_options.chunk_size ) ) == NULL ) {
			fprintf( stderr, "Memory allocation error" );
			return 0;
		}
		bufsize = pd_options.chunk_size;
	}
	else {
		buf = glob_buf;
		bufsize = sizeof( glob_buf );
	}
	*/
	lseek64( fd, start, SEEK_SET );
	while( start < end ) {
		bread = read( fd, buf, sizeof(buf) );
		if( bread == -1 ) {
			perror(NULL);
			return 0;
		}
		if( pd_options.writer( buf, bread ) == 0 ) {
			fprintf( stderr, "Error writing to file\n" );
			return 0;
		}
		start += sizeof(buf);
	}
	return 1;
}

int print_map_listing( int pid )
{
	FILE * fmaps;
	char path[PROC_PATH_SIZE] = {0};
	char chunk[256] = {0};
	size_t read;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	if( ( fmaps = fopen( path, "r" ) ) == 0 ) {
		fprintf( stderr, "Could not open maps file: %s", path );
		return EXIT_FAILURE;
	}
	while( ( read = fread( chunk, 1, sizeof( chunk ), fmaps ) ) > 0 ) {
		fwrite( chunk, 1, read, stdout );
	}
	fclose( fmaps );
	return EXIT_SUCCESS;
}

int apply_filter( off64_t start, off64_t end, char * filepath )
{
	char ** modules;

	if( pd_options.addr_start != 0 ) {
		if( start < pd_options.addr_start )
			return 0;
	}

	if( pd_options.addr_end != 0 ) {
		if( end > pd_options.addr_end )
			return 0;
	}

	if( pd_options.modules != NULL ) {
		modules = pd_options.modules;
		while( *modules ) {
			if( strstr( filepath, *modules ) != NULL ) {
				return 1;
			}
			modules++;
		}
		return 0;
	}
	return 1;
}

unsigned long check_perm( char * perm )
{

	if( strrchr( perm, 'r' ) == NULL ) {
		dprint( pd_options.verbose, "Skipping module with no read perm" );
		return 0;
	}

	if( pd_options.permissions == 0 ) {
		return 1;
	}

	short local_permissions = pd_options.permissions & MUST_MASK;
	while( *perm ) {
		switch( *perm ) {
			case 'r':
				if( pd_options.permissions & READ_NOT )
					return 0;
				if( ( pd_options.permissions & READ_MUST ) == 0 ) {
					if( ( pd_options.permissions & READ_ANY ) == 0 )
						return 0;
				}
				local_permissions &= ~READ_MUST;
				break;
			case 'w':
				if( pd_options.permissions & WRITE_NOT )
					return 0;
				if( ( pd_options.permissions & WRITE_MUST ) == 0 ) {
					if( ( pd_options.permissions & WRITE_ANY ) == 0 )
						return 0;
				}
				local_permissions &= ~WRITE_MUST;
				break;
			case 'x':
				if( pd_options.permissions & EXEC_NOT )
					return 0;
				if( ( pd_options.permissions & EXEC_MUST ) == 0 ) {
					if( ( pd_options.permissions & EXEC_ANY ) == 0 )
						return 0;
				}
				local_permissions &= ~EXEC_MUST;
				break;
			case 'p':
				if( pd_options.permissions & PRIV_NOT )
					return 0;
				if( ( pd_options.permissions & PRIV_MUST ) == 0 ) {
					if( ( pd_options.permissions & PRIV_ANY ) == 0 )
						return 0;
				}
				local_permissions &= ~PRIV_MUST;
				break;
			case 's':
				if( pd_options.permissions & SHR_NOT )
					return 0;
				if( ( pd_options.permissions & SHR_MUST ) == 0 ) {
					if( ( pd_options.permissions & SHR_ANY ) == 0 )
						return 0;
				}
				local_permissions &= ~SHR_MUST;
				break;
		}
		perm++;
	}
	if( local_permissions )
		return 0;
	else
		return 1;
}

int process_pid( pid_t pid )
{
	char path[PROC_PATH_SIZE];
	FILE *fmaps;
	int fmem;

	dprint( pd_options.verbose, "Processing %d", pid );
	if( ptrace( PTRACE_ATTACH, pid, NULL, NULL ) == -1 ) {
		perror(NULL);
		return EXIT_FAILURE;
	}
	dprint( pd_options.verbose, "Reading /proc/%d/maps", pid );
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	if( ( fmaps = fopen(path, "r") ) == NULL ) {
		perror(NULL);
		ptrace( PTRACE_DETACH, pid, NULL, NULL );
		return EXIT_FAILURE;
	}
	dprint( pd_options.verbose, "Opening stream to /proc/%d/mem", pid );
	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	if( ( fmem = open(path, O_RDONLY) ) == 0 ) {
		ptrace( PTRACE_DETACH, pid, NULL, NULL );
		fclose( fmaps );
		perror(NULL);
		return EXIT_FAILURE;
	}

	char buf[BUFSIZ + 1];

	dprint( pd_options.verbose, "Scanning modules");
	while(fgets(buf, BUFSIZ, fmaps)) {
		off64_t start, end, offset;
		char perm[5] = {0}, file_path[PROC_PATH_SIZE] = {0};
		unsigned int dev_maj=0, dev_min=0;
		int inode=0;
		sscanf(buf, "%llx-%llx %4s %llx %x:%x %d %255s", &start, &end, perm,
				&offset, &dev_maj, &dev_min, &inode, file_path );

		if( check_perm( perm ) && apply_filter( start, end, file_path ) ) {
			dprint( pd_options.verbose, "Dumping module: %llx - %llx %s", start,
					end, file_path );
			if( dump_memory(fmem, start, end) == 0 ) {
				fprintf( stderr, "Error dumping memory\n" );
				ptrace( PTRACE_DETACH, pid, NULL, NULL );
				close( fmem );
				fclose( fmaps );
				return EXIT_FAILURE;
			}
		}
	}
	dprint( pd_options.verbose, "Detaching from target" );
	close( fmem );
	fclose( fmaps );
	ptrace( PTRACE_DETACH, pid, NULL, NULL );
	if( pd_options.close != NULL )
		pd_options.close();
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	int c, i, cnt, list_maps = 0, perm_state = PERM_ANY;
	pid_t pid;

	char * tmp_str = NULL;

	if(argc < 2) {
		return usage( argv[0] );
	}

	while( ( c = getopt_long( argc, argv, opt_string,
			(const struct option *)&opts, &i ) ) != -1 ) {
		switch( c ) {
			case 'o':
				pd_options.output_file = optarg;
				break;
			case 'i':
				pd_options.tcp_host = optarg;
				break;
			case 'p':
				pd_options.tcp_port = atoi( optarg );
				if( pd_options.tcp_port > 65535 ) {
					fprintf( stderr, "Bad port number\n" );
					return EXIT_FAILURE;
				}
				break;
			case 'v':
				pd_options.verbose = 1;
				break;
			case 'h':
				return usage( argv[0] );
			case 's':
				pd_options.chunk_size = atoi( optarg );
				break;
			case 'l':
				list_maps = 1;
				break;
			case 'm':
				tmp_str = optarg;
				cnt = 0;
				while( *tmp_str ) {
					if( *tmp_str == ',' )
						cnt++;
					tmp_str++;
				}
				pd_options.modules = (char **)calloc( cnt+1, sizeof( char ** ) );
				if( pd_options.modules == NULL ) {
					fprintf( stderr, "Memory allocation error\n" );
					return EXIT_FAILURE;
				}
				cnt = 0;
				pd_options.modules[cnt++] = optarg;
				while( *optarg ) {
					if( *optarg == ',' ) {
						pd_options.modules[cnt++] = optarg;
						*optarg = '\0';
					}
					optarg++;
				}
				break;
			case 'f':
				while( *optarg ) {
					switch( * optarg ) {
						case '+': perm_state = PERM_MUST; break;
						case '-': perm_state = PERM_NOT; break;
						case 'r':
							pd_options.permissions |=
								( (unsigned int)PERM_READ << perm_state);
							break;
						case 'w':
							pd_options.permissions |=
								( (unsigned int)PERM_WRITE << perm_state);
							break;
						case 'x':
							pd_options.permissions |=
								( (unsigned int)PERM_EXEC << perm_state);
							break;
						case 'p':
							pd_options.permissions |=
								( (unsigned int)PERM_PRIV << perm_state);
							break;
						case 's':
							pd_options.permissions |=
								( (unsigned int)PERM_SHR << perm_state);
							break;
					}
					optarg++;
				}
				break;
			case 1: //XXX should use hexadecimal
				pd_options.addr_start = (unsigned long)strtol( optarg,
					NULL, 10 );
				break;
			case 2: //XXX should use hexadecimal
				pd_options.addr_start = (unsigned long)strtol( optarg,
					NULL, 10 );
				break;
		}
	}

	if( pd_options.tcp_host != NULL ) {
		if( pd_options.output_file != NULL ) {
			fprintf( stderr, "Can't do file and network\n" );
			return EXIT_FAILURE;
		}
		if( pd_options.tcp_port == 0 ) {
			fprintf( stderr, "No port specified\n" );
			return EXIT_FAILURE;
		}

		dprint( pd_options.verbose, "Setting up TCP connection" );
		if( tcp_setup( pd_options.tcp_host, pd_options.tcp_port ) == 0 ) {
			return EXIT_FAILURE;
		}
		pd_options.writer = (write_function_t *)tcp_write;
		pd_options.close = (close_function_t *)tcp_close;
	}
	else if( pd_options.output_file != NULL ) {
		dprint( pd_options.verbose, "Setting up file stream" );
		if( file_setup( pd_options.output_file ) == 0 ) {
			return EXIT_FAILURE;
		}
		pd_options.writer = (write_function_t *)file_write;
		pd_options.close = (close_function_t *)file_close;
	}
	else {
		pd_options.writer = (write_function_t *)stdout_write;
		pd_options.close = NULL;
	}

	if( optind < argc ) {
		if( argc - optind > 1 ) {
			while( optind < argc ) {
				pid = strtol( argv[optind], NULL, 10 );
				if( list_maps ) {
					printf( "Process: %d", pid );
					print_map_listing( pid );
					printf( "\n" );
				}
				else {
					process_pid( pid );
				}
				optind++;
			}
		}
		else {
			pid = strtol( argv[optind], NULL, 10 );
			if( list_maps ) {
				return print_map_listing( pid );
			}
			return process_pid( pid );
		}
	}
	else {
		fprintf( stderr, "No process id specified\n" );
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
