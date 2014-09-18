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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int fsocket;

int tcp_write( unsigned char * data, int len )
{
	int bsend;
	if( ( bsend = send( fsocket, data, len, 0 ) ) == -1 ) {
		perror(NULL);
		return 0;
	}
	return bsend;
}

int tcp_setup( char * host, int port )
{
	struct sockaddr_in tsockaddr;

	if( ( fsocket = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 ) {
		perror(NULL);
		return 0;
	}

	memset( &tsockaddr, 0, sizeof( tsockaddr ) );
	tsockaddr.sin_family = AF_INET;
	tsockaddr.sin_addr.s_addr = inet_addr( host );
	tsockaddr.sin_port = htons( port );

	if( connect( fsocket, (struct sockaddr *)&tsockaddr,
		sizeof(tsockaddr) ) < 0 ) {
			perror(NULL);
			return 0;
	}
	return 1;
}

void tcp_close() {
	close( fsocket );
}
