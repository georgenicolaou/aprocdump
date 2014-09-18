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

#include <stdio.h>

int stdout_write( char * data, int len )
{
	if( fwrite( data, 1, len, stdout ) != len ) {
		perror(NULL);
		return 0;
	}
	fflush(stdout);
	return len;
}
