/*
 *  test_gcrypt - Copyright 2009 Slide, Inc.
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public License 
 * as published by the Free Software Foundation; either version 2.1 of 
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
 * for more details. 
 *
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the 
 * Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gcrypt.h>


void __test_mpi_scan()
{
	const char *order = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
	char *outbuf;
	gcry_mpi_t point = gcry_mpi_new(0);
	int rc = 0;
	int n = 0;

	rc = gcry_mpi_scan(&point, GCRYMPI_FMT_HEX, order, 0, NULL);
	g_assert(rc == 0);

	fprintf(stderr, "OUT %s : %d\n", outbuf, n);
}

int main(int argc, char **argv)
{
	int rc = 0;
	g_test_init(&argc, &argv, NULL);

	/*
	 * Test some basic mpi operations
	 */
	g_test_add_func("/mpi/scan", __test_mpi_scan);

	rc = g_test_run();
	fflush(stderr);
	return rc;
}
