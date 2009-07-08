/*
 *  test_leaky - Copyright 2009 Slide, Inc.
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
#include <errno.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <time.h>

#include <glib.h>
#include <gcrypt.h>

#include "libseccure.h"

#define LOOPS 100
#define MAX_SIZE 256 * 1024

int main(int argc, char **argv)
{
	int fd = open("/dev/urandom", 0);
	if (fd == -1) {
		fprintf(stderr, "Failed to open /dev/urandom?\n");
		fprintf(stderr, "%s\n", strerror(errno));
		return -1;
	}
	
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair keypair = ecc_keygen(NULL, state);
	ECC_Data encrypted = NULL;
	unsigned int i = 0;
	size_t readbytes;
	char *data = NULL;

	g_assert(keypair != NULL);
	g_assert(keypair->pub != NULL);
	g_assert(keypair->priv != NULL);

	while (i < MAX_SIZE) {
		i = i + 1024;

		data = (char *)(malloc(sizeof(char) * i));
		readbytes = read(fd, (void *)(data), (size_t)(i));
		if (readbytes <= 0) {
			fprintf(stderr, "No data read! Bail!\n");
			fprintf(stderr, "Error: %s\n", strerror(errno));
			i = MAX_SIZE;
			continue;
		}
		
		encrypted = ecc_encrypt(data, i, keypair, state);

		fprintf(stderr, "%dKB, ", (i / 1024));

		g_assert(data != NULL);
		g_assert(encrypted != NULL);
		g_assert(encrypted->data != NULL);

		ecc_free_data(encrypted);
		free(data);
		data = NULL;
	}

	fprintf(stderr, "\n");

	close(fd);

	return 0;
}
