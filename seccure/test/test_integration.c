/*
 *  test_integration - Copyright 2009 Slide, Inc.
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <gcrypt.h>

#include "libseccure.h"

#define LOOPS 200

void __test_keygen_to_sign()
{
}

void __test_keygen_to_encrypt()
{
}

void print_data(ECC_Data d, bool aschar)
{
	unsigned int i = 0;
	if (!d->datalen)
		return;

	for (; i < d->datalen; ++i) {
		if (aschar) 
			fprintf(stderr, "%c ", ((char *)d->data)[i]);
		else
			fprintf(stderr, "%d ", (int)((char *)d->data)[i]);
	}
}
void assert_eqaul_data(ECC_Data left, ECC_Data right)
{
	unsigned int i = 0;
	char lc, rc;
	if ( (!left) || (!right) ) {
		fprintf(stderr, "left/right pointers (%p, %p)\n", left, right);
		goto abort;
	}

	if ( left->datalen != right->datalen ) {
		fprintf(stderr, "Non-equal `datalen` members\n");
		goto abort;
	}

	for (; i < left->datalen; ++i) {
		lc = ((char *)left->data)[i];
		rc = ((char *)right->data)[i];

		if ( lc != rc ) {
			fprintf(stderr, "Character mismatch at char %d, left/right: %d/%d\n", 
					i, (int)lc, (int)rc);
			goto abort;
		}	
	}

	return;

	abort:
		if (left && right) {
			fprintf(stderr, "\t\tLeft\t||\tRight\n");
			fprintf(stderr, "pointer\t %p \t||\t %p\n", left, right);
			fprintf(stderr, "len\t %d \t||\t %d\n", left->datalen, right->datalen);
			fprintf(stderr, "str\t ");
			print_data(left, false);
			fprintf(stderr, " \t||\t ");
			print_data(right, false);
			fprintf(stderr, "\n");
		}
		abort();
}

void __test_keygensalot()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair keypair = NULL;
	unsigned int i = 0;

	for (; i < LOOPS; ++i) {
		fprintf(stderr, "%d, ", i);
		keypair = ecc_keygen(NULL, state);
		ecc_free_keypair(keypair);
	}
	ecc_free_state(state);
}

void __test_keygen_encryptsalot()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair keypair = ecc_keygen(NULL, state);
	ECC_Data encrypted, last_run, decrypted;
	unsigned int i = 0;
	const char *data = "This should be all encrypted and such\n";
	encrypted = last_run = NULL;

	g_assert(keypair != NULL);
	g_assert(keypair->pub != NULL);
	g_assert(keypair->priv != NULL);

	for (; i < LOOPS; ++i) {
		fprintf(stderr, "%d (%d), ", i, errno);
		encrypted = ecc_encrypt(data, strlen(data), keypair, state);

		g_assert(data != NULL);
		g_assert(encrypted != NULL);
		g_assert(encrypted->data != NULL);

		if (last_run == NULL) {
			last_run = encrypted;
		}
		else {
			decrypted = ecc_decrypt(encrypted, keypair, state);
			g_assert_cmpstr(data, ==, decrypted->data);
			ecc_free_data(decrypted);
			g_assert(last_run->datalen == encrypted->datalen);
			ecc_free_data(last_run);
			last_run = encrypted;
		}
	}

	ecc_free_data(last_run);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/integration/keygen_to_sign", __test_keygen_to_sign);
	g_test_add_func("/integration/keygen_to_encrypt", __test_keygen_to_encrypt);
	g_test_add_func("/integration/keygensalot", __test_keygensalot);
	g_test_add_func("/integration/keygen_encryptsalot", __test_keygen_encryptsalot);

	return g_test_run();
}
