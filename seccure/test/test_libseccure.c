/*
 *  test_libseccure - Copyright 2009 Slide, Inc.
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

#include "protocol.h"
#include "serialize.h"
#include "libseccure.h"


/*
 * These values are built by running the seccure binary and 
 * assume the curve of DEFAULT_CURVE (currently p384)
 */
#define DEFAULT_DATA "This message will be signed\n"
#define DEFAULT_SIG "#cE/UfJ@]qte8w-ajzi%S%tO<?$?@QK_hTL&pk-ES1L~C9~4lpm+P7ZXu[mXTJ:%tdhQa:z~~q)BAw{.3dvt!ub+s?sXyxk;S%&+^P-~%}+G3G?Oj-nSDc/"

/*
 * private and public key generated with a 384 curve
 */
#define DEFAULT_PUBKEY "#&M=6cSQ}m6C(hUz-7j@E=>oS#TL3F[F[a[q9S;RhMh+F#gP|Q6R}lhT_e7b"
#define DEFAULT_PRIVKEY "!!![t{l5N^uZd=Bg(P#N|PH#IN8I0,Jq/PvdVNi^PxR,(5~p-o[^hPE#40.<|"

#define DEFAULT_PLAINTEXT "This is a very very secret message!\n"


/**
 * __test_verify() will test the ecc_verify() function to comply with 
 * the transcript from the original SECCURE site:
 */
void __test_verify()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);
	g_assert(ecc_verify(DEFAULT_DATA, DEFAULT_SIG, kp, state));
	ecc_free_state(state);
	ecc_free_keypair(kp);
}

void __test_verify_nullkp()
{
	g_assert(ecc_verify(DEFAULT_DATA, DEFAULT_SIG, NULL, NULL) == false);
}

void __test_verify_nulldata()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);
	g_assert(ecc_verify(NULL, DEFAULT_SIG, kp, state) == false);
	ecc_free_state(state);
	ecc_free_keypair(kp);
}

void __test_verify_nullsig()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);
	g_assert(ecc_verify(DEFAULT_DATA, NULL, kp, state) == false);
	ecc_free_state(state);
	ecc_free_keypair(kp);
}

void __test_verify_crapsig()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);
	g_assert(ecc_verify(DEFAULT_DATA, "This sig is crap", kp, state) == false);
	ecc_free_state(state);
	ecc_free_keypair(kp);
}



/**
 * __test_new_keypair() will test ecc_new_keypair() and make sure it generates an
 * allocated, but empty ::ECC_KeyPair object
 */
void __test_new_keypair()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(NULL, NULL, state);

	g_assert(kp != NULL);
	g_assert(kp->priv == NULL);
	g_assert(kp->pub == NULL);

	ecc_free_state(state);
	ecc_free_keypair(kp);
}

/**
 * __test_new_state() will test ecc_new_state() to make sure it generates
 * a properly allocated and empty ::ECC_State object
 */
void __test_new_state()
{
	ECC_State state = ecc_new_state(NULL);
	g_assert(state != NULL);
	ecc_free_state(state);
}

/**
 * __test_new_data() will test ecc_new_data() and make sure it generates
 * a properly allocated but empty ::ECC_Data object
 */
void __test_new_data()
{
	ECC_Data ed = ecc_new_data();
	g_assert(ed != NULL);
}


/**
 * __test_new_options() will test ecc_new_options() and make sure it generates
 * a properly allocated ::ECC_Options object
 */
void __test_new_options()
{
	ECC_Options eo = ecc_new_options();

	g_assert(eo != NULL);
	/* 
	 * Not checking all the options since I don't want to maintain
	 * a duplicate list
	 */
	g_assert(eo->curve != NULL);
}


/**
 * __test_sign should test a simple straight-forward
 * signing of a predetermined string to verify it outputs 
 * the same signature that the seccure binary does
 */
void __test_sign()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);

	ECC_Data result = NULL;

	result = ecc_sign(DEFAULT_DATA, kp, state);

	g_assert(result != NULL);
	g_assert_cmpstr(result->data, ==, DEFAULT_SIG);
	/*
	 * For completeness' sake, verify our signature we 
	 * just generated as well
	 */
	g_assert(ecc_verify(DEFAULT_DATA, result->data, kp, state));
	ecc_free_state(state);
	ecc_free_keypair(kp);
}
void __test_sign_nulldata()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);

	ECC_Data result = ecc_sign(NULL, kp, state);
	g_assert(result == NULL);
	ecc_free_state(state);
	ecc_free_keypair(kp);
}
void __test_sign_nullkp()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_Data result = ecc_sign(DEFAULT_DATA, NULL, state);
	g_assert(result == NULL);
	ecc_free_state(state);
}


/**
 * __test_keygen should test the canonical case
 * of public key generation with a given private key
 */
void __test_keygen()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair result = ecc_keygen(DEFAULT_PRIVKEY, state);

	g_assert(result != NULL);
	g_assert(result->pub != NULL);
	g_assert_cmpstr(result->pub, ==, DEFAULT_PUBKEY);
	ecc_free_state(state);
	ecc_free_keypair(result);
}

/**
 * __test_full_keygen should test the case where we
 * rely on libseccure to generate both the private and
 * the public keys
 */
void __test_full_keygen()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_KeyPair result = ecc_keygen(NULL, state);

	g_assert(result != NULL);
	g_assert(result->pub != NULL);
	g_assert(result->priv != NULL);

	/*

	fprintf(stderr, "pub %s\n",  (char *)(result->pub));

	char *buf = (char *)malloc(sizeof(char) * 
			(1 + state->curveparams->pk_len_compact));
	serialize_mpi(buf, (1 + state->curveparams->pk_len_compact), 
			DF_COMPACT, result->priv);

	fprintf(stderr, "priv %s\n", buf);
	*/

	ecc_free_state(state);
	ecc_free_keypair(result);
}


/**
 * __test_encrypt should test the basic encryption
 * of a string of data via ECC
 */
void __test_encrypt()
{
	ECC_State state = ecc_new_state(NULL);
	ECC_Data decrypted;
	ECC_KeyPair kp = ecc_new_keypair(DEFAULT_PUBKEY, NULL, state);

	ECC_Data result = ecc_encrypt(DEFAULT_PLAINTEXT, strlen(DEFAULT_PLAINTEXT), 
			kp, state);

	g_assert(result != NULL);
	g_assert(result->data != NULL);

	ecc_free_keypair(kp);

    kp = ecc_new_keypair(DEFAULT_PUBKEY, DEFAULT_PRIVKEY, state);

	decrypted = ecc_decrypt(result, kp, state);
	g_assert(decrypted != NULL);
	g_assert(decrypted->data != NULL);
	g_assert_cmpstr(DEFAULT_PLAINTEXT, ==, decrypted->data);

	if (result)
		ecc_free_data(result);
	if (decrypted)
		ecc_free_data(decrypted)

	ecc_free_state(state);
	ecc_free_keypair(kp);
}


int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	/*
	 * Basic data structures tests
	 */
	g_test_add_func("/libseccure/struct/ecc_new_keypair", __test_new_keypair);
	g_test_add_func("/libseccure/struct/ecc_new_data", __test_new_data);
	g_test_add_func("/libseccure/struct/ecc_new_options", __test_new_options);
	g_test_add_func("/libseccure/struct/ecc_new_state", __test_new_state);

	/*
	 * Tests for ecc_keygen()
	 */
	//g_test_add_func("/libseccure/ecc_keygen/default", __test_keygen);
	g_test_add_func("/libseccure/ecc_keygen/full", __test_full_keygen);


	/*
	 * Tests for ecc_verify()
	 */
	g_test_add_func("/libseccure/ecc_verify/default", __test_verify);
	g_test_add_func("/libseccure/ecc_verify/null_keypair", __test_verify_nullkp);
	g_test_add_func("/libseccure/ecc_verify/null_data", __test_verify_nulldata);
	g_test_add_func("/libseccure/ecc_verify/null_sig", __test_verify_nullsig);
	g_test_add_func("/libseccure/ecc_verify/crap_sig", __test_verify_crapsig);

	/* 
	 * Tests for ecc_sign()
	 */
	g_test_add_func("/libseccure/ecc_sign/default", __test_sign);
	g_test_add_func("/libseccure/ecc_sign/null_data", __test_sign_nulldata);
	g_test_add_func("/libseccure/ecc_sign/null_keypair", __test_sign_nullkp);

	/*
	 * Tests for ecc_encrypt()
	 */
	g_test_add_func("/libseccure/ecc_encrypt/default", __test_encrypt);


	return g_test_run();
}
