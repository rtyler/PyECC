/*
 *  test_libecc - Copyright 2009 Slide, Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "libecc.h"

#define DEFAULT_DATA "This message will be signed\n"
#define DEFAULT_SIG "$HPI?t(I*1vAYsl$|%21WXND=6Br*[>k(OR9B!GOwHqL0s+3Uq"
#define DEFAULT_PUBKEY "8W;>i^H0qi|J&$coR5MFpR*Vn"
#define DEFAULT_PRIVKEY "my private key"


/**
 * __test_verify() will test the ecc_verify() function to comply with 
 * the transcript from the original SECCURE site:
 */
void __test_verify()
{
	ECC_KeyPair kp = ecc_new_keypair();
	kp->priv = DEFAULT_PRIVKEY;
	kp->pub = DEFAULT_PUBKEY;

	g_assert(ecc_verify(DEFAULT_DATA, DEFAULT_SIG, kp, NULL));
}

void __test_verify_nullkp()
{
	g_assert(ecc_verify(DEFAULT_DATA, DEFAULT_SIG, NULL, NULL) == false);
}

void __test_verify_nulldata()
{
	ECC_KeyPair kp = ecc_new_keypair();
	kp->priv = DEFAULT_PRIVKEY;
	kp->pub = DEFAULT_PUBKEY;

	g_assert(ecc_verify(NULL, DEFAULT_SIG, kp, NULL) == false);
}

void __test_verify_nullsig()
{
	ECC_KeyPair kp = ecc_new_keypair();
	kp->priv = DEFAULT_PRIVKEY;
	kp->pub = DEFAULT_PUBKEY;

	g_assert(ecc_verify(DEFAULT_DATA, NULL, kp, NULL) == false);
}

void __test_verify_crapsig()
{
	ECC_KeyPair kp = ecc_new_keypair();
	kp->priv = DEFAULT_PRIVKEY;
	kp->pub = DEFAULT_PUBKEY;

	g_assert(ecc_verify(DEFAULT_DATA, "This sig is crap", kp, NULL) == false);
}



/**
 * __test_new_keypair() will test ecc_new_keypair() and make sure it generates an
 * allocated, but empty ::ECC_KeyPair object
 */
void __test_new_keypair()
{
	ECC_KeyPair kp = ecc_new_keypair();

	g_assert(kp != NULL);
	g_assert(kp->priv == NULL);
	g_assert(kp->pub == NULL);

	free(kp);
}


/**
 * __test_new_data() will test ecc_new_data() and make sure it generates
 * a properly allocated but empty ::ECC_Data object
 */
void __test_new_data()
{
	ECC_Data ed = ecc_new_data();
	
	g_assert(ed != NULL);
	g_assert(ed->data == NULL);
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
	ECC_KeyPair kp = ecc_new_keypair();
	kp->priv = DEFAULT_PRIVKEY;
	kp->pub = DEFAULT_PUBKEY;

	ECC_Data result = NULL;

	result = ecc_sign(DEFAULT_DATA, kp, NULL);

	g_assert(result != NULL);
	g_assert_cmpstr(result->data, ==, DEFAULT_SIG);
	g_assert(ecc_verify(DEFAULT_DATA, result->data, kp, NULL));
}



int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	/*
	 * Basic data structures tests
	 */
	g_test_add_func("/libecc/ecc_new_keypair", __test_new_keypair);
	g_test_add_func("/libecc/ecc_new_data", __test_new_data);
	g_test_add_func("/libecc/ecc_new_options", __test_new_options);


	/*
	 * Tests for ecc_verify()
	 */
	g_test_add_func("/libecc/ecc_verify/default", __test_verify);
	g_test_add_func("/libecc/ecc_verify/null_keypair", __test_verify_nullkp);
	g_test_add_func("/libecc/ecc_verify/null_data", __test_verify_nulldata);
	g_test_add_func("/libecc/ecc_verify/null_sig", __test_verify_nullsig);
	g_test_add_func("/libecc/ecc_verify/crap_sig", __test_verify_crapsig);

	/* 
	 * Tests for ecc_sign()
	 */
	g_test_add_func("/libecc/ecc_sign/default", __test_sign);


	return g_test_run();
}
