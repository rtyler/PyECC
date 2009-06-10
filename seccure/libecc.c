/*
 *  libecc - Copyright 2009 Slide, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>

#include <gcrypt.h>

#include "curves.h"
#include "ecc.h"
#include "libecc.h"
#include "serialize.h"


/**
 * Print a warning to stderr
 */
void __gwarning(const char *message, gcry_error_t err)
{
	fprintf(stderr, "WARNING: %s : %s\n", message, gcry_strerror(err));
}
void __warning(const char *message) 
{
		fprintf(stderr, "WARNING: %s\n", message);
}

/**
 * Handle initializing libgcrypt and some other preliminary necessities
 */
bool __init_ecc() 
{
	gcry_error_t err;
	
	if (!gcry_check_version(REQUIRED_LIBGCRYPT)) {
		__gwarning("Incorrect libgcrypt version", err);
		return false;
	}

	err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	if (gcry_err_code(err))
		__gwarning("Cannot enable libgcrypt's secure memory management", err);

	err = gcry_control(GCRYCTL_USE_SECURE_RNDPOOL, 1);
	if (gcry_err_code(err))
		__gwarning("Cannot enable libgcrupt's secure random number generator", err);
		
	return true;
}

ECC_KeyPair ecc_new_keypair()
{
	ECC_KeyPair kp = (ECC_KeyPair)(malloc(sizeof(struct _ECC_KeyPair)));
	bzero(kp, sizeof(struct _ECC_KeyPair));
	return kp;
}

ECC_Data ecc_new_data()
{
	ECC_Data data = (ECC_Data)(malloc(sizeof(struct _ECC_Data)));
	bzero(data, sizeof(struct _ECC_Data));
	return data;
}

ECC_Options ecc_new_options()
{
	ECC_Options opts = (ECC_Options)(malloc(sizeof(struct _ECC_Options)));
	bzero(opts, sizeof(struct _ECC_Options));
	/*
	 * Setup the default values of the ::ECC_Options object
	 */
	opts->secure_malloc = true;
	opts->curve = DEFAULT_CURVE;

	return opts;
}

bool ecc_verify(char *data, char *signature, ECC_KeyPair keypair, ECC_Options opts)
{
	if (!__init_ecc()) {
		__warning("Failed to initialize libecc for whatever reason");
		return false;
	}

	/*
	 * Preliminary argument checks, just for sanity of the library
	 */
	if ( (data == NULL) || (strlen(data) == 0) ) {
		__warning("Invalid or empty `data` argument passed to ecc_verify()");
		return false;
	}
	if ( (signature == NULL) || (strlen(signature) == 0) ) {
		__warning("Invalid or empty `signature` argument passed to ecc_verify()");
		return false;
	}
	if ( (keypair == NULL) || (keypair->pub == NULL) ) {
		__warning("Invalid ECC_KeyPair object passed to ecc_verify()");
		return false;
	}


	struct curve_params *c_params;
	//struct affine_point _ap;
	//gcry_error_t err;
	//gcry_mpi_t data, sig;
	
	/*
	 * Pull out the curve if it's passed in on the opts object
	 */
	if ( (opts != NULL) && (opts->curve != NULL) ) 
		c_params = curve_by_name(opts->curve);
	else
		c_params = curve_by_name(DEFAULT_CURVE);
		
	return false;
}
