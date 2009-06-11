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
#include "protocol.h"
#include "serialize.h"


/**
 * Print a warning to stderr
 */
void __gwarning(const char *message, gcry_error_t err)
{
	fprintf(stderr, "WARNING (libgcrypt): %s : %s\n", message, gcry_strerror(err));
}
void __warning(const char *message) 
{
	fprintf(stderr, "WARNING: %s\n", message);
}

/**
 * Handle initializing libgcrypt and some other preliminary necessities
 */
bool __init_ecc(ECC_Options options)
{
	gcry_error_t err;
	
	if (!gcry_check_version(REQUIRED_LIBGCRYPT)) {
		__gwarning("Incorrect libgcrypt version", err);
		return false;
	}

	err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	if (gcry_err_code(err))
		__gwarning("Cannot enable libgcrypt's secure memory management", err);

	if ( (options != NULL) && (options->secure_random) ) {
		err = gcry_control(GCRYCTL_USE_SECURE_RNDPOOL, 1);
		if (gcry_err_code(err))
			__gwarning("Cannot enable libgcrupt's secure random number generator", err);
	}
		
	return true;
}

void __del_ecc()
{
	gcry_error_t err;

	err = gcry_control(GCRYCTL_TERM_SECMEM);
	if (gcry_err_code(err))
		__gwarning("Failed to disable the secure memory pool in libgcrypt", err);
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
	opts->secure_random = true;
	opts->curve = DEFAULT_CURVE;

	return opts;
}

ECC_KeyPair ecc_keygen(void *priv)
{
	return NULL;

}


ECC_Data ecc_sign(char *data, ECC_KeyPair keypair, ECC_Options opts)
{
	ECC_Data rc = NULL;

	if (!__init_ecc(opts)) {
		__warning("Failed to initialize libecc for whatever reason");
		goto exit;
	}

	/* 
	 * Preliminary argument checks, just for sanity of the library 
	 */
	if ( (data == NULL) || (strlen(data) == 0) ) {
		__warning("Invalid or empty `data` argument passed to ecc_verify()");
		goto exit;
	}
	if ( (keypair == NULL) || (keypair->priv == NULL) || 
			(strlen(keypair->priv) == 0) ) {
		__warning("Invalid ECC_KeyPair object passed to ecc_verify()");
		goto exit;
	}

	struct curve_params *c_params;
	gcry_md_hd_t digest;
	gcry_error_t err;
	gcry_mpi_t signature, keyhash;
	char *digest_buf = NULL;
	char *privkey_buf = NULL;

	/*
	 * Pull out the curve if it's passed in on the opts object
	 */
	if ( (opts != NULL) && (opts->curve != NULL) ) 
		c_params = curve_by_name(opts->curve);
	else
		c_params = curve_by_name(DEFAULT_CURVE);

	/* 
	 * Process the private key in secure memory
	 */
	gcry_md_hd_t key_store;
	err = gcry_md_open(&key_store, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if (gcry_err_code(err)) {
		__warning("Could not initialize SHA-256 digest for the private key");
		goto bailout;
	}
	gcry_md_write(key_store, (char *)(keypair->priv), strlen((char *)(keypair->priv)));
	gcry_md_final(key_store);
	privkey_buf = (char *)(gcry_md_read(key_store, 0));

	keyhash = hash_to_exponent(privkey_buf, c_params);
	gcry_md_close(key_store);

	/*
	 * Open up message digest for the signing
	 */
	err = gcry_md_open(&digest, GCRY_MD_SHA512, 0);
	if (gcry_err_code(err)) {
		__gwarning("Failed to initialize SHA-512 message digest", err);
		goto bailout;
	}

	/*
	 * Write our data into the message digest buffer for gcrypt
	 */
	gcry_md_write(digest, data, strlen(data));
	gcry_md_final(digest);
	digest_buf = (char *)(gcry_md_read(digest, 0));

	if (digest_buf == NULL) {
		__warning("Digest buffer was NULL");
		goto bailout;
	}

	signature = ECDSA_sign(digest_buf, keyhash, c_params);

	if (signature == NULL) {
		__warning("ECDSA_sign() returned a NULL signature");
		goto bailout;
	}

	rc = ecc_new_data();
	char *serialized = (char *)(malloc(sizeof(char) * (1 + c_params->sig_len_compact)));

	serialize_mpi(serialized, c_params->sig_len_compact, DF_COMPACT, signature);
	rc->data = serialized;
	
	bailout:
		gcry_mpi_release(keyhash);
		gcry_mpi_release(signature);
		gcry_md_close(digest);
		curve_release(c_params);
		goto exit;
	exit:
		__del_ecc();
		return rc;
}


bool ecc_verify(char *data, char *signature, ECC_KeyPair keypair, ECC_Options opts)
{
	bool rc = false;

	if (!__init_ecc(opts)) {
		__warning("Failed to initialize libecc for whatever reason");
		goto exit;
	}

	/*
	 * Preliminary argument checks, just for sanity of the library
	 */
	if ( (data == NULL) || (strlen(data) == 0) ) {
		__warning("Invalid or empty `data` argument passed to ecc_verify()");
		goto exit;
	}
	if ( (signature == NULL) || (strlen(signature) == 0) ) {
		__warning("Invalid or empty `signature` argument passed to ecc_verify()");
		goto exit;
	}
	if ( (keypair == NULL) || (keypair->pub == NULL) ) {
		__warning("Invalid ECC_KeyPair object passed to ecc_verify()");
		goto exit;
	}


	struct curve_params *c_params;
	struct affine_point _ap;
	gcry_error_t err;
	gcry_mpi_t deserialized_sig;
	gcry_md_hd_t digest;
	char *digest_buf = NULL;
	int result = 0;
	
	/*
	 * Pull out the curve if it's passed in on the opts object
	 */
	if ( (opts != NULL) && (opts->curve != NULL) ) 
		c_params = curve_by_name(opts->curve);
	else
		c_params = curve_by_name(DEFAULT_CURVE);
	

	if (!decompress_from_string(&_ap, keypair->pub, DF_COMPACT, c_params)) {
		__warning("Invalid public key");
		goto bailout;
	}

	err = gcry_md_open(&digest, GCRY_MD_SHA512, 0);
	if (gcry_err_code(err)) {
		__gwarning("Failed to initialize SHA-512 message digest", err);
		goto bailout;
	}

	/*
	 * Write our data into the message digest buffer for gcrypt
	 */
	gcry_md_write(digest, data, strlen(data));
	gcry_md_final(digest);
	digest_buf = (char *)(gcry_md_read(digest, 0));

	result = deserialize_mpi(&deserialized_sig, DF_COMPACT, signature, 
						strlen(signature));
	if (!result) {
		__warning("Failed to deserialize the signature");
		goto bailout;
	}

	result = ECDSA_verify(digest_buf, &_ap, deserialized_sig, c_params);
	if (result)
		rc = true;
	/*
	 * Calling gcry_mpi_release() here after we're certain we have an object
	 * and we're certain that it's valid. I don't *think* that this should 
	 * case a leak in the case above if `result` doesn't exist and we bailout.
	 *
	 * Calling gcry_mpi_release() will cause a double free() if placed in bailout
	 * most likely because somebody inside libgcrypt isn't checking members for NULL
	 * prior to free()
	 */
	gcry_mpi_release(deserialized_sig);

	bailout:
		point_release(&_ap);
		curve_release(c_params);
		gcry_md_close(digest);
		goto exit;
	exit:
		__del_ecc();
		return rc;
}
