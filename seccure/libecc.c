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

static unsigned int __init_ecc_refcount = 0;

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
bool __init_ecc(ECC_State state)
{
	/* Make sure we don't accidentally double-init */
	if (state->gcrypt_init)
		return true;

	if (__init_ecc_refcount > 0) {
		__init_ecc_refcount++;
		state->gcrypt_init = true;
		return true;
	}
	
	gcry_error_t err;
	
	if (!gcry_check_version(REQUIRED_LIBGCRYPT)) {
		__gwarning("Incorrect libgcrypt version", err);
		return false;
	}

	err = gcry_control(GCRYCTL_INIT_SECMEM, 1);
	if (gcry_err_code(err))
		__gwarning("Cannot enable libgcrypt's secure memory management", err);

	if ( (state->options != NULL) && (state->options->secure_random) ) {
		err = gcry_control(GCRYCTL_USE_SECURE_RNDPOOL, 1);
		if (gcry_err_code(err))
			__gwarning("Cannot enable libgcrupt's secure random number generator", err);
	}

	state->gcrypt_init = true;
	return true;
}

struct curve_params *__curve_from_opts(ECC_Options opts)
{
	struct curve_params *c_params;
	/*
	 * Pull out the curve if it's passed in on the opts object
	 */
	if ( (opts != NULL) && (opts->curve != NULL) ) 
		c_params = curve_by_name(opts->curve);
	else
		c_params = curve_by_name(DEFAULT_CURVE);

	return c_params;
}

ECC_State ecc_new_state(ECC_Options opts)
{
	ECC_State state = (ECC_State)(malloc(sizeof(struct _ECC_State)));
	bzero(state, sizeof(struct _ECC_State));

	state->options = opts;

	if (!__init_ecc(state)) {
		__warning("Failed to initialize libecc's state properly!");
		free(state);
		return NULL;
	}

	state->curveparams = __curve_from_opts(opts);

	return state;
}

void ecc_free_state(ECC_State state)
{
	if (state == NULL)
		return;
	
	if (state->options)
		free(state->options);
	
	if (state->curveparams)
		curve_release(state->curveparams);
	
	if (state->gcrypt_init) {
		__init_ecc_refcount--;

		if (__init_ecc_refcount == 0) {
			gcry_error_t err;

			err = gcry_control(GCRYCTL_TERM_SECMEM);
			if (gcry_err_code(err))
				__gwarning("Failed to disable the secure memory pool in libgcrypt", err);
		}
	}

	free(state);
}
ECC_KeyPair ecc_new_keypair(char *pubkey, char *privkey, ECC_State state)
{
	ECC_KeyPair kp = (ECC_KeyPair)(malloc(sizeof(struct _ECC_KeyPair)));

	kp->pub = NULL;
	kp->priv = NULL;
	kp->pub_len = 0;

	if (pubkey != NULL) {
		kp->pub = pubkey;
		kp->pub_len = (unsigned int)(strlen(pubkey));
	}

	if (privkey != NULL) {
		gcry_error_t err;
		gcry_md_hd_t container;
		gcry_mpi_t privkey_hash;
		char *privkey_secure = NULL;

		err = gcry_md_open(&container, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
		if (gcry_err_code(err)) {
			__gwarning("Could not initialize SHA-256 digest for the private key", err);
			free(kp);
			return NULL;
		}
		gcry_md_write(container, privkey, strlen(privkey));
		gcry_md_final(container);
		privkey_secure = (char *)(gcry_md_read(container, 0));

		privkey_hash = hash_to_exponent(privkey_secure, state->curveparams);
		gcry_md_close(container);

		kp->priv = privkey_hash;
	}

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

ECC_KeyPair ecc_keygen(void *priv, ECC_State state)
{
	if (priv == NULL) {
		/*
		 * We should use a NULL private key as a signal to use
		 * /dev/urandom or something with sufficient entropy
		 * to generate our own private key
		 */
		return NULL;
	}

	ECC_KeyPair result = ecc_new_keypair(NULL, priv, state);
	struct affine_point ap;
	result->pub = (char *)(malloc(sizeof(char) * 
			(state->curveparams->pk_len_compact + 1)));

	ap = pointmul(&state->curveparams->dp.base, result->priv,
			&state->curveparams->dp);
	compress_to_string(result->pub, DF_COMPACT, &ap, state->curveparams);
	point_release(&ap);

	return result;
}


ECC_Data ecc_sign(char *data, ECC_KeyPair keypair, ECC_State state)
{
	ECC_Data rc = NULL;

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
	if ( (state == NULL) || (!state->gcrypt_init) ) {
		__warning("Invalid or uninitialized ECC_State object");
		goto exit;
	}

	gcry_md_hd_t digest;
	gcry_error_t err;
	gcry_mpi_t signature;
	char *digest_buf = NULL;

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

	signature = ECDSA_sign(digest_buf, keypair->priv, state->curveparams);

	if (signature == NULL) {
		__warning("ECDSA_sign() returned a NULL signature");
		goto bailout;
	}

	rc = ecc_new_data();
	char *serialized = (char *)(malloc(sizeof(char) * 
			(1 + state->curveparams->sig_len_compact)));

	serialize_mpi(serialized, state->curveparams->sig_len_compact, 
			DF_COMPACT, signature);
	serialized[state->curveparams->sig_len_compact] = '\0';
	rc->data = serialized;
	
	bailout:
		gcry_mpi_release(signature);
		gcry_md_close(digest);
		goto exit;
	exit:
		return rc;
}


bool ecc_verify(char *data, char *signature, ECC_KeyPair keypair, ECC_State state)
{
	bool rc = false;

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
	if ( (state == NULL) || (!state->gcrypt_init) ) {
		__warning("Invalid or uninitialized ECC_State object");
		goto exit;
	}

	struct affine_point _ap;
	gcry_error_t err;
	gcry_mpi_t deserialized_sig;
	gcry_md_hd_t digest;
	char *digest_buf = NULL;
	int result = 0;

	if (!decompress_from_string(&_ap, keypair->pub, DF_COMPACT, state->curveparams)) {
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

	result = ECDSA_verify(digest_buf, &_ap, deserialized_sig, state->curveparams);
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
		gcry_md_close(digest);
		goto exit;
	exit:
		return rc;
}
