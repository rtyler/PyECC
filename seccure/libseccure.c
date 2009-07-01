/*
 *  libseccure - Copyright 2009 Slide, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>

#include <gcrypt.h>

#include "curves.h"
#include "ecc.h"
#include "libseccure.h"
#include "protocol.h"
#include "serialize.h"
#include "aes256ctr.h"

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

bool __verify_keypair(ECC_KeyPair keypair, bool require_private, bool require_public)
{
	if (keypair == NULL)
		return false;
	if (require_private) {
		if (keypair->priv == NULL)
			return false;
	}
	if (require_public) {
		if ( (keypair->pub == NULL) )
			return false;
	}
	return true;
}

bool __verify_state(ECC_State state)
{
	if ( (state == NULL) || (!state->gcrypt_init) )
		return false;
	return true;
}


/**
 * Handle initializing libgcrypt and some other preliminary necessities
 */
bool __init_ecc(ECC_State state)
{
	gcry_error_t err = 0;
	
	/* Make sure we don't accidentally double-init */
	if (state->gcrypt_init)
		return true;

	if (__init_ecc_refcount > 0) {
		__init_ecc_refcount++;
		state->gcrypt_init = true;
		return true;
	}
	
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

	gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

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

void ecc_free_keypair(ECC_KeyPair kp)
{
	if (kp == NULL)
		return;
	
	/*
	 * Double-free()'s for some god-awful reason
	 *
	if ( (kp->pub) && (kp->pub_bytes) )
		free(kp->pub);
	 */

	if (kp->priv)
		gcry_mpi_release(kp->priv);
	free(kp);
}

ECC_KeyPair ecc_new_keypair(char *pubkey, char *privkey, ECC_State state)
{
	unsigned int publen = 0;
	unsigned int privlen = 0;
	/*
	 * If we have a pubkey, it should be cp->pk_len_compact and no larger
	 */
	if (pubkey)
		publen = state->curveparams->pk_len_compact;
	/*
	 * Relying on the private key being passed in as a legit string (i.e.
	 * a hex encoded MPI
	 */
	if (privkey)
		privlen = strlen((const char *)(privkey));

	return ecc_new_keypair_s(pubkey, publen, privkey, privlen, state);
}

ECC_KeyPair ecc_new_keypair_s(char *pubkey, unsigned int pubkeylen, 
		char *privkey, unsigned int privkeylen, ECC_State state)
{
	ECC_KeyPair kp = (ECC_KeyPair)(malloc(sizeof(struct _ECC_KeyPair)));

	kp->pub = NULL;
	kp->priv = NULL;
	kp->pub_bytes = 0;

	if (pubkey != NULL) {
		kp->pub = pubkey;
		kp->pub_bytes = pubkeylen;
	}

	if (privkey != NULL) {
		kp->priv = hash_to_exponent(privkey, state->curveparams);
	}

	return kp;
}

ECC_Data ecc_new_data()
{
	ECC_Data data = (ECC_Data)(malloc(sizeof(struct _ECC_Data)));
	data->datalen = 0;
	return data;
}
void ecc_free_data(ECC_Data data)
{
	if (data == NULL)
		return;
	if (data->data != NULL)
		free(data->data);
	free(data);
}

ECC_Options ecc_new_options()
{
	ECC_Options opts = (ECC_Options)(malloc(sizeof(struct _ECC_Options)));
	/*
	 * Setup the default values of the ::ECC_Options object
	 */
	opts->secure_random = true;
	opts->curve = DEFAULT_CURVE;

	return opts;
}

ECC_KeyPair ecc_keygen(void *priv, ECC_State state)
{
	ECC_KeyPair result = NULL;
	struct affine_point ap;
	char *r;
	unsigned int bits;

	if (priv != NULL)
		return NULL;

	/* 
	 * Generate our own private key via /dev/urandom
	 */
	bits = gcry_mpi_get_nbits(state->curveparams->dp.order);
	r = (char *)(malloc(bits));
	gcry_randomize(r, bits, GCRY_VERY_STRONG_RANDOM);
	if (!r) {
		__warning("Failed to generate a random buffer of N bytes");
		ecc_free_keypair(result);
	}
	result = ecc_new_keypair_s(NULL, 0,  r, bits, state);

	if (r)
		free(r);

	/*
	 * This makes me die inside
	 */
	r = malloc(sizeof(char) * (state->curveparams->pk_len_compact + 1));

	ap = pointmul(&state->curveparams->dp.base, result->priv,
		&state->curveparams->dp);

	compress_to_string((char *)(r), DF_COMPACT, &ap, state->curveparams);

	point_release(&ap);

	result->pub = r;
	r[state->curveparams->pk_len_compact] = '\0';
	result->pub_bytes = (unsigned int)(state->curveparams->pk_len_compact + 1);

	return result;
}

const char *ecc_mpi_to_str(gcry_mpi_t key)
{
	gcry_error_t err;
	unsigned char *buf;
	size_t written;

	if (!key)
		return NULL;

	err = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &buf, &written, key);
	if (err) {
		__gwarning("Failed to call gcry_mpi_aprint() in ecc_key_to_str()", err);
		return NULL;
	}
	return (const char *)(buf);
}

ECC_Data ecc_decrypt(ECC_Data encrypted, ECC_KeyPair keypair, ECC_State state)
{
	ECC_Data rc = NULL;
	int offset;
	char *keybuf, *block;
	struct aes256ctr *ac;
	gcry_md_hd_t digest;
	struct affine_point *R = (struct affine_point *)(malloc(sizeof(struct affine_point)));

	if (!__verify_state(state)) {
		__warning("Invalid state passed to ecc_decrypt()");
		goto exit;
	}
	if (!__verify_keypair(keypair, true, false)) {
		__warning("Invalid keypair passed to ecc_decrypt()");
		goto exit;
	}

	/*
	 * Take the first bits off buffer to get the curve info
	 */
	if (!decompress_from_string(R, (char *)(encrypted->data), DF_BIN, 
				state->curveparams)) {
		__warning("Failed to decompress_from_string() in ecc_decrypt()");
		goto exit;
	}

	/* Why only 64? */
	if (!(keybuf = gcry_malloc_secure(64))) { 
		__warning("Out of secure memory!");
		goto bailout;
	}

	if (!ECIES_decryption(keybuf, R, keypair->priv, state->curveparams)) {
		__warning("ECIES_decryption() failed");
		goto bailout;
	}

	if (!(ac = aes256ctr_init(keybuf))) {
		__warning("Cannot initialize AES256-CTR");
		goto bailout;
	}

	if (!(hmacsha256_init(&digest, keybuf + 32, HMAC_KEY_SIZE))) {
		__warning("Couldn't initialize HMAC-SHA256");
		goto bailout;
	}

	rc = ecc_new_data();
	memset(keybuf, 0x00, 64);

	/*
	 * Decrypt the rest of the block (the actual encrypted data)
	 */
	block = ((char *)(encrypted->data) + state->curveparams->pk_len_bin);
	offset = (encrypted->datalen - state->curveparams->pk_len_bin);

	gcry_md_write(digest, block, offset);

	aes256ctr_dec(ac, block, offset);
	aes256ctr_done(ac);
	gcry_md_close(digest);

	offset = offset - DEFAULT_MAC_LEN;
	rc->data = (void *)(malloc(sizeof(char) * offset));
	rc->datalen = offset;
	memcpy(rc->data, block, offset);

	bailout:
		point_release(R);
		free(R);
		gcry_free(keybuf);
	exit:
		return rc;
}

ECC_Data ecc_encrypt(void *data, int databytes, ECC_KeyPair keypair, ECC_State state)
{
	ECC_Data rc = NULL;
	struct affine_point *P, *R;
	struct aes256ctr *ac;
	char *readbuf;
	char *keybuf, *md;
	void *plaintext = NULL;
	unsigned int offset = 0;
	gcry_md_hd_t digest;

	if ( (data == NULL) ) {
		__warning("Invalid or empty `data` argument passed to ecc_verify()");
		goto exit;
	}
	if (!__verify_keypair(keypair, false, true)) {
		__warning("Invalid ECC_KeyPair object passed to ecc_verify()");
		goto exit;
	}
	if (!__verify_state(state)) {
		__warning("Invalid or uninitialized ECC_State object");
		goto exit;
	}

	readbuf = (char *)(malloc(sizeof(char) * state->curveparams->pk_len_bin));
	P = (struct affine_point *)(malloc(sizeof(struct affine_point)));
	R = (struct affine_point *)(malloc(sizeof(struct affine_point)));

	if (!decompress_from_string(P, (char *)keypair->pub, 
			DF_COMPACT, state->curveparams)) {
		__warning("Invalid public key");
		goto bailout;
	}

	/* Why only 64? */
	if (!(keybuf = gcry_malloc_secure(64))) { 
		__warning("Out of secure memory!");
		goto exit;
	}
	*R = ECIES_encryption(keybuf, P, state->curveparams);
	compress_to_string(readbuf, DF_BIN, R, state->curveparams);

	if (!(ac = aes256ctr_init(keybuf))) {
		__warning("Cannot initialize AES256-CTR");
		goto bailout;
	}
	if (!(hmacsha256_init(&digest, keybuf + 32, HMAC_KEY_SIZE))) {
		__warning("Couldn't initialize HMAC-SHA256");
		goto bailout;
	}

	rc = ecc_new_data();
	/*
	 * The data buffer should be in three sections:
	 *    - rbuffer
	 *    - cipher
	 *    - hmac
	 */
	rc->data = (void *)(malloc( 
			(sizeof(char) * state->curveparams->pk_len_bin) + 
			(sizeof(char) * databytes) +
			(sizeof(char) * DEFAULT_MAC_LEN)));

	plaintext = (void *)(malloc(sizeof(char) * databytes));
	memcpy(plaintext, data, databytes);

	aes256ctr_enc(ac, plaintext, databytes);
	aes256ctr_done(ac);

	gcry_md_final(digest);
	md = (char *)(gcry_md_read(digest, 0));

	/* 
	 * Overlay the three segments for the data buffer via memcpy(3)
	 */
	memcpy(rc->data, readbuf, state->curveparams->pk_len_bin);
	offset = state->curveparams->pk_len_bin;
	
	memcpy((char *)(rc->data) + offset, plaintext, databytes);
	offset += databytes;

	memcpy((char *)(rc->data) + offset, md, DEFAULT_MAC_LEN);
	offset += DEFAULT_MAC_LEN;

	rc->datalen = offset;

	free(plaintext);
	gcry_md_close(digest);

	bailout:
		gcry_free(keybuf);
		point_release(P);
		point_release(R);
		free(P);
		free(R);
		free(readbuf);
	exit:
		return rc;
}

ECC_Data ecc_sign(char *data, ECC_KeyPair keypair, ECC_State state)
{
	ECC_Data rc = NULL;
	gcry_md_hd_t digest;
	gcry_error_t err;
	gcry_mpi_t signature = NULL;
	char *digest_buf, *serialized;

	/* 
	 * Preliminary argument checks, just for sanity of the library 
	 */
	if (!data) {
		__warning("Invalid or empty `data` argument passed to ecc_sign()");
		goto exit;
	}
	if (!__verify_keypair(keypair, true, false)) {
		__warning("Invalid ECC_KeyPair object passed to ecc_sign()");
		goto exit;
	}
	if (!__verify_state(state)) {
		__warning("Invalid or uninitialized ECC_State object");
		goto exit;
	}

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
	serialized = (char *)(malloc(sizeof(char) * 
			(1 + state->curveparams->sig_len_compact)));

	serialize_mpi(serialized, state->curveparams->sig_len_compact, 
			DF_COMPACT, signature);
	serialized[state->curveparams->sig_len_compact] = '\0';
	rc->data = serialized;
	
	bailout:
		gcry_mpi_release(signature);
		gcry_md_close(digest);
	exit:
		return rc;
}

bool ecc_verify(char *data, char *signature, ECC_KeyPair keypair, ECC_State state)
{
	bool rc = false;
	struct affine_point _ap;
	gcry_error_t err;
	gcry_mpi_t deserialized_sig;
	gcry_md_hd_t digest;
	char *digest_buf = NULL;
	int result = 0;

	/*
	 * Preliminary argument checks, just for sanity of the library
	 */
	if ( (data == NULL) ) {
		__warning("Invalid or empty `data` argument passed to ecc_verify()");
		goto exit;
	}
	if ( (signature == NULL) || (strlen(signature) == 0) ) {
		__warning("Invalid or empty `signature` argument passed to ecc_verify()");
		goto exit;
	}

	if (!__verify_keypair(keypair, false, true)) {
		__warning("Invalid ECC_KeyPair object passed to ecc_verify()");
		goto exit;
	}
	if (!__verify_state(state)) {
		__warning("Invalid or uninitialized ECC_State object");
		goto exit;
	}

	if (!decompress_from_string(&_ap, keypair->pub, DF_COMPACT, 
			state->curveparams)) {
		__warning("Your public key appears invalid");
		goto exit;
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
	exit:
		return rc;
}
