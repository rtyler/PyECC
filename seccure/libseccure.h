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

#ifndef _LIBECC_H_
#define _LIBECC_H_

#include <gcrypt.h>
#include <stdbool.h>


/**
 * Required version of libgcrypt for libecc to function
 */
#define REQUIRED_LIBGCRYPT "1.4.1"

/**
 * Default curve to use when encrypting, etc
 */
#define DEFAULT_CURVE "p160"
#define DEFAULT_MAC_LEN 10


/**
 * ::ECC_KeyPair denotes a structure to hold the public/private
 * keys necessary for ECC sign/verify/encrypt and decrypting.
 */
struct _ECC_KeyPair {
	gcry_mpi_t priv;
	void *pub;
	unsigned int pub_len;
};
typedef struct _ECC_KeyPair* ECC_KeyPair;

/**
 * ::ECC_Data is simply a shortcut to an allocated void pointer
 */
struct _ECC_Data {
	void *data;
	unsigned int datalen;
};
typedef struct _ECC_Data* ECC_Data;

/**
 * ::ECC_Options is a container for options some ecc_ functions
 *
 */
struct _ECC_Options {
	char *curve; /*!< curve will be defaulted to ::DEFAULT_CURVE by ecc_new_options() */
	bool secure_random; /*!< secure_random enables libgcrypt's secure random number generator, default true */
}; 
typedef struct _ECC_Options* ECC_Options;

/**
 * ::ECC_State is a bag of useful bits for maintaining cross-function state
 */
struct _ECC_State {
	bool gcrypt_init;
	ECC_Options options;
	struct curve_params *curveparams;
};
typedef struct _ECC_State* ECC_State;


/**
 * Allocate an empty ::ECC_KeyPair
 */
ECC_KeyPair ecc_new_keypair(char *pubkey, char *privkey, ECC_State state);
/**
 * Free and release an ::ECC_KeyPair
 */
void ecc_free_keypair(ECC_KeyPair kp);
/**
 * Allocate an empty ::ECC_Data
 */
ECC_Data ecc_new_data(void);
/**
 * Free and release an ::ECC_Data object
 */
void ecc_free_data(ECC_Data data);
/**
 * Allocate an empty ::ECC_Options
 *
 * ecc_new_options() will fill out a few default values for the options
 * object after allocation and prior to returning the object
 */
ECC_Options ecc_new_options(void);
/**
 * Allocate an empty ::ECC_State
 */
ECC_State ecc_new_state(ECC_Options opts);
/**
 * Free and release an ::ECC_state object
 */
void ecc_free_state(ECC_State state);


/**
 * Generate an ECC public/private key pair
 *
 * If the "priv" parameter isn't passed, then ecc_keygen() will generate
 * it's own private key via some other source of entropy and then return
 * the allocated key in the ::ECC_KeyPair
 *
 * @return ECC_KeyPair 
 * @param priv Specify NULL to generate a random private key, otherwise string.
 * You will be responsible for deallocating "priv" yourself, if not-NULL then
 * the contents of the buffer will be copied into a new buffer
 * @param state ::ECC_State object
 */
ECC_KeyPair ecc_keygen(void *priv, ECC_State state);


/**
 * Encrypt the specified block of data using the public key specified
 *
 * @return An allocated buffer with the encrypted data 
 */
ECC_Data ecc_encrypt(void *data, int databytes, ECC_KeyPair keypair, ECC_State state);


/**
 * Decrypt the specied block of data using the private key specified
 *
 * @return An allocated buffer with the decrypted data
 */
ECC_Data ecc_decrypt(ECC_Data encrypted, ECC_KeyPair keypair, ECC_State state);


/**
 * Sign the specified block of data using the private key specified
 *
 * @return An allocated buffer with the signature of the data block
 * @param data An allocated buffer to generate a signature against
 * @param keypair ::ECC_KeyPair to use when generating the signature 
 * (only needs "priv" member to contain data)
 * @param state ::ECC_State object
 */
ECC_Data ecc_sign(char *data, ECC_KeyPair keypair, ECC_State state);


/**
 * Verify the signature of the data block using the specified public key
 *
 * @return True/False
 * @param data An allocated buffer against which to verify the signature
 * @param signature The ECC generated signature 
 * @param keypair ::ECC_KeyPair object (only needs the "pub" member to contain data)
 * @param state ::ECC_State object
 */
bool ecc_verify(char *data, char *signature, ECC_KeyPair keypair, ECC_State state);

#endif
