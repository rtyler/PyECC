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

#include <stdbool.h>


/**
 * Required version of libgcrypt for libecc to function
 */
#define REQUIRED_LIBGCRYPT "1.4.1"

/**
 * ::ECC_KeyPair denotes a structure to hold the public/private
 * keys necessary for ECC sign/verify/encrypt and decrypting.
 */
struct _ECC_KeyPair {
	void *priv;
	void *pub;
};
typedef struct _ECC_KeyPair* ECC_KeyPair;

/**
 * ::ECC_Data is simply a shortcut to an allocated void pointer
 */
struct {
	void *data;
} _ECC_Data;
typedef struct _ECC_Data ECC_Data;


/**
 * Allocate an empty ::ECC_KeyPair
 */
ECC_KeyPair ecc_new_keypair(void);


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
 */
ECC_KeyPair ecc_keygen(void *priv);


/**
 * Encrypt the specified block of data using the public key specified
 *
 * @return An allocated buffer with the encrypted data 
 */
ECC_Data ecc_encrypt(void *data, ECC_KeyPair keypair);


/**
 * Decrypt the specied block of data using the private key specified
 *
 * @return An allocated buffer with the decrypted data
 */
ECC_Data ecc_decrypt(void *encrypted, ECC_KeyPair keypair);


/**
 * Sign the specified block of data using the private key specified
 *
 * @return An allocated buffer with the signature of the data block
 */
ECC_Data ecc_sign(void *data, ECC_KeyPair keypair);


/**
 * Verify the signature of the data block using the specified public key
 *
 * @return True/False
 */
bool ecc_verify(void *data, void *signature, ECC_KeyPair keypair);



#endif
