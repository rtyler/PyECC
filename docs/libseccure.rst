libseccure
===========

**libseccure** is a small, portable C library that handles abstracting much of the 
work involved with :abbr:`ECC (Elliptical Curve Crypto)`. 

Constants
----------

.. _DEFAULT_CURVE:

**DEFAULT_CURVE**:  `p384`

.. _DEFAULT_MAC_LEN:

**DEFAULT_MAC_LEN**:  `10`


Datatypes
---------

.. _ECC_State:

**ECC_State**

The ECC_State_ object is passed from function to function in order to ensure some 
information about the curves, the state of the libgcrypt memory pools, etc are 
accessible.

* **bool** *gcrypt_init*: set to `true` if the libgcrypt memory pool(s) and number generators have been properly initialized
* ECC_Options_ *options*: defaults to `NULL` but can be filled with an allocated ECC_Options_ object 
* **struct curveparams *** *curveparams*: allocated `curveparams` structure, the contents of this struct are dependent on the curve loaded (defaults to DEFAULT_CURVE_)

.. _ECC_Options:

**ECC_Options**

* **char *** *curve*: string representation of the curve to use, defaults to DEFAULT_CURVE_
* **bool** *secure_random*: enable/disable libgcrypt's secure random number generator (defaults to `true`)

.. _ECC_KeyPair:

**ECC_KeyPair**

* **gcry_mpi_t** *priv*: numeric representation of the private key, use ecc_new_keypair_ to properly generate this
* **void *** *pub*: binary data representing the public key
* **unsigned int** *pub_bytes*: number of bytes the *pub* member contains (as it's not `NULL` terminated)

.. _ECC_Data:

**ECC_Data**

* **void *** *data*: generic pointer referncing the memory containing data
* **unsigned int** *datalen*: number of bytes the *data* member contains


Internal Functions
------------------
.. _ecc_new_state:

**ecc_new_state(** ECC_Options_ `options` **)**

.. _ecc_free_state:

**ecc_free_state(** ECC_State_ `state` **)**

.. _ecc_new_keypair:

**ecc_new_keypair(** **char *** `publickey`, **char *** `privatekey`, ECC_State_ `state` **)**

.. _ecc_free_keypair:

**ecc_free_keypair(** ECC_KeyPair_ `keypair` **)**

.. _ecc_new_options:

**ecc_new_options(void)**

.. _ecc_new_data:

**ecc_new_data(void)**

.. _ecc_free_data:

**ecc_free_data(** ECC_Data_ `data` **)**

Crypto Functions
----------------

.. _ecc_mpi_to_str:

**ecc_mpi_to_str(** **gcry_mpi_t** `key` **)**

.. _ecc_serialize_private_key:

**ecc_serialize_private_key(** ECC_KeyPair_ `keypair`, ECC_State_ `state` **)**

.. _ecc_encrypt:

**ecc_encrypt(** **void *** `data`, **int** `datalen`, ECC_KeyPair_ `keypair`, ECC_State_ `state` **)**

.. _ecc_decrypt:

**ecc_decrypt(** ECC_Data_ `data`, ECC_KeyPair_ `keypair`, ECC_State_ `state` **)**

.. _ecc_sign:

**ecc_sign(** **char *** `data`, ECC_KeyPair_ `keypair`, ECC_State_ `state` **)**

.. _ecc_verify:

**ecc_verify(** **char *** `data`, **char *** `signature`, ECC_KeyPair_ `keypair`, ECC_State_ `state` **)**
