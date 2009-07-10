/*
 *  seccure  -  Copyright 2009 B. Poettering
 *
 *  Maintained by R. Tyler Ballance <tyler@slide.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* 
 *   SECCURE Elliptic Curve Crypto Utility for Reliable Encryption
 *
 * Current homepage: http://slideinc.github.com/PyECC
 * Original homepage: http://point-at-infinity.org/seccure/
 *
 *
 * seccure implements a selection of asymmetric algorithms based on  
 * elliptic curve cryptography (ECC). See the manpage or the project's  
 * homepage for further details.
 *
 * This code links against the GNU gcrypt library "libgcrypt" (which
 * is part of the GnuPG project). Use the included Makefile to build
 * the binary.
 * 
 * Report bugs to: http://github.com/rtyler/PyECC/issues
 */




#ifndef INC_SERIALIZE_H
#define INC_SERIALIZE_H

#include <gcrypt.h>

enum disp_format { DF_BIN, DF_COMPACT };

#define COMPACT_DIGITS_COUNT 90
extern const char compact_digits[];

int get_serialization_len(const gcry_mpi_t x, enum disp_format df);
void serialize_mpi(char *outbuf, int outlen, enum disp_format df, 
		   const gcry_mpi_t x);
int deserialize_mpi(gcry_mpi_t *x, enum disp_format ds, const char *buf, 
		    int inlen);

#endif /* INC_SERIALIZE_H */
