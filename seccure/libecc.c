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

#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>

#include "ecc.h"
#include "libecc.h"


/**
 * Handle initializing libgcrypt and some other preliminary necessities
 */
bool __init_ecc() 
{

	return false;
}

ECC_KeyPair ecc_new_keypair()
{
	ECC_KeyPair kp = (ECC_KeyPair)(malloc(sizeof(struct _ECC_KeyPair)));
	bzero(kp, sizeof(struct _ECC_KeyPair));
	return kp;
}

bool ecc_verify(void *data, void *signature, ECC_KeyPair keypair)
{
	return false;
}
