/*
 *  pyecc - Copyright 2009 Slide, Inc.
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
#include <string.h>

#include "_pyecc.h"

static char pyecc_doc[] = "\
The _pyecc module provides underlying C hooks for the \
\"pyecc\" module\n\n\
Refer to the pyecc documentation for it's use as \
_pyecc is not intended for public consumption as \
it does not provide the proper wrapper and object-\
oriented support that the pyecc module does\n\
";



static char new_state_doc[] = "\
Generate a new ECC_State object that will ensure the \
libgcrypt state necessary for crypto is all set up and \
ready for use\n\
";
static void *_release_state(void *_state)
{
    if (_state)
        ecc_free_state((ECC_State)(_state));
    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject *py_new_state(PyObject *self, PyObject *args, PyObject *kwargs)
{
    ECC_State state = ecc_new_state(NULL);

    PyObject *rc = PyCObject_FromVoidPtr(state, _release_state);
    if (!PyCObject_Check(rc)) {
        if (state)
            ecc_free_state(state);
        return NULL;
    }
    return rc;
}



static char new_keypair_doc[] = "\
Return a new ECC_KeyPair object that will contain the appropriate \
references to the public and private keys in memory\n\
";
static void *_release_keypair(void *_keypair)
{
    if (_keypair) {
        ECC_KeyPair kp = (ECC_KeyPair)(_keypair);
        if (kp->priv) {
            free(kp->priv);
        }
        if (kp->pub) {
            free(kp->pub);
        }
        free(kp);
    }
    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject *py_new_keypair(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *privkey, *temp_pubkey, *pubkey;
    PyObject *temp_state;
    ECC_State state;
    int pubkeylen = 0;

    if (!PyArg_ParseTuple(args, "s#sO", &temp_pubkey, &pubkeylen, 
                &privkey, &temp_state))
        return NULL;

    if (pubkeylen < 1)
        return NULL;

    pubkey = (char *)(malloc(sizeof(char) * pubkeylen + 1));
    memcpy(pubkey, temp_pubkey, pubkeylen + 1);
    
    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));

    ECC_KeyPair kp = ecc_new_keypair(pubkey, privkey, state);

    PyObject *rc = PyCObject_FromVoidPtr(kp, _release_keypair);
    if (!PyCObject_Check(rc)) {
        if (kp)
            _release_keypair(kp);
        return NULL;
    }
    return rc;
}


static char verify_doc[] = "\
Verify that the specified data matches the given signature \
and vice versa. Should return a True/False depending on the \
success of the verification call\n\
";
static PyObject *py_verify(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *temp_state, *temp_keypair;
    ECC_State state;
    ECC_KeyPair keypair;
    char *data, *signature;

    if (!PyArg_ParseTuple(args, "ssOO", &data, &signature, &temp_keypair,
            &temp_state)) {
        return NULL;
    }

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    keypair = (ECC_KeyPair)(PyCObject_AsVoidPtr(temp_keypair));

    if (ecc_verify(data, signature, keypair, state)) 
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static struct PyMethodDef _pyecc_methods[] = {
    {"new_state", py_new_state, METH_NOARGS, new_state_doc},
    {"new_keypair", py_new_keypair, METH_VARARGS, new_keypair_doc},
    {"verify", py_verify, METH_VARARGS, verify_doc},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC init_pyecc(void)
{
    PyObject *module = Py_InitModule3("_pyecc", _pyecc_methods, pyecc_doc);
}
