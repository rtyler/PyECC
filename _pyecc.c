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

#include "_pyecc.h"

static char pyecc_doc[] = "\
The _pyecc module provides underlying C hooks for the \
\"pyecc\" module\n\n\
Refer to the pyecc documentation for it's use as \
_pyecc is not intended for public consumption as \
it does not provide the proper wrapper and object-\
oriented support that the pyecc module does\n\
";


static void *_release_state(void *_state)
{
    if (_state)
        ecc_free_state((ECC_State)(_state));
    Py_INCREF(Py_None);
    return Py_None;
}

static char new_state_doc[] = "\
Generate a new ECC_State object that will ensure the \
libgcrypt state necessary for crypto is all set up and \
ready for use\n\
";
static PyObject *new_state(PyObject *self, PyObject *args, PyObject *kwargs)
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

static void *_release_keypair(void *_keypair)
{
    if (_keypair) {
        ECC_KeyPair kp = (ECC_KeyPair)(_keypair);
        if (kp->priv)
            free(kp->priv);
        /* We're assuming this was setup as a PyStringObject */
        if (kp->pub) 
            Py_DECREF((PyStringObject *)(kp->pub));
        free(kp);
    }
    Py_INCREF(Py_None);
    return Py_None;
}

static char new_keypair_doc[] = "\
Return a new ECC_KeyPair object that will contain the appropriate \
references to the public and private keys in memory\n\
";
static PyObject *new_keypair(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char *privkey;
    /* 
     * Pulling the public key coming from Python into a PyStringObject
     * instead of copying the contents of the buffer into a newly allocated
     * buffer (Py_DECREF() will be called in _release_keypair)
     */
    PyStringObject *pubkey;
    PyObject *temp_state;
    ECC_State state;

    if (!PyArg_ParseTuple(args, "SsO", &pubkey, &privkey, &temp_state))
        return NULL;

    state = (ECC_State)(PyCObject_AsVoidPtr(temp_state));
    Py_INCREF(pubkey);

    ECC_KeyPair kp = ecc_new_keypair(pubkey, privkey, state);

    PyObject *rc = PyCObject_FromVoidPtr(kp, _release_keypair);
    if (!PyCObject_Check(rc)) {
        if (kp)
            _release_keypair(kp);
        return NULL;
    }
    return rc;
}

static struct PyMethodDef _pyecc_methods[] = {
    {"new_state", new_state, METH_NOARGS, new_state_doc},
    {"new_keypair", new_keypair, METH_VARARGS, new_keypair_doc},
    {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC init_pyecc(void)
{
    PyObject *module = Py_InitModule3("_pyecc", _pyecc_methods, pyecc_doc);
}
