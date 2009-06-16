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
    fprintf(stderr, "Freeing state object at %p\n", _state);
    ecc_free_state((ECC_State)(_state));
    Py_INCREF(Py_None);
    return Py_None;
}

static char new_state_doc[] = "\
Generate a new ECC_State object that will ensure the \
libgcrypt state necessary for crypto is all set up and \
ready for use\n\
";
static PyObject *new_state(PyObject *self, PyObject *args, PyObject **kwargs)
{
    ECC_State state = ecc_new_state(NULL);
    fprintf(stderr, "Created state object at %p\n", state);

    PyObject *rc = PyCObject_FromVoidPtr(state, _release_state);
    if (!PyCObject_Check(rc)) {
        if (state)
            ecc_free_state(state);
        return NULL;
    }
    return rc;
}

static struct PyMethodDef _pyecc_methods[] = {
    {"new_state", new_state, METH_NOARGS, new_state_doc},
    {NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC init_pyecc(void)
{
    PyECC_KeyPairType.tp_new = PyType_GenericNew;
    PyECC_ECCType.tp_new = PyType_GenericNew;

    if (PyType_Ready(&PyECC_KeyPairType) < 0)
        return;
    if (PyType_Ready(&PyECC_ECCType) < 0)
        return;

    PyObject *module = Py_InitModule3("_pyecc", _pyecc_methods, pyecc_doc);

    Py_INCREF(&PyECC_ECCType);
    PyModule_AddObject(module, "ECC", (PyObject *)(&PyECC_ECCType));

    Py_INCREF(&PyECC_KeyPairType);
    PyModule_AddObject(module, "PyECC_KeyPair", (PyObject *)(&PyECC_KeyPairType));
}
