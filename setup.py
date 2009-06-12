import os
from distutils.core import setup, Extension

base_modules = [
    Extension('pyecc', [
            'seccure/libecc.c',
            'seccure/numtheory.c',
            'seccure/ecc.c',
            'seccure/serialize.c',
            'seccure/protocol.c',
            'seccure/curves.c',
            'seccure/aes256ctr.c',
            '_pyecc.c',
        ])
]

# if an extension is missing dependencies, distutils will attempt the build regardless
modules = filter(lambda m: reduce(lambda x, y: x and os.path.exists(y), m.depends, True), base_modules)
missing_modules = filter(lambda m: m not in modules, base_modules)
if missing_modules:
	print 'WARNING: Some Python modules are missing dependencies: %s' % ', '.join(map(lambda x: x.name, missing_modules))

setup(ext_modules=modules)


