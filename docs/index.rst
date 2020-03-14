Memorable Unique Identifiers
============================

.. toctree::
   :maxdepth: 2

This library generates unique identifiers whose hashes are memorable.

Quickstart
===========

If you cut and paste the following at the terminal it will mine for MUIDs and explain itself along the way

     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/microprediction/muid/master/examples/mine_from_venv.sh)"

If it fails you might need Python 3

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew install python

Explanatory video
=================

https://vimeo.com/397352413

Installation
============

    $ pip install muid

Hash-memorability
=================

    >>> muid.bhash(b'f601f291896bb66b8a3c3d783077713a')
        b'56a33411a3ae7cfc95597911708358ad'

    Don't see it?

        >>> muid.pretty(b'56a33411a3ae7cfc95597911708358ad',k1=6,k2=5)
        'Shammy Llama'

Validation
==========

    >>> muid.animal(b'f601f291896bb66b8a3c3d783077713a')
    'Shammy Llama'

    >>> muid.validate(b'f601f291896bb66b8a3c3d783077713a')
    True

Mining
======

    >>> muid.mine()
    {'hash': b'56a33411a3ae7cfc95597911708358ad',
    'key': b'f601f291896bb66b8a3c3d783077713a',
    'length': 11,
    'pretty': 'Shammy Llama'}

Bequeath unwanted MUIDs to a worthy statistician.

Applications
============

See the video at https://vimeo.com/397352413 for some motivation.

We hope you have an application that can benefit from one less join.

Implementation decisions
========================

We welcome thoughtful suggestions at https://github.com/microprediction/muid/issues

We truncate the output of hashlib.sha256

Collisions
==========

MUID collision requires approximately the same computational capacity as UUID collision or more.

Stupid dog trick
================

https://vimeo.com/396819347
