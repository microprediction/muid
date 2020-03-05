Memorable Unique Identifiers
============================

.. toctree::
   :maxdepth: 2

This library generates unique identifiers whose hashes are memorable.

Documentation
=============

The READMEs at https://pypi.org/project/muid/ and
https://github.com/microprediction/muid are likely to be more up to date than this documentation.

Installation
============

    $ pip install muid

    >> import muid

Quickstart
==========

Let's generate an MUID

    key  = muid.muid4( min_len=6 )

    print( muid.mhash( key ) )

    print( muid.mnemonic( key ) )

Get the joke? MUIDs are "hash-memorable" UUIDs, meaning that if you stare at the hash for long enough you'll see a word or phrase.

Mining
======

More time on your hands?

     muid.mine(min_len=9)

and wait, and wait, cool identifiers to come in.

Verification
============

To verify that a key is hash-memorable:

    muid.mverify( key=key, min_len=4 ) )

Collisions
==========

The computational capacity required to create MUID collisions over any interval of time is at least as large as the computational capacity
that must be employed to create UUID collisions with any non-vanishing probability.

Short version: don't worry about it. See the README at
https://github.com/microprediction/muid for more remarks.
