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

Mining and selling MUIDs
========================

More time on your hands?

     muid.mine()

and wait, and wait, cool identifiers to come in. At time of writing
it was possible to sell MUIDs with difficulty 11 for 7c a pop at https://algorithmia.com/algorithms/microprediction/mverify/docs ... but you'll
first need to sign up for a free Algorithmia account at http://www.algorithmia.com/signup. If you'd like to
mine and sell automatically check out https://github.com/microprediction/muid/blob/master/examples/mining_example.py and modify as you see fit.

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
