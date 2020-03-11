Memorable Unique Identifiers
============================

.. toctree::
   :maxdepth: 2

This library generates unique identifiers whose hashes are memorable.

Quickstart
===========

If you cut and paste the following at the terminal it will mine for MUIDs and explain itself along the way

     /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/microprediction/muid/master/examples/mine_from_venv.sh)"

Better docs
===========

The READMEs at https://pypi.org/project/muid/ and
https://github.com/microprediction/muid tend to be more up to date than this documentation.


Installation
============

    $ pip install muid

    >> import muid

Quickstart
==========

Let's generate an MUID

    key  = muid.muid4( min_len=6 )

    print( muid.mhash( key ) )

Get the joke? MUIDs are "hash-memorable" UUIDs, meaning that if you stare at the hash for long enough you'll see a word or phrase.

Mining MUIDs
============

More time on your hands?

     muid.mine()

and wait, and wait, cool identifiers to come in. At time of writing
it was possible to sell MUIDs with difficulty 11 for 7c a pop. Or you could find
a talented person with latent mathematical talent and make their day - they will
be able to participate at www.microprediction.com without waiting.

Comparison to bitcoin economics
===============================

Probably highly favourable, probably by one or two orders of magnitude. Detailed calculations comparing bitcoin mining and MUID mining economics can be
found at https://github.com/microprediction/muid/blob/master/muid/economics.py

Collisions
==========

Ain't gonna happen.

The computational capacity required to create MUID collisions over any interval of time is at least as large as the computational capacity
that must be employed to create UUID collisions with any non-vanishing probability.
