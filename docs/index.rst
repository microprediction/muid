Memorable Unique Identifiers
============================

.. toctree::
   :maxdepth: 2

This library generates unique identifiers whose hashes are memorable

Installation
============

    >> pip install muid

Quickstart
==========

    >> from muid.memorable import muid4

    >> key  = muid4( min_len=4 )

Readable, Memorable hashes
==========================

I'm not going to show you the result as it is private, but I don't mind showing you a hash of it:

    >> from muid.memorable import mhash

    >> code = mhash( key )

    >> print( code)

    f01dab1e-ca70-403a-a0c7-00f6c29596c4

Since this is a public quantity it might as well be partially memorable. Well, it is! Stare at the first part
of the hash and you'll see it is borderline readable. It is more readable yet with
a few character swaps, namely exchanging l for 1, s for 5, t for 7 and o for 0.

    >> from muid.memorable import Memorable

    >> readable = Memorable.to_readable_hex(code)

    >> print(readable)

    foldable-cato-4o3a-aoct-oof6c29596c4
    
The astute reader will surmise that we used muid(min_len=11) to create this example.

Pretty
======

If we really want, we can use the corpus to extract only the part of the hash and make that even prettier.

    >> long = Memorable.longest_word_or_phrase(readable)

    >> pretty = Memorable.pretty(long)

    >> print(pretty)

    'Foldable Cat'
    
which, you may agree, is hard to forget.

Thus although memorable UUID's are an oxymoron, the first part
of the hash can be memorable without jeopardizing collision probabilities in any really serious way. 

Mining
======

Who doesn't want identifiers with pretty hashes? The current rate for mining cute memorable identifiers is probably much higher than bitcoin. So..

     from muid.memorable import mine

     mine()

and wait, and wait, and wait for the cool identifiers to come in.

Verification
============

To verify that a key was generated in this fashion,

    >> from muid.memorable import mverify

    >> print( mverify( key=key, min_len=4 ) )

    True