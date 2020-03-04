Memorable Unique Identifiers
============================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Quickstart
==========

This library generates unique identifiers whose hashes are memorable

    from muid.memorable import muid4

    key  = muid4()

The call to muid4 may take ten minutes or so. Is it worth it? Depends. 

Readable, Memorable hashes
==========================

Here is an example of the hash of a memorable unique identifier:

    f01dab1e-ca70-403a-a0c7-00f6c29596c4
    
If you stare at it you'll see the first part of the hash is borderline readable. We can make it
more readable with a few character swaps, namely swapping l for 1, s for 5, t for 7 and o for 0 to get:
 
    foldable-cato-4o3a-aoct-oof6c29596c4
    
Finally, we can use mpretty() to extract the mnemonic:

    Foldable Cat  
    
which, you may agree, is hard to forget. The last call benefits
from the supplied corpus of readable hex scrabble words.

Thus although memorable UUID's are an oxymoron, the first part
of the hash can be memorable without jeopardizing collision probabilities in any really serious way. 


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
