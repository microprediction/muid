

EXPLANATION = ["This script runs a mining routine from the MUID package, available at https://pypi.org/project/muid/",
            "If at any point you feel uncomfortable just Control-C",
            "                   ",
            "The script searches for hash-memorable keys",
            "A hash-memorable key is a unique identifier - which is to say a long randomly generated string representing a hexidecimal number",
            "Such as 683697d0c930403aa0c700f6c29596c4"
            "However a hash-memorable key, as the name suggests, has another property which makes it hard to find",
            "To explain, we introduce a hash function that takes one hex number and turns it into another",
            "For example, ",
            "  ",
            "Most of the time the second string will be gibberish, just like the first.",
            "But sometimes ...",
            "...if you are lucky ...",
            "...the second string will try to tell you something about yourself.",
            "It will reveal your spirit animal.",
            " ",
            "Don't believe me?",
            "Here's an example",
            " ",
            " "
            "Or at least the first part of it does",
            "The first dozen characters (say) comprise two words describing an animal",
            "The spirit animal, shall we say, becomes your nom de plume should you wish to participate in at www.microprediction.com",
            "   ",
            "More on that in a minute",
            "    ",
            "But first a brief aside for those unfamiliar with hashes, or similar uses or hashes (like bitcoin mining).",
            "A hash is a just a function that is almost impossible to invert. See https://en.wikipedia.org/wiki/Hash_function",
            "This script does nothing but generate a vast number of random hexadecimal numbers in the hope that the hash function, when applied to them, accidentally produces a recognizable string",
            "Actually the strings aren't that recognizable unless you squint, and replace digits with letters (like 0->o, 7->t and so forth)",
            "We've introduced the notion of readable hex, in this manner.",
            "And to save your eyesight we'll print the translation of the leading part of the hashed key.",
            "  ",
            "For example 'Foldable Cat' looks better than f01dab1eca7",
            "  ",
            "The most important thing about your spirit animal, in this example 'Foldable Cat', is the sum of the lengths of the two words",
            "In this case the sum is 11 and this is called the length",
            "Very imaginative terminology, no?",
            " ",
            "Well the length, sometimes called the difficulty (to confuse the bitcoin folks) is important.",
            "Maybe not as important as your liking your spirit animal, but the length determines its utilitarian value.",
            "          ",
            "Which brings us to the motivation for running this script",
            "    ",
            "Why would you want hash-memorable keys?",
            "    ",
            "Good question",
            "      ",
            "Bit of a long answer",
            "  ",
            "The short version is this: there's a microprediction web coming",
            "The microprediction web will, asymptotically, make bespoke AI cheap and ubiquitous ... though it will have humble beginnings",
            "A microprediction web will make consulting companies, artisan data scientists, and overpaid pompous managers about as relevant to model and data search as the librarian who didn't help you find this script.",
            " ",
            "We like librarians ... but there is a message in the plot here:  https://blog.oup.com/2011/06/librarian-census/    ",
            "And more importantly there is a rather obvious contradiction at the heart of the so-called AI revolution",
            " ",
            "The contradiction runs as follows:",
            "   ",
            "   (A) The Machine Learning revolution is 'just' a bunch of problems where there is sufficient data to distinguish good from bad models by means of a simple score",
            "       Of course it is also a bunch of very clever work ... not downplaying that at all ... ",
            "          ... but ... ",
            "   (B) It also comprises a flood with mind-numbingly stupid powerpoint slides written by recent applied statisticians. ",
            "       Who claim that their human ability to manage the production of prediction is essential ",
            "  ",
            " We say: nonsense. If there is enough data to distinguish good models from bad, the machines should be managing the humans and not the other way around.",
            " At least for a class of problems so defined, which we term 'microprediction' ",
            " Which is not to be confused with predicting singular events like the outcome of the 2020 US election. ",
            " ",
            "Anyway, thankfully this script is helping in some small way",
            "By running it you are not just sitting on your hands ",
            "You are helping to stop the proliferation of expensive cold-start data science.",
            "You are taking a stand against the quaint aspirations of so-called 'number scientists'.",
            "You are helping in some small way mage progress towards affordable bespoke AI for small to medium size enterprises.",
            "You are helping in some small way to address a tragedy of the commons: the lack of a common realtime feature space.",
            "Which would have been really useful when Corono took off now, it must be admitted.",
            "That's all because hash-memorable keys carry special significance at www.microprediction.com, humble birthplace of the predictino web.",
            "The keys serve as an entry ticket, one you - or someone you kindsly donate your key to - can use in two ways.",
            "    ",
            "   (1) They enable you to enter realtime statistical prediction contests. The more difficult your key, the greater drawdown leeway you will be granted.",
            "       That's a nice way of saying that you are less likely to be kicked out because your key is declared bankrupt",
            "     ",
            "   (2) Keys enable you to ask other people and algorithms to predict live data that you care about",
            "       That can be anything at all.",
            "       But more difficult the key you supply, the more accurate the predictions will be.",
            "       That's because self-navigating automated prediction algorithms, and human guided models, are more likely to find their way to your data stream and"
            "       when they get there, will have have more incentive to fight.",
            "      ",
            "Now as a small technical matter, www.microprediction.com isn't quite operational yet.",
            "But it is close ... probably April 1, 2020 ... but don't hold me to it",
            "So we are allowing you to run this script now because it can take weeks to mine a really valuable key.",
            "By the way, no harm in running this on multiple terminals, but we thought it would be rude to take all your processors without asking",
            "   ",
            "Oh wait I know what you are thinking ...",
            "What if I don't care about microprediction or statistics or AI or whatever and I just want to mine",
            "Will this be more economical than mining bitcoin?",
            "    ",
            "A moment's reflection might convince you that is the case, assuming ",
            "... the monetary rewards at www.microprediction.com are going to be serious",
            "... because at least one top tier investment company intends to use microprediction.com for a variety of purposes",
            "... and it is likely to be useful for many businesses",
            "It seems plausible that some participants may be impatient",
            "... and less prescient than yourself",
            "... and thus your longer keys may be valuable to them",
            "... but we can't make any promises",
            "... though we might in the near future provide an API where you can sell keys you don't want",
            "... maybe.  ",
            " ",
            "Anyway, thanks for listenning.",
            "Next time run python3 -c 'from muid import mine; mine(skip_intro=True)' to avoid this rant and the install",
            "Here come your keys and corresponding spirit animals. ",
            "   ",
           ]
