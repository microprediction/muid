
TITLE = """                         
         __    __     __    __    _____   ______              
         \ \  / /     ) )  ( (   (_   _) (_  __ \             
         () \/ ()    ( (    ) )    | |     ) ) \ \            
         / _  _ \     ) )  ( (     | |    ( (   ) )           
        / / \/ \ \   ( (    ) )    | |     ) )  ) )           
       /_/      \_\   ) \__/ (    _| |__  / /__/ /            
      (/          \)  \______/   /_____( (______/             
                                
             Memorable Unique Identifiers                                                
   __    __      _____      __      _    _____   ______       
   \ \  / /     (_   _)    /  \    / )  / ___/  (   __ \      
   () \/ ()       | |     / /\ \  / /  ( (__     ) (__) )     
   / _  _ \       | |     ) ) ) ) ) )   ) __)   (    __/      
  / / \/ \ \      | |    ( ( ( ( ( (   ( (       ) \ \  _     
 /_/      \_\    _| |__  / /  \ \/ /    \ \___  ( ( \ \_))    
(/          \)  /_____( (_/    \__/      \____\  )_) \__/                                             
                                              
           https://pypi.org/project/muid/
           
                 Mining has begun  
"""


EXPLANATION = ["This script runs a simple open source mining routine from the MUID package",
               "You can read the code at https://github.com/microprediction/muid ",
               "You should hear your laptop fan firing up.",
              "If at any point you feel uncomfortable, or your computer does, just Control-C",
              "Honestly you can probably run this script in half a dozen terminals without issue.",
               "We thought it would be rude to take all your processors without asking, however.",
               "                   ",
              "The script searches for hash-memorable keys",
              "This takes a while so the script is a little chatty, sorry.",
              "There is a video explaining MUIDS at https://vimeo.com/397352413 too.",
              " ",
              "A hash-memorable key is a unique identifier.",
              "Which is to say a long randomly generated string representing a hexidecimal number",
             "Such as 30599b096bc5751c311ea6e15e306c86",
             "Which might have been produced by a monkey sitting at 1/3 of a typewriter."
             " ",
             "Now a hash function takes one hex number and turns it into another",
             "A hash is a just a function that is almost impossible to invert.",
             "See https://en.wikipedia.org/wiki/Hash_function. We use SHA-256 truncated.",
             "The hash function might convert our key 30599b096bc5751c311ea6e15e306c86 ... ",
             "... into say 105ab1ef1ea6ab3e85743e028f42847e "
             "which looks like complete gibberish as well.",
             " ",
             "Except ...",
             "  ",
             "Once in a while ... ",
             "  ",
             "The hash of the key isn't completely random looking",
              "  ",
              "... something the astute reader might have noticed already",
              " ",
              "Take a second look at 105ab1ef1ea6ab3e85743e028f42847e ",
              "... and in particular the first 11 characters 105ab1ef1ea",
              "You'll notice the astronomical coincidence.",
              "The characters spell 'Losable Flea' ",
              "Sort of.",
              "Which means that the original key 30599b096bc5751c311ea6e15e306c86 is ...",
              "'hash-memorable', so to speak.",
              "It is a MUID",
              "Like a UUID - if you are familiar with https://docs.python.org/3/library/uuid.html",
              "Only better, clearly.",
              "  ",
             "This script does nothing but generate a vast number of random hexadecimal numbers,",
             "Eventually their hashes are recognizable strings although,",
             "as noted, the strings aren't that recognizable unless you squint,",
             "and replace digits with letters (like 0->o, 7->t and so forth).",
             "We've introduced the notion of readable hex, in this manner.",
             "The rules for coverting digits to letters are at https://pypi.org/project/muid/",
             "And to save your eyesight we'll print the translation,",
             "which is to say your spirit animal."
             "At times like this we all need a good spirit animal.",
             " ",
             "Why might hash-memorable keys be important?",
             "  ",
             "If you run this script some time after April 1st, or if you let it run long enough now ...",
              "... it may reveal some details of a novel use of MUIDs. ",
              "  ",
             "But perhaps you already have your own ideas for using them",
             "The key is typically intended to be private, but the hash can be public.",
             "Part of the hash includes a memorable identifier, of course, and thus ...",
             "... hash-memorable keys can be used to create applications with one less join, as it were.",
             "If you write applications, you might appreciate that.",
             "  ",
             "Now as it happens, this script has already generated lots of MUIDs for you,",
             "while simultaneously heating your home a little.",
             "In a moment you will be able to see some of them and choose your spirit animal.",
             "There are 422,013 possible non de plumes.",
             "If you do manage to generate an amusing spirit animal, by all means share it.",
             "You can post at https://www.quora.com/What-are-the-most-amusing-hash-memorable-identifiers-you-have-generated ",
             "Or vote there on your favourite hash-memorable key",
            "  ",
            "But first ... there is a minor technical thing you need to know.",
            "Before choosing 'Collosal Oca' or 'Foldable Cat' over 'Bleachable Crab' you should ...",
            "... observe that the first two are length 11 and the latter length 14.",
            "So while Foldable Cat is unequivocally funnier than Bleachable Crab ...",
            "Bleachable Crab is about four thousand times harder to find than Foldable Cat",
            "And in a very important but yet mysterious application to be revealed on April 1st, 2020 ... ",
            "Bleachable Crab, or rather any key that hashes to it, will be four thousand times more valuable."   
            "  ",
            "You are strongly advised to let the program run until Apr 1st and thereafter,",
             "so as to generate the longest possible MUID.",
            "Good MUIDs come to those who wait",
            "Check the length property of those that come out ...",
            "A length of 12 or higher is pretty useful ...",
            "These initial ones are just for fun.",
            "Keep going until you get some long ones.",
            "  ",
            "Here they come ...",
            "   "]

LEVEL12 = """
                     You have reached
██╗     ███████╗██╗   ██╗███████╗██╗          ██╗██████╗     ██╗
██║     ██╔════╝██║   ██║██╔════╝██║         ███║╚════██╗    ██║
██║     █████╗  ██║   ██║█████╗  ██║         ╚██║ █████╔╝    ██║
██║     ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║          ██║██╔═══╝     ╚═╝
███████╗███████╗ ╚████╔╝ ███████╗███████╗     ██║███████╗    ██╗
╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝     ╚═╝╚══════╝    ╚═╝                                        
        Well done. You are starting to unlock valuable keys.                     
"""

LEVEL13 = """

                                                   You have reached                                                                                                                    
                                                                                                                                              
LLLLLLLLLLL                                                                        lllllll        1111111    333333333333333         !!!  !!! 
L:::::::::L                                                                        l:::::l       1::::::1   3:::::::::::::::33      !!:!!!!:!!
L:::::::::L                                                                        l:::::l      1:::::::1   3::::::33333::::::3     !:::!!:::!
LL:::::::LL                                                                        l:::::l      111:::::1   3333333     3:::::3     !:::!!:::!
  L:::::L                   eeeeeeeeeeee  vvvvvvv           vvvvvvv eeeeeeeeeeee    l::::l         1::::1               3:::::3     !:::!!:::!
  L:::::L                 ee::::::::::::ee v:::::v         v:::::vee::::::::::::ee  l::::l         1::::1               3:::::3     !:::!!:::!
  L:::::L                e::::::eeeee:::::eev:::::v       v:::::ve::::::eeeee:::::eel::::l         1::::1       33333333:::::3      !:::!!:::!
  L:::::L               e::::::e     e:::::e v:::::v     v:::::ve::::::e     e:::::el::::l         1::::l       3:::::::::::3       !:::!!:::!
  L:::::L               e:::::::eeeee::::::e  v:::::v   v:::::v e:::::::eeeee::::::el::::l         1::::l       33333333:::::3      !:::!!:::!
  L:::::L               e:::::::::::::::::e    v:::::v v:::::v  e:::::::::::::::::e l::::l         1::::l               3:::::3     !:::!!:::!
  L:::::L               e::::::eeeeeeeeeee      v:::::v:::::v   e::::::eeeeeeeeeee  l::::l         1::::l               3:::::3     !!:!!!!:!!
  L:::::L         LLLLLLe:::::::e                v:::::::::v    e:::::::e           l::::l         1::::l               3:::::3      !!!  !!! 
LL:::::::LLLLLLLLL:::::Le::::::::e                v:::::::v     e::::::::e         l::::::l     111::::::1113333333     3:::::3               
L::::::::::::::::::::::L e::::::::eeeeeeee         v:::::v       e::::::::eeeeeeee l::::::l     1::::::::::13::::::33333::::::3      !!!  !!! 
L::::::::::::::::::::::L  ee:::::::::::::e          v:::v         ee:::::::::::::e l::::::l     1::::::::::13:::::::::::::::33      !!:!!!!:!!
LLLLLLLLLLLLLLLLLLLLLLLL    eeeeeeeeeeeeee           vvv            eeeeeeeeeeeeee llllllll     111111111111 333333333333333         !!!  !!! 
                                                
                                                                                                                                              
                                        You are now be the envy of your peers. 
                      Consider finding a budding statistician who may value the keys you have mined. 

"""


RANT =      ["   ",
             "   ",
            "Hello again.",
            "Your mining is going very well",
            "Things tend to slow down, don't they?",
            "Each level is 16 times harder than the last, but the MUIDs are 16 times more valuable as a result.",
            "   ",
            "So it isn't a waste of time that we are sitting here chatting.",
            "   ",
            "Or maybe you took the time to read the code on github. That's cool.",
            "Either way I think you deserve to know the true purpose of MUIDS",
            "      ",
            "So why MUIDs? ",
            "Simple. You need MUIDs to make use of the microprediction web. ",
            "   ",
            "Which doesn't exist yet, admittedly. ",
            "But when it does the MUIDs will provide mass, ",
            "just as a similar concept provides 'weight' for blockchain applications, preventing Cybil attacks.",
            "  ",
            "So why should you care about a microprediction web? ",
            "Right now?" 
            "    ",
            "Well, if you are clever you can forsee things that others cannot. ",
            "And this gives you an opportunity to get ahead of the game and pick up low fruit.",
            "Like 12 and 13 digit MUIDs for example",
            "Because by the time the utility of the prediction web is obvious to one and all, ",
            "it is going to be a lot harder to profit from running obscure scripts like this one." 
            "Instead you'll have to think a little about mathematics, ",
            "which won't kill you,",
            "but isn't quite as easy as this.",
            "   ",
            "We suggest that the microprediction web will prove valuable for many businesses ...",
            "... and profitable for smart people with good models and data ... ",
            "... so long as they can get hold of a good MUIDs to start playing.",
            "   ",
            "Before getting into the what, we mention the when.",
            "This prediction web we speak of will be born Apr 1st, 2020 at www.microprediction.com",
            "It will be far from perfect.",
            "But at least one major investment firm will use it immediately.",
            "   ",
            "Eventually - and of course this is more speculative ... ",
            "... prediction webs will have a big impact on commerce, including realtime operations.",
            "But not just commerce.",
            "The goal of a prediction web is to (asymptotically) render AI applications cheap and ubiquitous",
            "... even if they require bespoke prediction and decision making ",
            "... and obscure applied mathematical techniques mastered by few ",
            "... or data that might not be obviously related.",
            "  ",
            "Your goal should be to invent the microprediction web.",
            "While we sit here.",
            "   ",
            "It would be good if your microprediction web could perform 'search' better than hierarchies of people.",
            "By which we refer to search in the space of relevant models and data, not searching for your car keys.",
            "You should invent a microprediction web that will make consulting companies, artisan data scientists,",
            "and overpaid pompous managers ",
            "about as relevant to model and data search as ...",
            " ... librarians are to document search.",
            "   ",
            "Ouch. We like librarians ... but there is a message in the plot here:  https://blog.oup.com/2011/06/librarian-census/   ",
            "Look at the date of 'peak librarian', in particular.",
            "Document search was made possible by a collective undertaking known as ...",
            "... adding links to web pages!",
            "  ",
            "We think that when you invent the prediction web that should probably be part of your inspiration.",
            "Joint model and data search will be solved in a collective manner, assuredly ... ",
            "... eventually",
            "... and that might make data science management as you know it today look cumbersome ...",
            "... to put it mildly.",
            "   ",
            "Search will be solved by a network, or lattice if you will, of random variables.",
            "And that will look a lot different to ",
            "'Hey Sally', can you build a model for X please?",
            "Human managed data science is on the way out.",
            "Collective prediction orchestrated by lightweight market-inspired mechanism is on the way in.",
            "   ",
            "But with a hypothesis such as this, there is some visualization required.",
            "On your part.",
            "  ",
            "There is likely to a book on the topic, to be published by MIT Press next year.",
            "The book addresses some of the standard objections, such as privacy, although ... ",
            "... we've found that most people with mathematical training see around the objections rather easily.",
            "... and are confident you will too.",
            "For example, privacy is not continuous with respect to Haar measure. ",
            "  ",
            "A good way to invent the prediction web is to examine a contradiction at the heart of the so-called AI revolution.",
            "  ",
            "The contradiction runs approximately as follows:",
            "   ",
            "   (A) The Machine Learning revolution is 'just' a bunch of problems where there is sufficient data to distinguish good from bad models by means of a simple score",
            "       Of course it is also a bunch of very clever work ... not downplaying that at all ... ",
            "          ... but ... ",
            " ",
            "   (B) It also comprises a flood of mind-numbingly daft powerpoint slides written by recent applied statisticians. ",
            "       ... who claim that their human ability to manage the production of prediction is essential",
            "       ... including managing a newish type of statistics and emphasis",
            "       ... which is different to 'old' statistics/emphasis",
            "       ... because there is enough data for black/grey box approaches to be provably better than inference",
            "       ... because they can be assessed mechanically, for example by a simple score like RMSE.",
            "       ... and they are not limited by the lack of imagination us humans have for generative models.",
            "       ... and that's all true and for that matter widely observed since 2000 (e.g. Brieman)",
            "  ",
            "However this brings us to the contradiction. ",
            "    "
            "   (C) If it is really the case that mechanical assessment of model work is possible ",
            "       ... that opens up the possibility for vastly more efficient ways to orchestrate production ",
            "       ... which in turn is just Econ 101 (Hayek)",
            "       ... so long as you can reduce economic frictions of trade  (Coarse)",
            "       ... which is where the microprediction web enters the picture",
            "       ... as a lightweight market mechanism encouraging decentrally optimized supply chains for microprediction",
            "  ",
            "The microprediction web is somewhat subversive.",
            "Senior data scientists generally hate it.",
            "The microprediction web says to the AI industry: what a load of malarkey!",
             "If there is enough data to distinguish good models from bad, the machines should be managing the humans and not the other way around.",
            "At least for a class of problems so defined, which we term 'microprediction' ",
            "Which is not to be confused with predicting singular events like the outcome of the 2020 US election. ",
             "  ",
             "Have you invented the microprediction web yet?",
             "  ",
             "The prediction web project is highly self-selecting. Decide if it is for you.",
             "The prediction web runs counter to a strong yearning to believe in one's own polymath datascience capabilities.",
             "The prediction web suggests that you can engineer statistical algorithms that others can improve on an ongoing basis...",
             "... without asking for your permission ...",
             "... without even asking you to accept a pull request.",
             "Instead, you decouple your control and R/L problems (are there any other kinds?) from the pure microprediction task.",
             "And fire out the task, obfuscated as need be, to the entire world.",
             "And in doing so sponsor a prediction stream of data",
             "   ",
             "I think you are well on your way to inventing the prediction web",
             "    ",
             "Regardless of whether that's for you this script is helping in some small way",
             "Because you can provide good keys to others, should you wish to",
             "Thus indirectly you are helping to stop the proliferation of expensive cold-start data science.",
             "You are taking a stand against the marginal cost of number scientists who have stumbled upon the second culture of statistics",
             "You are helping in some small way mage progress towards affordable bespoke AI for small to medium size enterprises, individuals and not-for-profit organizations.",
             "You are helping in some small way to address a tragedy of the commons: the lack of a common realtime feature space.",
             "... which would have been really useful when Corono took off now, it must be admitted.",
            "    ",
            "Wait ... why ...   ",
            "What's this got to do with MUIDs?",
            "    ",
            "MUIDS carry special special significance at www.microprediction.com ",
            "... which admittedly might not be as good as your prediction web.",
            "    ",
            "The keys serve as an entry ticket, to be used two ways.",
            "    ",
            "   (1) They enable anyone to enter realtime statistical prediction contests. The more difficult the key, the greater drawdown leeway is granted.",
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
            "  ",
            "So, to complete the circle, you should keep running this script until Apr 1st, 2020",
            "Because it can take weeks to mine a really valuable key.",
            "And no doubt you are an under-appreciated mathematical genius ... ",
            "... or you know an under-appreciated mathematical genius one who would love a really difficult key",
            " ",
            "   ",
            "Oh wait I know what you are thinking ...",
            "What if I don't care about microprediction or statistics or AI or whatever and I just want to mine",
            "And I don't feel like playing Abel Magwitch to some bright young spark ...",
            "... because my heart is frosted over, ",
            "   ",
            "Can I sell MUIDs? Will this be more economical than mining bitcoin?",
            "    ",
            "A moment's reflection might convince you that is the case, assuming ",
            "... the monetary rewards at www.microprediction.com are going to be serious",
            "... because at least one top tier investment company intends to use microprediction.com for a variety of purposes",
            "... and it is likely to be useful for many businesses",
            "... and it is a free country.",
            " ",
            "Indeed it seems plausible that some participants may be impatient",
            "... and less prescient than yourself",
            "... and thus your longer keys may be valuable to them",
            "... but we can't make any promises",
            "... though we might in the near future provide an API where you can sell keys you don't want",
            "... maybe.  ",
            " ",
            "Anyway, thanks for listenning.",
            "Next time run python3 -c 'from muid import mine; mine(skip_intro=True)' to avoid this rant",
            "    ",
            "Here come some more valuable keys, hopefully. Hang in there. ",
            "   "]
