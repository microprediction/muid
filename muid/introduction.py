WELCOME = """                         
         __    __     __    __    _____   ______              
      
██     ██ ███████ ██       ██████  ██████  ███    ███ ███████ 
██     ██ ██      ██      ██      ██    ██ ████  ████ ██      
██  █  ██ █████   ██      ██      ██    ██ ██ ████ ██ █████   
██ ███ ██ ██      ██      ██      ██    ██ ██  ██  ██ ██      
 ███ ███  ███████ ███████  ██████  ██████  ██      ██ ███████ 
                                                              
                                                              
            https://github.com/microprediction
           
            
                   
"""


WAFFLE = ["Hey thanks for giving this a spin ",
               "  ",
               "Pretty soon you'll be firing predictions at data streams https://www.microprediction.org/browse_streams.html",
               "Which you can read about at https://www.microprediction.com/blog/livedata",
               "And you'll be helping create Community Distribution Functions (CDFs) like ... ",
               "   ... this https://www.microprediction.org/stream_dashboard.html?stream=xray_429&horizon=3555",
               "Isn't she beautiful?",
               "      ",
               "Well that CDF you see is hard to beat",
               "... eventually",
               "... after enough people read https://mitpress.mit.edu/9780262047326/microprediction/",
               "More on that later",
               "  ",
               "But first, you ask, why the slow 80's intro?",
               "  ",
               "Don't worry it is a one off. You don't have a WRITE_KEY.txt file so I'm assuming you don't have an identity",
               " ",
               "So we have to make you one",
               "As soon as that is done it will be saved to WRITE_KEY.txt",
               "And then you will be able to start crawling, as it is known",
               "See https://microprediction.github.io/microprediction/predict-using-python-microcrawler.html",
               "  ",
               "But first, your computer is running a little script from the MUID package",
               "Your write key is actually a MUID",
               "    ",
               "If you are suspicious you can read the code at https://github.com/microprediction/muid ",
               "  ",
               "Nothing too sinister actually, except for some hashing",
                "  ",
               "You should hear your laptop fan firing up. Well, maybe. ",
               "If at any point you feel uncomfortable, or your computer does, just Control-C",
               "Honestly you can probably run this script in half a dozen terminals without issue.",
               "We thought it would be rude to take all your processors without asking, however.",
               "  ",
               "Honestly not trying to mine crypto on your machine", 
               "                   ",
              "But the script searches for hash-memorable keys",
              "There is a video explaining MUIDS at https://vimeo.com/397352413 too.",
              "The video is pretty cheesy",
              "Yet oddly informative",
              " ",
              "Yeah okay never mind I'll just explain",
              "A hash-memorable key is a unique identifier.",
              "Which is to say a long randomly generated string representing a hexidecimal number",
             "Such as 30599b096bc5751c311ea6e15e306c86",
             "Which might have been produced by a monkey sitting at 1/3 of a typewriter."
             " ",
             "Just in case you don't know what a hash function is, and didn't watch the video",
             "A hash function, in this case, takes one hex number and turns it into another",
             "A hash is a just a function that is almost impossible to invert.",
             "See https://en.wikipedia.org/wiki/Hash_function.",
             "  ",
             "We use SHA-256, truncated.",
              "  ",
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
             "So anyway this overly chatty script does nothing but generate a vast number of random hexadecimal numbers,",
             "Eventually their hashes are recognizable strings although,",
             "as noted, the strings aren't that recognizable unless you squint,",
             "  ",
             "and replace digits with letters (like 0->o, 7->t and so forth).",
             " ",
             "We've introduced the notion of readable hex, in this manner.",
             "The rules for coverting digits to letters are at https://pypi.org/project/muid/",
             "And to save your eyesight we'll print the translation,",
             "which is to say your spirit animal.",
             "or nom de plume, which will appear on the leaderboards https://www.microprediction.org/leaderboard.html ",
             " ",
             "At times like this we all need a good spirit animal.",
             " ",
             "And some cash. Did you notice the $$ on the leaderboards?", 
             "  ",
             "Obviously you are doing this for science, though", 
             "  ",
             "   ", 
             "The key is typically intended to be private, but the hash can be public.",
             "But you knew that because you watched the video",
             "Part of the hash includes a memorable identifier, of course, and thus ...",
             "... hash-memorable keys can be used to create applications with one less join, as it were.",
             "If you write applications, you might appreciate that.",
             "  ",
              "Or not.",
              "  ",
              "Don't worry we aren't going to burn the Earth either way",
               "Just generate you a good write key and then get on with it",
               "  "
              "There are 422,013 possibilities.",
             "If you do manage to generate an amusing spirit animal, by all means share it.",
             "You can post at https://www.quora.com/What-are-the-most-amusing-hash-memorable-identifiers-you-have-generated ",
             "  ",
              "That was a joke",
              " ",
              "Nobody reads Quora",
              "  ",
              "It is so dumb",
              "  ",
              "Naturally, if you don't like your name you can just run this again, after deleting WRITE_KEY.txt",
              " ",
              "Or you can do it many other ways, if you read the docs https://microprediction.github.io/microprediction/writekeys.html",
              "  ",
              "Or open up this notebook https://github.com/microprediction/microprediction/blob/master/notebook_examples/New_Key.ipynb",
               "  and run it on Google's dime",
             "  ",
             "  ",
             "I hate notebooks", 
              " ", 
            "But first ... there is a minor technical thing you need to know.",
            "Before choosing 'Collosal Oca' or 'Foldable Cat' over 'Bleachable Crab',",
            "Observe that the first two are length 11 and the latter length 14.",
            " ",
            "So while Foldable Cat is unequivocally funnier than Bleachable Crab ...",
            "Bleachable Crab is about four thousand times harder to find than Foldable Cat",
            "  ",
            "And that matters, actually",
            "In theory ...",
            "Bleachable Crab, or rather any key that hashes to it, will be four thousand times more valuable."   
            "  ",
            "Good MUIDs come to those who wait",
             "   ",
            " ... and wait",
            "Your mining is going very well, don't worry",
              "  ",
             "That's a joke about Poisson arrival times",
            "Not a very funny one, admittedly",
            " ",
            "If my comedic timing is really off you are using a bad computer",
            "But it isn't a waste of time that we are sitting here chatting.",
            "   ",
            "Hey maybe you took the time to read the rest of the docs https://microprediction.github.io/microprediction/",
            "  ", 
            "That's another joke",
            "  ",
            "Nobody reads docs",
            "   ",
            "Hey did you know some people stock-pile Memborable Unique Identifiers?",
            "  ",
            "They think they might be very valuable",
            "     ",   
            "Because, you know, after everybody reads https://mitpress.mit.edu/9780262047326/microprediction/",
            " ", 
            "That was a joke too",
            "  ", 
            "Nobody reads books",
            "Just medium",
            "    "
            "They liked this though https://medium.com/geekculture/scientists-discover-150-000-year-old-machine-learning-algorithm-cc047ff61aa8",
            "It is very profound",
            "Great article. Really recommend it",
            "Oh you don't read?",
            "Hmmm, you can listen to this I suppose https://github.com/microprediction/building_an_open_ai_network/blob/main/docs/assets/audio/Microprediction_Chapter_1.mp3 "
            "   ",
            "Anyway, about that prediction web",
            "Which doesn't exist yet, admittedly. ",
            "  ",
            "But when it does the use of write keys that are MUIDs will provide mass, ",
            "just as a similar concept provides 'weight' for blockchain applications, preventing Cybil attacks.",
            "  ",
            "The difference is that it is hard to think of a good blockchain application",
            "And really hard to not think of a good microprediction application", 
            "  ", 
            "There are millions of bloody obvious applications of microprediction",
            " ",
            "  ",
            "Where was I? Oh, write keys", 
            "Just a primitive throttling mechanism",
            "You can read about bankruptcy https://microprediction.github.io/microprediction/bankruptcy",
             "  ",
             "Easily circumvented by joining the slack https://microprediction.github.io/microprediction/slack.html",
             "And then saying 'hey peter can you increase my balance?' ",
             "Which usually works",  
            "  ",
            "So btw I'm definitely not saying you should hoard MUIDs ",
            "Though if you are clever you can forsee things that others cannot. ",
            "And this gives you an opportunity to get ahead of the game and pick up low fruit.",
            "Like 14 digit MUIDs for example",
            "  ", 
            "Because by the time the utility of the prediction web is obvious to one and all, ",
            "It might take a 14 MUID to create a stream on the primary oracle",
            "  ",
            "Right now it only takes 12", 
            "  ",
            "See https://microprediction.github.io/microprediction/publish.html ",
            "   ",
            "Also, one day, you might have to try harder than running the default algorithm",
            "Instead you'll have to think a little about mathematics, ",
            "And distributional time-series prediction", 
            "which won't kill you,",
            "but isn't quite as easy as this.",
            "   ",
            "   ", 
            "   "
            "I suggest that the microprediction web will prove valuable for many businesses ...",
            "... and profitable for smart people with good models and data ... ",
            "... so long as they can get hold of a good MUIDs to start playing.",
            "   ",
            "The prediction web is a prophesy, mostly",
            "Though there is a microprediction oracle api.microprediction.org",
            " ... to use terminology from the book you didn't read",
            " ... and you are about to start polling data from there, running a model, and submitting predictions back",
            "  "
            "This oracle is far from perfect.",
            "But actually one manager has been using it for a while",
             "They have billions of assets under management",
             "And you probably don't",
             "Maybe they are smart",
             "And don't like overfitting-as-a-service baloney automated machine learning", 
             "  ",
             "  ",
             "The oracle you are able to help has processed about a billion predictions", 
             "With better uptime than LinkedIn", 
            "   ",
            "Eventually - and of course this is more speculative ... ",
            "... microprediction webs will have a big impact on commerce, including realtime operations.",
            "  ", 
            "  ",
            "But not just commerce.",
            "The goal of a prediction web is to (asymptotically) render AI applications cheap and ubiquitous",
            "... even if they require bespoke prediction and decision making ",
            "... and obscure applied mathematical techniques mastered by few ",
            "... or data that might not be obviously related.",
            "  ",
            "  ",
            "But don't let me tell you what it should be",
            "Your goal should be to invent the microprediction web",
            "While we sit here.",
            "   ",
            "It would be good if your microprediction web could perform 'search' better than hierarchies of people.",
            "By which we refer to search in the space of relevant models and data, not searching for your car keys.",
            "  ", 
            "You should invent a microprediction web that will make consulting companies, artisan data scientists,",
            "and overpaid pompous managers ",
            "about as relevant to model and data search as ...",
            " ... librarians are to document search.",
            "   ",
            "Ouch. I like librarians ... but there is a message in the plot here:  https://blog.oup.com/2011/06/librarian-census/   ",
            "Look at the date of 'peak librarian', in particular.",
            "  ", 
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
            "If only there were a book about this",  
            "The book addresses some of the standard objections, such as privacy, although ... ",
            "... we've found that most people with mathematical training see around the objections rather easily.",
            "... and are confident you will too.",
            "For example, privacy is not continuous with respect to Haar measure. ",
            "  ",
            "The book might not get everything right",
            "But its ratio of accuracy to cost will increase over time",
            " ",
            "See, I am getting funnier", 
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
             "Chapter 8 is about that, by the way",
             "   ",
             "I think you are well on your way to inventing the prediction web",
             "    ",
             "Regardless of whether that's for you this script is helping in some small way",
             "   ",
             "This script is going to run the default crawler",
             "But it will also stop every now and then to upgrade",
             "And the default crawler is going to get pretty good over time",
              "You see if I'm wrong",
             "   "  
             "Thus indirectly you are helping to stop the proliferation of expensive cold-start data science.",
             "You are taking a stand against the marginal cost of number scientists who have stumbled upon the second culture of statistics",
             "You are helping in some small way mage progress towards affordable bespoke AI for small to medium size enterprises, individuals and not-for-profit organizations.",
             "You are helping in some small way to address a tragedy of the commons: the lack of a common realtime feature space.",
             "... which would have been really useful when Coronovirus took off now, it must be admitted.",
            "    ",
            "Wait ... why ...   ",
            "What's this got to do with MUIDs?",
            "    ",
            "MUIDS carry special special significance at www.microprediction.com ",
            "... which admittedly might not be as good as your prediction web, the one your are currently formulating in your head",
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
            "  ",
            "Oh wait I know what you are thinking ...",
            "What if I don't care about microprediction or statistics or AI or whatever and I just want to burn WRITE_KEYS?",
            "Because you played nearest neighbour and came up with bitcoin mining?",
            "But you have no intention of donating them to talented statisticians impatient to enter the prediction web",
            "... because you don't feel like playing Abel Magwitch to some bright young spark ...",
            "... because your heart is frosted over, ",
            "   ",
            "Can you sell MUIDs? Will this be more economical than mining bitcoin?",
            "    ",
            "A moment's reflection might convince you that could, just possibly, be the case, assuming ",
            "... the monetary rewards are going to be serious",
            "... and it is likely to be useful for many businesses",
            "... actually all businesses", 
            "... and it is a free country.",
            " ",
            "But I am skeptical",
            "I would not encourage you to think of this mining process as similar to bitcoin at all",
            "   ",
            "That's because running compute to solve a hash is stupid and pointless",
            "Here you will be running a statistical algorithm, soon, I promise",
            "And you are free to run the same python code after modifying your crawler",
            "And you can make it do whatever you want using whatever model you like",
            "See https://github.com/microprediction/microprediction/tree/master/crawler_examples_modification ",
            " ",
            "Or if you like R or Julia that's fine too.",
            "See https://microprediction.github.io/microprediction/publish.html", 
            " ",
            "If you like video tutorials https://microprediction.github.io/microprediction/videos.html",
            "  ",
            "Anyway, do ask questions in the slack https://microprediction.github.io/microprediction/slack.html",
            "And like I said, be patient... ",
            "  ",
            "Go to lunch",
            "Or sleep",
            "I'll be just fine"]


SUCCESS = """
         __    __     __    __    _____   ______              
      
  
       / /\     /\_\               /\ \           /\ \           /\ \        / /\        / /\      
      / /  \   / / /         _    /  \ \         /  \ \         /  \ \      / /  \      / /  \     
     / / /\ \__\ \ \__      /\_\ / /\ \ \       / /\ \ \       / /\ \ \    / / /\ \__  / / /\ \__  
    / / /\ \___\\ \___\    / / // / /\ \ \     / / /\ \ \     / / /\ \_\  / / /\ \___\/ / /\ \___\ 
    \ \ \ \/___/ \__  /   / / // / /  \ \_\   / / /  \ \_\   / /_/_ \/_/  \ \ \ \/___/\ \ \ \/___/ 
     \ \ \       / / /   / / // / /    \/_/  / / /    \/_/  / /____/\      \ \ \       \ \ \       
 _    \ \ \     / / /   / / // / /          / / /          / /\____\/  _    \ \ \  _    \ \ \      
/_/\__/ / /    / / /___/ / // / /________  / / /________  / / /______ /_/\__/ / / /_/\__/ / /      
\ \/___/ /    / / /____\/ // / /_________\/ / /_________\/ / /_______\\ \/___/ /  \ \/___/ /       
 \_____\/     \/_________/ \/____________/\/____________/\/__________/ \_____\/    \_____\/        
                                                                                                   

                                                              
                      You have successfully created your WRITE_KEY.txt  
                 
                                        Now we predict 
                         
                     Don't forget to paste your write key in at https://www.microprediction.org/    
                     
            
                   
"""
