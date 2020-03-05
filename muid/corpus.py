import ring

class Corpus():

    @ring.lru()
    @staticmethod
    def max_word_len():
        return max(list(Corpus.words().keys()))

    @ring.lru()
    @staticmethod
    def min_word_len():
        return min(list(Corpus.words().keys()))

    @staticmethod
    def max_phrase_len():
        return 13

    @ring.lru()
    @staticmethod
    def words_of_len(k):
        return Corpus.words()[k]

    @ring.lru()
    @staticmethod
    def words():
        return {3: Corpus.words3(),
                4: Corpus.words4(),
                5: Corpus.words5(),
                6: Corpus.words6(),
                7: Corpus.words7(),
                8: Corpus.words8(),
                9: Corpus.words9(),
                10 :Corpus.words10(),
                11 :Corpus.words11(),
                12 :Corpus.words12()}

    @staticmethod
    def is_word(word):
        words = Corpus.words()
        return (len(word) in words) and (word in words[len(word)])

    @ring.lru()
    @staticmethod
    def phrases():
        return dict([(k, Corpus.phrases_of_len(k)) for k in range(7, 14)])

    @ring.lru()
    @staticmethod
    def phrases_of_len(k):
        if Corpus.max_phrase_len() >= k >= 6:
            words = Corpus.words()
            phrases = list()
            for k1 in range(k):
                k2 = k - k1
                if k1 >= 3 and k2 >= 3:
                    w1 = words[k1]
                    w2 = words[k2]
                    ph = [a + b for a in w1 for b in w2]
                elif k1 >= 7:
                    ph = words[k1]
                else:
                    ph = []
                phrases.extend(ph)
            return phrases
        else:
            return []


    @staticmethod
    def words12():
        return []

    @staticmethod
    def words11():
        return []

    @staticmethod
    def words10():
        return ['obsolesced', 'obsolesces', 'calabooses',
                'saddleless', 'assessable', 'offsaddles',
                'coalfields']  # TODO: Add t's


    @staticmethod
    def words9():
        return ['baldfaced', 'boldfaced', 'coalfaces', 'decodable',
                'accolades', 'caboodles', 'closeable', 'coalesced',
                'ecolabels', 'scaleable', 'calaboose', 'deadballs',
                'deadfalls', 'escaladed', 'looseleaf', 'baseloads',
                'adolases', 'cascabells', 'cascables', 'classless',
                'abscesses', 'bloodless', 'baseballs', 'deadballs',
                'discalced', 'sociables', 'disclosed', 'siblicide',
                'localised', 'silicosis']  # TODO: Add t's


    @staticmethod
    def words8():
        return ['albedoes', 'allseeds', 'beefalos', 'boldface', 'caboosed',
                'cadelles', 'calloses', 'closable', 'coalless', 'codeless',
                'debacles', 'declasse', 'descales', 'ecolabel', 'faceless',
                'fadeless', 'foldable', 'laceless', 'leadless', 'leafless',
                'lobeless', 'secalose', 'socalled', 'sofabeds', 'cladodes',
                'descaled', 'socalled', 'badassed', 'baseload', 'calloses',
                'caseload', 'colossal', 'debossed', 'declasse', 'escalade',
                'fadeless', 'foodless', 'laceless', 'leasable', 'lobeless',
                'saleable', 'scalades', 'scalados', 'sealable', 'seafoods',
                'secalose', 'aldolase', 'allseeds', 'leadless']  # TODO: Add t's


    @staticmethod
    def words7():
        return ['albedoe', 'beefalo', 'befools', 'debacle', 'beadles', 'beefalo',
                'caboodl', 'befleas', 'belaced', 'boodles', 'caboose', 'codable',
                'doolees', 'elodeas', 'solaced', 'sofabed', 'seafood', 'fadable',
                'abodes0', 'cabals0', 'f1eeced', 'feedab1', '1abe1ed', 'facaded',
                'defaced', 'daffed0', 'cabbed0', 'baff1ed', 'acceded', '2faced0',
                'faded00', 'beaded0', 'decaded', 'ebbed00', 'acceded', 'effaced',
                'ceded00', 'dada007', 'debac1e', 'decada1', '1eafed0', 'fab1ed00',
                'dabb1e0', 'cab1ed0', '1ead000', 'b1ade00', 'f1ea000', 'flee000',
                'beef000', 'babe000', 'ee10000', 'dad0000', 'deadfa11', 'fadab1e',
                '1ad1ed0', 'be1aced', 'class00', 'leadles', 'fleeced', 'decease',
                'sealed0', 'scales0', 'felled0', 'leafles', 'eased00', 'decaf00',
                'called0', 'sell000', 'self000']  # TODO: Add t's


    @staticmethod
    def words6():
        return ['deflea', 'felted', 'foaled', 'fooled', 'leafed', 'lofted', 'albedo',
                'beadle', 'belted', 'bolted', 'boodle', 'coaled', 'colead', 'cooled',
                'doable', 'locoed', 'tabled', 'talced', 'aflood', 'defeat', 'fatted',
                'feeted', 'footed', 'batted', 'betted', 'boated', 'booted', 'catted',
                'coated', 'cooeed', 'debate', 'detect', 'fettle', 'feotal', 'battle',
                'blotto', 'boetel', 'bolete', 'bottle', 'cattle', 'lobate', 'locate',
                'oblate', 'ocelot', 'tablet', 'talbot', 'tectal', 'bootee', 'coatee',
                'cottae', 'delate', 'doolee', 'dottel', 'dottle', 'elated', 'elodea',
                'letted', 'looted', 'lotted', 'toledo', 'tooled', 'teated']  # TODO add more


    @staticmethod
    def words5():
        return ['abbas', 'babas', 'babes', 'beads', 'beefs',
                'cafes', 'cecas', 'dadas', 'deeds', 'focal',
                'faces', 'fades', 'feebs', 'feeds', 'decaf',
                'faced', 'cleft', 'cable', 'focal', 'cable',
                'celeb', 'coble', 'facet', 'facto', 'delft',
                'flood', 'abled', 'acold', 'baled', 'bedel',
                'blade', 'bleed', 'blood', 'clade', 'coled',
                'decal', 'dobla', 'dolce', 'defat', 'fated',
                'feted', 'abode', 'acted', 'adbot', 'adobe',
                'adobo', 'aloft', 'aloof', 'bated', 'booed',
                'cadet', 'cooed', 'coted', 'fetal', 'fleet',
                'fleet', 'float', 'flota', 'loofa', 'octad',
                'abele', 'betel', 'blate', 'bleat', 'bloat',
                'botel', 'cleat', 'cloot', 'eclat', 'elect',
                'obole', 'octal', 'table', 'telco', 'ebola',
                'ecole', 'afoot', 'betta', 'cooee', 'cotta',
                'octet', 'taboo', 'tacet', 'tecta', 'bottle',
                'fetta', 'dealt', 'delta', 'dotal', 'lated',
                'looed', 'toled', 'ladoo', 'datto', 'toted',
                'elate', 'latte', 'lotta', 'lotte', 'lotto',
                'telae', 'total', 'teaed']  # TODO add more


    @staticmethod
    def words4():
        return ['abba', 'abbe', 'abed', 'aced', 'baba', 'babe', 'bade', 'baff', 'bead', 'beef',
                'caca', 'cade', 'cafe', 'caff', 'ceca', 'cede', 'dace', 'dada', 'daff', 'dead',
                'deed', 'face', 'fade', 'feeb', 'feed', 'deaf', 'calf', 'clef', 'cafe', 'flab',
                'coof', 'fact', 'baft', 'delf', 'fled', 'fold', 'bald', 'bled', 'bold', 'clad',
                'clod', 'cold', 'daft', 'deaf', 'deft', 'fade', 'fado', 'feed', 'feod', 'food',
                'abed', 'aced', 'alef', 'bade', 'bead', 'bode', 'cade', 'cede', 'coda', 'code',
                'coed', 'dace', 'debt', 'deco', 'feal', 'feel', 'felt', 'flat', 'flea', 'floe',
                'foal', 'fool', 'leaf', 'left', 'loaf', 'loof', 'able', 'alec', 'bale', 'belt',
                'blae', 'blat', 'blet', 'blot', 'bola', 'bole', 'bolo', 'bolt', 'calo', 'celt',
                'clot', 'coal', 'cola', 'cole', 'colt', 'cool', 'cool', 'lace', 'lobe', 'lobo',
                'loca', 'obol', 'talc', 'doco', 'ecad', 'fale', 'felo', 'fate', 'feat', 'feet',
                'feta', 'fete', 'foot', 'tolf', 'abet', 'bate', 'batt', 'beat', 'beet', 'beta',
                'boat', 'boot', 'bota', 'bott', 'cate', 'cete', 'coat', 'coot', 'coot', 'cote',
                'oboe', 'tace', 'taco', 'tact', 'toco', 'acto', 'bato', 'bete', 'boto', 'dale',
                'dolt', 'lade', 'dale', 'deal', 'dele', 'delt', 'dole', 'dolt', 'lade', 'lead',
                'lede', 'load', 'olde', 'told', 'date', 'dato', 'deet', 'doat', 'odea', 'teed',
                'toad', 'toad', 'toed', 'alee', 'aloe', 'alto', 'late', 'leet', 'loot', 'lota',
                'olea', 'oleo', 'teel', 'tela', 'tele', 'tool', 'aloo', 'lato', 'leat', 'todo',
                'otto', 'tate', 'teat', 'toea', 'toot', 'etat', 'tete', 'tete', 'toto', 'feeb',
                'dobe', 'beal', 'tolt', 'loto']


    @staticmethod
    def words3():
        return ['aba', 'ace', 'add', 'baa', 'bad', 'bed', 'bee', 'cab', 'cad', 'dee', 'def', 'ebb',
                'ebb', 'fab', 'fad', 'fed', 'fee', 'ado', 'alb', 'ale', 'all', 'bad', 'bal', 'doc',
                'doe', 'dol', 'eel', 'eld', 'elf', 'ell', 'fab', 'fad', 'foe', 'lad', 'lea', 'led',
                'loo', 'oaf', 'oba', 'oca', 'oda', 'ode', 'old', 'cat', 'fab', 'cob', 'def', 'fad',
                'bad', 'bed', 'bod', 'cad', 'cod', 'dab', 'deb', 'doc', 'elf', 'alb', 'bal', 'bal',
                'bel', 'col', 'lab', 'lac', 'lob', 'bol', 'dob', 'dof', 'flo', 'aft', 'eft', 'aft',
                'fat', 'oof', 'act', 'bat', 'bee', 'boa', 'bot', 'cat', 'cee', 'cot', 'eco', 'old',
                'lad', 'dot', 'eel', 'ale', 'eel', 'loo', 'eta', 'oat', 'oot', 'tae', 'tea', 'tee',
                'tet', 'toe', 'tot']
