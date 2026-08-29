# passwordgen.py
'''Establish sets of rules for generating passwords.'''

#   I M P O R T S
import random    # choice(), randint(), X- shuffle()-X
import string    # ascii_uppercase, ascii_lowercase, ascii_letters, digits
import sys       # exit(), argv[]
import time      # strptime()
import warnings  # warn()
from collections.abc import Sequence

from exceptions import *


#   M O D U L E   C O N S T A N T S

GBP = '\u00A3'  # British Pound Sterling
UpArrow = '\uA71B'  # just for testing


#   M O D U L E   V A R I A B L E S

pswdGens = {}  # dict w/DNS domains for keys, PasswordGen instances for values.


#   F U N C T I O N S

def delChars(chars: str | NoneType, forbiddenChars: str) -> str:
    '''Remove forbidden characters from a string and return remaining chars.

    It doesn't matter if forbidden chars includes chars not present in "chars."
    '''

    if chars is None:
        return ''
    else:
        return ''.join(sorted(set(chars) - set(forbiddenChars)))


#   F R O M   C O N F I G U R A T I O N   F I L E   ( E V E N T U A L L Y )

myConfusableChars = 'Il1|O0'  # maybe '2Z'  '5S'  '6b'  '8B'

if 'myConfusableChars' not in globals():
    myConfusableChars = 'Il1|O0'  # maybe '2Z'  '5S'  '6b'  '8B'


#   C L A S S E S

class PasswordGen:
    '''Rules for generating passwords for a particular site.'''

    #   C L A S S   C O N S T A N T S

    lenMinDflt = 12
    lenMaxDflt = 63

    # We need ASCIIspecialChars b/c string.punctuation varies with the locale.
    asciiSpecialChars = '`~!@#$%^&*()-_=+[]{}\\|;:\'",./<>?'


    #   I N S T A N C E   M E T H O D S

    def __init__(self, *,
                       uc: int | Sequence = 0, lc: int | Sequence = 0,
                       letters: int | Sequence = 0, num: int | Sequence = 0,
#                      specialchars: str = '`~!@#$%^&*()-_=+[]{}\\|;:\'",./<>?',
#                      specialchars: str = string.punctuation,
                       specialchars: str = asciiSpecialChars,
                       special: int | Sequence = 0, lenmin: int = lenMinDflt,
                       lenmax: int = lenMaxDflt,
                       maxrun: int | NoneType = None,
                       n_of_m_groups: tuple | NoneType = None,
                       firstchar: tuple | NoneType = None,
                       firstcharspecialchars: str | NoneType = None,
                       history: int = 0, spacesallowed: bool = False,
                       casesensitive: bool = True, domain: str = '',
                       ruleschecked: str | NoneType = None,  # date string YYYY-mm-dd
                       extraspecialchars: str | Sequence | NoneType = None,
                       otherchars: str | Sequence | NoneType = None,
                       allowconfusables: bool = True,
                       confusablechars: str = myConfusableChars):
        '''Initializer sets the types and quantities of required characters.
        '''


#             or len(confusablechars) == 0):
#           self.ascii_uppercase = string.ascii_uppercase
#           self.ascii_lowercase = string.ascii_lowercase
#           self.ascii_letters = string.ascii_letters
#           self.digits = string.digits
#           self.specialChars = specialchars
#           self.extraSpecialChars = extraspecialchars
#           self.firstCharSpecialChars = firstcharspecialchars
#           self.otherChars = otherchars
#       else:  # confusables not allowed

        if lenmin > lenmax:
            raise UserError(f'Minimum password length ({lenmin}) may'
                            f' not be greater than maximum length ({lenmax}).')
        if extraspecialchars is None:
            self.extraSpecialChars = ''
        else:
            for char in extraspecialchars:
                if ord(char) < 128:  # ASCII?
                    if char in string.printable:
                        if char in PasswordGen.asciiSpecialChars:
                            raise UserError(f'ExtraSpecialChars contains a'
                                            f' punctuation mark.  Use'
                                            f' "specialchars" instead.')
                        else:  # not punctuation
                            raise UserError(f'ExtraSpecialChars contains'
                                            f' a non-punctuation ASCII'
                                            f' char.  Illegal.')
                    else:  # non-printable ASCII char
                        raise(f'ExtraSpecialChars contains a non-printable'
                              f' ASCII char (control code).  Illegal.')
            self.extraSpecialChars = ''.join(set(extraspecialchars))  # str or other Sequence
        remainder = set(specialchars) - set(PasswordGen.asciiSpecialChars)
        if len(remainder) > 0:
            raise UserError(f'Illegal character(s) in'
                            f' specialchars argument "{''.join(remainder)}"')

        if allowconfusables or confusablechars is None:
            self.confusableChars = ''
        else:
            self.confusableChars = confusablechars
        self.ascii_uppercase = delChars(string.ascii_uppercase,
                                        self.confusableChars)
        self.ascii_lowercase = delChars(string.ascii_lowercase,
                                        self.confusableChars)
        self.ascii_letters = delChars(string.ascii_letters,
                                      self.confusableChars)
        self.digits = delChars(string.digits, self.confusableChars)
        self.specialChars = delChars(specialchars, self.confusableChars)
        self.extraSpecialChars = delChars(self.extraSpecialChars,
                                          self.confusableChars)
        self.specialChars += self.extraSpecialChars
        self.firstCharSpecialChars = delChars(firstcharspecialchars,
                                              self.confusableChars)
        if firstcharspecialchars is None:
            self.firstCharSpecialChars = self.specialChars  # allowed in first char
        else:
            self.firstCharSpecialChars = delChars(firstcharspecialchars,
                                                  confusablechars)
        self.otherChars = delChars(otherchars, self.confusableChars)


        chrGroups = ((uc,      'uc'),       # upper case letters
                     (lc,      'lc'),       # lower case letters
                     (letters, 'letters'),  # either case letters
                     (num,     'num'),      # digits
                     (special, 'special'))  # punctuation / symbols / specials
        for (arg, grp) in chrGroups:
            if isinstance(arg, Sequence):  # list, tuple, or descendant of those
                if 1 > len(arg) > 2:       # ^yes.  How long is Sequence?
                    raise UserError(f'Char group "{grp}" can have'
                                     ' only 1 or 2 limits.')
                setattr(self, grp+'Min', int(arg[0]))  # minimum uc/lc/...
                if len(arg) == 1:  # has a maximum been specified in the tuple?
                    setattr(self, grp+'Max', None)  # unlimited maximum
                elif arg[1] < arg[0]:  # max < min?
                    raise UserError(f'Min chars of group cannot exceed max.')
                else:              # ^yes, get max from Sequence
                    setattr(self, grp+'Max', int(arg[1]))
            else:  # not a Sequence; just an int
                setattr(self, grp+'Min', int(arg))
                setattr(self, grp+'Max', None)  # unlimited Max
#       self.ucMin = uc                   # nbr of req'd Upper-case letters
#       self.lcMin = lc                   # nbr of req'd Lower-case letters
#       self.lettersMin = letters         # nbr of req'd letters (when uc & lc not
#                                         #    specified)
#       self.numMin = num                 # nbr of req'd numerals
#       self.specialChars = ''.join(set(specialchars))  # string of all allowable special chars
#       self.specialMin = special         # nbr of req'd special characters
        self.lenMin = lenmin              # minimum allowable length of password
        self.lenMax = lenmax              # maximum allowable length of password
        self.maxRun = maxrun              # allowable consecutive same character
        self.NofMgroups = n_of_m_groups   # req'r chars from n groups of m indicated
        self.firstChar = firstchar    # restrict 1st char to chars in these grps
        self.history = history        # pswd cannot match last n passwords
        self.domain = domain  # name of domain to use this password with.
        self.spacesAllowed = spacesallowed
        self.caseSensitive = casesensitive
        if (len(self.specialChars)  # + len(self.extraSpecialChars)
              == 0
              and self.specialMax != 0):
            warnings.warn(f'No special chars are in list of allowed specials,'
                            f' but the specified maximum # of specials'
                            f' ({self.specialMax}) is not zero. Setting to'
                            f' zero temporarily.')
            self.specialMax = 0
        # otherchars are puncuation symbols that don't count as special chars
        # for purposes of adhering to a minimum or maximum count of specials.
        if self.otherChars is not None and len(self.otherChars) > 0:
            for char in self.otherChars:
                if char not in PasswordGen.asciiSpecialChars:
                    raise UserError(f'Char in "otherchars" is not a punctuation'
                                    f' symbol.')
                if char in self.specialChars:
                    raise UserError(f'Char in "otherchars" already specified'
                                    f' in "specialchars".')
#           self.otherChars = ''.join(set(otherchars))
        else:  # otherchars is None or ''
            self.otherChars = ''
        if ruleschecked is not None:
            try:
                time.strptime(ruleschecked, '%Y-%m-%d')
            except ValueError:
                raise UserError(f'ruleschecked date ({ruleschecked}) not'
                                f' in YYYY-mm-dd format.')
        self.rulesChecked = ruleschecked

        if casesensitive:
            self.allLetters = self.ascii_letters
        else:  # not casesensitive
            self.allLetters = self.ascii_lowercase
            if (self.ucMin != 0 or self.ucMax is not None
                or self.lcMin != 0 or self.lcMax is not None):
                    raise ProgrammerError(
                            'Cannot specify "lc" or "uc" when not case'
                            ' sensitive. However, you can specify "letters".')
        if self.firstChar is not None:
           if ('ltrs' in self.firstChar
                  and ('uc' in self.firstChar or 'lc' in self.firstChar)):
                raise ProgrammerError(
                    'First char restriction cannot contain "ltrs" with either'
                    ' "uc" or "lc".')

#       self.allChars = (self.allLetters
#                        + string.digits
#                        + specialchars
#                        + (' ' if spacesallowed else '')
#                       )
        self.allChars = ''
        if ((self.ucMax is None or self.ucMax > 0)
            and (self.lettersMax is None or self.lettersMax > 0)
            and casesensitive):
                self.allChars += self.ascii_uppercase
        if ((self.lcMax is None or self.lcMax > 0)
            and (self.lettersMax is None or self.lettersMax > 0)):
                self.allChars += self.ascii_lowercase
        if self.numMax is None or self.numMax > 0:
            self.allChars += self.digits
        if self.specialMax is None or self.specialMax > 0:
            self.allChars += self.specialChars  # + self.extraSpecialChars
        if spacesallowed:
            self.allChars += ' '
        self.allChars += self.otherChars
        requiredlen = (max(self.ucMin + self.lcMin, self.lettersMin)
                       + self.numMin + self.specialMin)  # more later?
        if n_of_m_groups is not None:
            if not isinstance(n_of_m_groups[0], int):
                raise UserError(f'1st element of n_of_m_groups'
                                f' "{n_of_m_groups[0]}" must be an integer')
            groups = n_of_m_groups[1:]
            if len(groups) <= n_of_m_groups[0]:
                raise UserError(f'The number of groups ({len(groups)}) is not'
                                f' greater than the # of required groups'
                                f' ({n_of_m_groups[0]}).')
            for grp in groups:
                match grp:
                    case 'uc':
                        if not casesensitive:
                            raise ProgrammerError(
                                'A case-insensitive n_of_m_group'
                                ' cannot have "lc" or "uc" specified,'
                                ' but may have "letters" specified.')
                        if (self.ucMin > 0 or self.lettersMin > 0
                              or self.ucMax == 0 or self.lettersMax == 0):
                            raise UserError('Cannot have minimums for uc or'
                                            ' letters when "uc" is an n_of_m_group')
                    case 'lc':
                        if not casesensitive:
                            raise ProgrammerError(
                                'A case-insensitive n_of_m_group'
                                ' cannot have "lc" or "uc" specified,'
                                ' but may have "letters" specified.')
                        if (self.lcMin > 0 or self.lettersMin > 0
                              or self.lcMax == 0 or self.lettersMax == 0):
                            raise UserError('Cannot have minimums for lc or'
                                            ' letters when "lc" is an n_of_m_group')
                    case 'ltrs':
                        if 'uc' in groups or 'lc' in groups:
                            raise UserError('In n_of_m_groups cannot have'
                                            ' "ltrs" together'
                                            ' with "uc" or "lc".')
                        if (self.lcMin > 0 or self.ucMin > 0
                              or self.lettersMin > 0
                              or self.lcMax == 0 or self.ucMax == 0
                              or self.lettersMax == 0):
                            raise UserError('Cannot have minimums for lc, uc or'
                                            ' letters when "ltrs" is an'
                                            ' n_of_m_group')
                    case 'num':
                        if self.numMin > 0 or self.numMax == 0:
                            raise UserError('Cannot have num minimum > 0'
                                            ' or num maximum == 0 when "num"'
                                            ' is an n_of_m_group')
                    case 'spec':
                        if self.specialMin > 0 or self.specialMax == 0:
                            raise UserError('Cannot have special minimum > 0'
                                            ' or special maximum == 0 when'
                                            ' "special" is an n_of_m_group')
                    case _:  # catchall
                        warnings.warn(f'Unknown group "{grp}" in N-of-M groups.')

            requiredlen += n_of_m_groups[0]  # number of required groups
        if requiredlen > lenmax:
            raise UserError('Required length exceeds maximum length.')
        if requiredlen > lenmin:
            warnings.warn(f'Minimum length ({lenmin}) adjusted'
                          f' to required length ({requiredlen})')
            self.lenmin = lenmin = requiredlen

    def genPassword(self, preferredlen: int = 16,
                          *, test=False, fill=False) -> str | NoneType:
        '''Generate a password for a particular site.'''


        #   M E T H O D   C O N S T A N T S

        MAXTRIES = 1000  # break infinite loop of attempts to generate a password.


        #   M E T H O D   F U N C T I O N S

        def shuffle(chars: str) -> str:
            charsList = list(chars)
            shuffled = ''
            while len(charsList) > 0:
                shuffled += charsList.pop(random.randint(0, len(charsList)-1))
            return shuffled

        def adjustQuotas(char: str):
            nonlocal adjLtrs, adjUc, adjLc, adjNum, adjSpec
            if char in string.ascii_letters:  # could use self.allLetters
                adjLtrs -= 1
            # char could be both Ltrs and either Uc or Lc
            if char in string.ascii_uppercase:
                adjUc -= 1
            elif char in string.ascii_lowercase:
                adjLc -= 1
            elif char in string.digits:
                adjNum -= 1
            elif char in (self.specialChars  # + self.extraSpecialChars
                         ):
                adjSpec -= 1

        def countChars(char: str):
            nonlocal ctLtrs, ctUc, ctLc, ctNum, ctSpec
            if char in string.ascii_letters:  # could use self.allLetters
                ctLtrs += 1
                if self.lettersMax is not None and ctLtrs >= self.lettersMax:
                    removeCharGroup(string.ascii_letters)
            # char could be both Ltrs and either Uc or Lc -- SO WHAT!
            elif char in string.ascii_uppercase:
                ctUc += 1
                if self.ucMax is not None and ctUc >= self.ucMax:
                    removeCharGroup(string.ascii_uppercase)
            elif char in string.ascii_lowercase:
                ctLc += 1
                if self.lcMax is not None and ctlc >= self.lcMax:
                    removeCharGroup(string.ascii_lowercase)
            elif char in string.digits:
                ctNum += 1
                if self.numMax is not None and ctNum >= self.numMax:
                    removeCharGroup(string.digits)
            elif char in self.specialChars:   # could use string.puncuation
                ctSpec += 1
                if self.specialMax is not None and ctSpec >= self.specialMax:
                    removeCharGroup(self.specialChars  # + self.extraSpecialChars
                                   )

        def removeCharGroup(group):
            self.allChars = ''.join(sorted(set(self.allChars) - set(group)))


        #   M E T H O D   M A I N   C O D E

        if isinstance(preferredlen, str):
            if preferredlen.lower() == 'max':
                preferredlen = self.lenMax
            else:  # not 'max'
                raise UserError(f'Illegal value "{preferredlen}" for'
                                f' preferredlen in genPassword method.')

        # Keep count of each character type to enforce maximums
        ctUc = 0    # count of uc letters so far
        ctLc = 0    # count of lc letters so far
        ctLtrs = 0  # count of any letters so far
        ctNum = 0   # count of numerals so far
        ctSpec = 0  # count of specials so far

        # May have to adjust required quantities, if 1st char restrictions used
        adjUc = self.ucMin         # adjusted qty of upper-case letters
        adjLc = self.lcMin         # adjusted qty of lower-case letters
        adjLtrs = self.lettersMin  # adjusted qty of letters
        adjNum = self.numMin       # adjusted qty of numerals
        adjSpec = self.specialMin  # adjusted qty of special chars

        if self.firstChar is None:  # are there 1st char restrictions?
            firstCharacter = ''  # the 1st char not treated specially
            adjMinLen = self.lenMin    # adjusted minimum password length
            adjMaxLen = self.lenMax    # adjusted maximum password length
            adjPrefLen = preferredlen  # adjusted requested password length
        else:                       # yes, there are 1st char restrictions.
            adjMinLen = self.lenMin - 1    # 1st char handled separately
            adjMaxLen = self.lenMax - 1    # so remainder of password is
            adjPrefLen = preferredlen - 1  # one character shorter.

            firstChrTypes = {'uc':   self.ascii_uppercase,
                             'lc':   self.ascii_lowercase,
                             'ltrs': self.allLetters,
                             'num':  self.digits,
                             'spec': self.firstCharSpecialChars,
                            }  # end firstChrTypes
            firstChrAllowed = ''        # Start constructing seq of allowable
            try:                        #  chars for 1st char of password
                for grp in self.firstChar:
                    firstChrAllowed += firstChrTypes[grp]
            except KeyError:
                firstChrAllowed = ''    # discard previously added groups
                warnings.warn(f'Illegal 1st char group name "{grp}".')

            try:
                firstCharacter = random.choice(firstChrAllowed)
            except IndexError:  # nothing to choose from
                # Cannot choose 1st char because there are no groups
                return None  # no password returned from genPassword
            adjustQuotas(firstCharacter)
            countChars(firstCharacter)

        NofMgroupTable = {'uc':   self.ascii_uppercase,
                          'lc':   self.ascii_lowercase,
                          'ltrs': self.allLetters,
                          'num':  self.digits,
                          'spec': self.specialChars  # + self.extraSpecialChars,
                         }  # end NofMgroupTable

        tries = 0  # How many times have we tried to generate a password for this
                   # method invocation?
        runsAcceptable = False  # runs of same char sufficiently short, init'y no
        while not runsAcceptable:
            if tries >= MAXTRIES:
                raise ProgrammerError(f'Tried {MAXTRIES} times to generate a'
                                      f' password. Giving up.')
            tries += 1
            password = ''  # initialize string to accumulate password chars

            # Choose characters for N-of-M char groups
            if self.NofMgroups is not None:
                groups = list(self.NofMgroups)
                n = groups.pop(0)  # 1st element is the number of required groups
                for _ in range(n): # remaining elements are char group names
                    group = groups.pop(random.randint(0, len(groups)-1))
                    try:
                        char = random.choice(NofMgroupTable[group])
                    except KeyError:
                        raise UserError(f'No such group "{group}" in N-of-M')
                    password += char
                    adjustQuotas(char)
                    countChars(char)

            # Satisfy required quantities of char types in rest of password
            charTypeMins = ((self.ascii_uppercase,   adjUc),
                            (self.ascii_lowercase,   adjLc),
                            (self.allLetters,        adjLtrs),
                            (self.digits,            adjNum),
                            (self.specialChars
                             #  + self.extraSpecialChars
                             , adjSpec),
                           )
            for (chars, qty) in charTypeMins:
                for n in range(qty):
                    char = random.choice(chars)
                    password += char
                    countChars(char)

            # Choose additional characters to reach password's target length
            adjActualLen = min(adjMaxLen, adjPrefLen)
            actualLen = adjActualLen + (0 if self.firstChar is None else 1)
            prefLen   = adjPrefLen   + (0 if self.firstChar is None else 1)
            if actualLen < prefLen:
                warnings.warn(f'Requested password length ({prefLen}) reduced to'
                              f' the maximum ({actualLen}) allowed by this ruleset.')
            for n in range(max(adjMinLen, actualLen)
#                              min(adjMaxLen, adjPrefLen))
                           - len(password)):
                if fill:  # Be careful with this feature.  It can create
                          #   illegal runs of same characters if
                          #   the site specifies that restriction.
                    char = '\xb0'  # degree sign
                    password += char
                else:
                    char = random.choice(self.allChars)
                    password += char
                countChars(char)

            # Shuffle password characters, except 1st char if restricted.
            # Then prepend the 1st char with restrictions to the password.
            password = firstCharacter + shuffle(password)

            # Check that neither first nor last chars of password are spaces.
            if password[0] == ' ' or password[-1] == ' ':
                continue

            # Check for illegally long runs of same character
            if self.maxRun is None:  # no limit on character runs
                runsAcceptable = True
            else:
                for i in range(len(password) - self.maxRun):
                    if (password[i+1 : i+self.maxRun+1]
                          == password[i] * self.maxRun):
                        if test:
                            print(f'Too many chars in run "{password}"...retrying')
                        if self.maxRun == 0:  # Zero is useful for testing
                            self.maxRun = None  # stop infinite loop
                        break
                else:  # didn't break out of loop
                    runsAcceptable = True
        return password

    def __str__(self):
        return f'Pswd Generator Ruleset for domain {self.domain}'

    def __repr__(self):
        def minmax(label: str):
            colWidth = 9
            minDflt = 0
            minVal = getattr(self, label+'Min')
            maxVal = getattr(self, label+'Max')
            if minVal == minDflt and maxVal is None:
                line = ''
            else:
                if minVal == minDflt:
                    minCol = ' ' * colWidth
                else:
                    minCol = f'min {minVal}'.ljust(colWidth)
                if maxVal is None:
                    maxCol = ''
                else:
                    maxCol = f'max {maxVal}'.ljust(colWidth)
                line = f'\n\t {(label+':').ljust(9)}{minCol}{maxCol}'
            return line

        value = f'Pswd Generator Ruleset for domain {self.domain}'
        value += minmax('len')
        value += minmax('uc')
        value += minmax('lc')
        value += minmax('letters')
        value += minmax('num')
        value += minmax('special')
        if self.specialChars != PasswordGen.asciiSpecialChars:
            value += f'\n\t specialChars = {self.specialChars}'
        if (self.extraSpecialChars is not None
              and len(self.extraSpecialChars) > 0):
            value += f'\n\t extraSpecialChars = {self.extraSpecialChars}'
        if len(self.otherChars) > 0:
            value += f'\n\t otherChars = {self.otherChars}'
        if self.NofMgroups is not None:
            value += f'\n\t n_of_m_groups = {self.NofMgroups}'
        if self.firstChar is not None:
            value += f'\n\t firstchar = {self.firstChar}'
        if self.firstCharSpecialChars != self.specialChars:
            value += f'\n\t firstCharSpecialChars = {self.firstCharSpecialChars}'
        if self.spacesAllowed:
            value += f'\n\t Spaces allowed'
        if not self.caseSensitive:
            value += f'\n\t NOT sensitive to case'
        return value


#   R U L E   S E T S

# Mobile apps have a top-level domain of "app".

pswdGens = {
    (dom := 'aa.com'): PasswordGen(domain=dom,  # American Airlines
        lenmin=5, lenmax=16),
    (dom := 'aaa.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=31, num=1, letters=1, ruleschecked='2026-08-14',
        specialchars='^.-!@#{}~$_', special=0, history=1),
    (dom := 'aarp.org'): PasswordGen(domain=dom,
        lenmin=8, lenmax=64, spacesallowed=True, ruleschecked='2026-08-14'),
    (dom := 'actalis.it'): PasswordGen(domain=dom,
        lenmin=8, lenmax=16, uc=1, lc=1, num=1, special=1,
        specialchars='$%!?-_', extraspecialchars=GBP, ruleschecked='2026-08-14'),
    (dom := 'actblue.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, ruleschecked='2026-08-14'),
    (dom := 'adorama.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=100, uc=0, lc=0, num=0, special=0, spacesallowed=True,
        ruleschecked='2026-08-14'),
    (dom := 'aliexpress.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=20, ruleschecked='2026-08-14'),
    (dom := 'alltrails.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=128, ruleschecked='2026-08-19'),
    (dom := 'americastestkitchen.com'): PasswordGen(domain=dom,
        lenmin=1, uc=0, num=0, special=0, ruleschecked='2026-08-19'),
    (dom := 'americanexpress.com'): PasswordGen(domain=dom,
        lenmin=8, spacesallowed=True, history=2, ruleschecked='2026-08-19'),
    (dom := 'anvil.works'): PasswordGen(domain=dom,
        lenmin=1, uc=0, num=0, special=0, ruleschecked='2026-08-19'),
    (dom := 'aplus.net'): PasswordGen(domain=dom,
        lenmin=10, lenmax=32, uc=1, lc=1, num=2, special=1,
        specialchars='~!@#$%^&*()-_+={}<>/?', ruleschecked='2026-08-19'),
    (dom := 'aquasana.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'att.com'): PasswordGen(domain=dom,  # AT&T
        lenmin=8, lenmax=24, specialchars='!#$*-_=+?'),
    (dom := 'avast.com'): PasswordGen(domain=dom,  # Avast! Antivirus
        lenmin=8, lenmax=50, uc=1, lc=1, num=1, special=1, ruleschecked='2026-08-19'),
    (dom := 'badlandsranch.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, special=1, specialchars='!&$%^*@',
        ruleschecked='2026-08-11'),
    (dom := 'bestwestern.com'): PasswordGen(domain=dom,
        lenmin=10, num=1, special=1, history=4, ruleschecked='2026-08-19'),
    (dom := 'bhphotovideo.com'): PasswordGen(domain=dom,  # B&H Photo (NYC)
        lenmin=8, letters=2, num=2, special=2),
    (dom := 'bit.ly'): PasswordGen(domain=dom,
        lenmin=6, letters=1, num=1, special=1),
    (dom := 'bosch-home.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'breville.com'): PasswordGen(domain=dom,
        lenmin=6, num=1),
    (dom := 'choicehotels.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=44, special=1, history=0),  # all specialchars OK
    (dom := 'citi.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=64, uc=1, lc=1, num=1, maxrun=2, spacesallowed=False,
        specialchars='~`!@#$%^&*()_-\\/|', special=1, ruleschecked='2026-08-26'),
    (dom := 'citizensbankonline.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=24, letters=1, num=1, spacesallowed=False,
        specialchars='`~!@#$%^&*()-_=+[]{}|;:\',./<>?'),
    (dom := 'costco.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=16, uc=1, lc=1, num=1, special=1,
        specialchars='!@#$&', spacesallowed=False),  # no < >
    (dom := 'culturaldistrict.org'): PasswordGen(domain=dom,  # Pgh Cultural District
        lenmin=8, uc=1, num=1, special=1),
    (dom := 'customerfeed.com'): PasswordGen(domain=dom,  # Highmark BCBS Secure Msg Ctr
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'cvs.com'): PasswordGen(domain=dom,
        lenmin=10, lenmax=64, uc=1, lc=1, num=1, special=1,
        specialchars='/@$%&'),
    (dom := 'delish.com'): PasswordGen(domain=dom,
        lenmin=8, num=1, special=1),
    (dom := 'delta.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, uc=1, lc=1, num=1, special=(0, 3),
        specialchars='`~!#$%^&*()-_=+[]{}\\|;:\'",./>?'),
    (dom := 'dentalplans.com'): PasswordGen(domain=dom,  # Aetna Dental Access
        lenmin=8, lenmax=260,  # maybe more than 260
        uc=1, lc=1, num=1, special=1,  # others (punc not special) allowed too
        specialchars='#$!@&', spacesallowed=True, ruleschecked='2026-08-14',
        otherchars='`~%^*()-_=+[]{}\\|;:\'",./<>?'),
    (dom := 'disneyplus.com'): PasswordGen(domain=dom,
        lenmin=6, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'dollarbank.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=10, letters=1, num=1, casesensitive=False,
        specialchars='!@#$%&*_+-=?()', special=0),
    (dom := 'e-zpassny.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=64, uc=1, lc=1, num=1, special=1,
        specialchars='!@#$%*()-_+=~;,.'),
    (dom := 'experian.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=35, uc=1, lc=1, num=1, special=1,
        specialchars='_@~!?#$^*+=:;,|/()&{}[\\.-'),
    (dom := 'fandango.com'): PasswordGen(domain=dom,
        lenmin=8, lc=1, num=1, spacesallowed=False),  # maxrun=3 ?
    (dom := 'fcc.gov'): PasswordGen(domain=dom,  # FCC Commission Registration System (CORES)
        lenmin=12, lenmax=15, uc=1, lc=1, num=1, special=1,
        specialchars='@%+=/\'"!#$^?:;,(){}[]~`-_*&<>\\|.'),
    (dom := 'fidelity.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=20,
        specialchars='`~!@$%^()-_=+\\|;:",./?'),
    (dom := 'gofundme.com'): PasswordGen(domain=dom,
        lenmin=12, uc=1, lc=1, num=1, special=1),
    (dom := 'goingtocamp.com'): PasswordGen(domain=dom,  # Wisconsin State Park System
        lenmin=8, uc=1, lc=1, num=1, special=0),
    (dom := 'goodhousekeeping.com'): PasswordGen(domain=dom,
        lenmin=8, num=1, special=1),
    (dom := 'guardianprotection.com'): PasswordGen(domain=dom,
        lenmin=7, uc=1, lc=1, num=1),
    (dom := 'guardianprotection.app'): PasswordGen(domain=dom,
        lenmin=10, letters=1, num=1, special=1),
    (dom := 'hbr.org'): PasswordGen(domain=dom,  # Harvard Business Review
        lenmin=8, uc=1, lc=1, num=1, special=1, specialchars='@!#$%^&+='),
    (dom := 'hertz.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, special=1, specialchars='#$%^&'),
    (dom := 'highmarkbcbs.com'): PasswordGen(domain=dom,
        lenmin=12, uc=1, lc=1, num=1, special=1,
        specialchars='`~!@#$%^&*()-_=[]{}\\|;:\'",./?'),
    (dom := 'higi.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=30),
    (dom := 'homedepot.com'): PasswordGen(domain=dom,
        lenmin=9, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'homeagain.com'): PasswordGen(domain=dom,  # HomeAgain Pet Recovery
        lenmin=8, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'hotels.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=20, num=1),
    (dom := 'hotmail.com'): PasswordGen(domain=dom,
        lenmin=8, n_of_m_groups=(2, 'uc', 'lc', 'num', 'spec')),
    (dom := 'hulu.com'): PasswordGen(domain=dom,
        lenmin=6, uc=0, lc=0, letters=0, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'id.me'): PasswordGen(domain=dom,  # ID.me (IRS)
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'idoxs.net'): PasswordGen(domain=dom,  # PWSA
        lenmin=8, lenmax=15, uc=1, lc=1, num=1, special=0,
        specialchars='!.#%&*'),
    (dom := 'irs.gov'): PasswordGen(domain=dom,  # ID.me (IRS)
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'jccpgh.org'): PasswordGen(domain=dom,
        lenmin=8, lenmax=130,  # maybe more than 130
        letters=1, num=1, ruleschecked='2026-08-19'),
    (dom := 'kraken.com'): PasswordGen(domain=dom,
        lenmin=8, letters=1, num=1, special=1),
    (dom := 'laundryvalue.app'): PasswordGen(domain=dom,
        specialchars='', special=0),
    (dom := 'live.com'): PasswordGen(domain=dom,  # Microsoft outlook hotmail
        lenmin=8, n_of_m_groups=(2, 'uc', 'lc', 'num', 'spec')),
    (dom := 'logitech.com'): PasswordGen(domain=dom,
        lenmin=10),
    (dom := 'lowes.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=128, letters=1, num=1, maxrun=3, spacesallowed=False),
    (dom := 'manuscriptcentral.com'): PasswordGen(domain=dom,  # Scholar One Manuscripts - Orcid
        lenmin=8, num=2),
    (dom := 'marriott.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec'),
        specialchars='$!#&@?%=_'),
    (dom := 'meetup.com'): PasswordGen(domain=dom,
        lenmin=10),
    (dom := 'microsoft.com'): PasswordGen(domain=dom,  # Microsoft account
        lenmin=4, lenmax=127),
    (dom := 'MorganStanleyClientServ.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, special=(0, 0), history=3,
        specialchars='', spacesallowed=False),
    (dom := 'moveon.org'): PasswordGen(domain=dom,
        lenmin=8),
    (dom := 'myequifax.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, uc=1, lc=1, num=1,
        special=1, specialchars='!@$*+-'),
    (dom := 'mymedicare.gov'): PasswordGen(domain=dom,
        lenmin=8, lenmax=16, letters=1, num=1, special=1,
        specialchars='@!$%^*()', history=6),
    (dom := 'myprepaidcenter.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, uc=1, lc=1, num=1, special=1,
        specialchars='!@#$%&'),
    (dom := 'mytrueidentity.com'): PasswordGen(domain=dom,  # TransUnion
        lenmin=12, lenmax=64),
    (dom := 'nationwide.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=30, uc=1, lc=1, num=1, special=1,
        specialchars='!#$+,-./\\:=?@[]_{}|~', spacesallowed=False),
    (dom := 'nbc.com'): PasswordGen(domain=dom,
        lenmin=10, uc=1, lc=1),
    (dom := 'netacad.com'): PasswordGen(domain=dom,  # Cisco Networking Academy
        lenmin=8, uc=1, lc=1, num=1, special=1, history=3),
    (dom := 'netflix.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=60),
    (dom := 'newegg.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=30, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'nist.gov'): PasswordGen(domain=dom,  # Voting TWiki
        lenmin=12, lenmax=32, uc=1, lc=1, num=1, special=1),
    (dom := 'nvidia.com'): PasswordGen(domain=dom,
        lenmin=9, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'onsolve.net'): PasswordGen(domain=dom,  # Allegheny Alerts
        lenmin=8, specialchars='!@#$%^&*()'),
    (dom := 'openai.com'): PasswordGen(domain=dom,  # ChatGPT
        lenmin=8),
    (dom := 'opendns.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, special=1),
    (dom := 'pa.us'): PasswordGen(domain=dom,  # HHS Keystone ID (PA Child Abuse clearances)
        lenmin=8, lenmax=14, uc=1, lc=1, special=1, specialchars='@&*%$^'),
    (dom := 'panerabread.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=20),
    (dom := 'partswarehouse.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'pbs.org'): PasswordGen(domain=dom,
        lenmin=8, letters=1, num=1),
    (dom := 'penzeys.com'): PasswordGen(domain=dom,
        lenmin=4, lenmax=20),
    (dom := 'peopleseaccount.com'): PasswordGen(domain=dom,  # Peoples Natural Gas
        lenmin=8, lenmax=32, uc=1, lc=1, num=1,
        specialchars='!@#$%*_-', special=1),
    (dom := 'petco.com'): PasswordGen(domain=dom,
        lenmin=12, specialchars='!@#$%^&*',
        n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'pghartsmedia.org'): PasswordGen(domain=dom,  # Pittsburgh Center for the Arts PF/PCA
        lenmin=8, uc=1, lc=3, num=1, special=1),
    (dom := 'pnc.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, letters=1, num=1, maxrun=2, spacesallowed=False,
        specialchars='`@#$%*()-_=+;:,.?'),
    (dom := 'privateinternetaccess.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'promasterforum.com'): PasswordGen(domain=dom,
        lenmin=8),
    (dom := 'quora.com'): PasswordGen(domain=dom,
        lenmin=8),
    (dom := 'reserveamerica.com'): PasswordGen(domain=dom,  # Pennsylvania (PA) State Parks - DCNR
        lenmin=8, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'scribd.com'): PasswordGen(domain=dom,
        lenmin=10, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    (dom := 'securevetsource.com'): PasswordGen(domain=dom,  # Point Breeze Vet Clinic pharmacy - Vetsource
        lenmin=8, uc=1, lc=1, num=1),
    (dom := 'sharefile.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, special=1),
    (dom := 'solaredge.com'): PasswordGen(domain=dom,
        lenmin=8, letters=1, num=1),
    (dom := 'ssa.gov'): PasswordGen(domain=dom,  # my Social Security
        lenmin=8, lenmax=64, uc=1, lc=1, num=1, special=1,
        specialchars='!@#$%^&*', firstchar=('uc', 'lc', 'num')),
    (dom := 'staples.com'): PasswordGen(domain=dom,
        lenmin=8, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec'),
        ruleschecked='2026-08-28'),
    (dom := 'synology.com'): PasswordGen(domain=dom,
        lenmin=8, n_of_m_groups=(2, 'uc', 'lc', 'num')),
    (dom := 'tiaa-cref.org'): PasswordGen(domain=dom,
        lenmin=6, lenmax=20, specialchars='', special=(0, 0)),
    (dom := 'ticketmaster.com'): PasswordGen(domain=dom,
        lenmin=8, letters=1, num=1),
    (dom := 'topcoder.com'): PasswordGen(domain=dom,
        lenmin=8, letters=1, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'trainingmagnetwork.com'): PasswordGen(domain=dom,
        lenmin=8),
    (dom := 'tranehome.com'): PasswordGen(domain=dom,
        uc=1, lc=1, num=1),
    (dom := 'transunion.com'): PasswordGen(domain=dom,
        lenmin=12, lenmax=64),
    (dom := 'tvguide.com'): PasswordGen(domain=dom,
        lenmin=6),
    (dom := 'upmc.com'): PasswordGen(domain=dom,  # HealthTrak
        lenmin=8, uc=1, lc=1, num=1, special=1),
    (dom := 'upmchealthplan.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=14, uc=1, lc=1, num=1),
    (dom := 'ups.com'): PasswordGen(domain=dom,  # My Choice
        lenmin=12, lenmax=26, uc=1, lc=1, num=1,
        specialchars='!@#$%*', special=1),
    (dom := 'vectorsecurity.com'): PasswordGen(domain=dom,
        lenmin=6, uc=1, n_of_m_groups=(1, 'num', 'spec')),
    (dom := 'verizonwireless.com'): PasswordGen(domain=dom,
        lenmin=8, lenmax=20, letters=1, num=1),
    (dom := 'vitalant.com'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1, special=1),
    (dom := 'warwickhotels.com'): PasswordGen(domain=dom,
        lenmin=6, lenmax=17, num=1),
    (dom := 'washingtonpost.com'): PasswordGen(domain=dom,
        lenmin=8, specialchars='!"#$%&\'()*+,-./:;=?@[\\]^_{}~', special=1),
    (dom := 'wdc.com'): PasswordGen(domain=dom,  # Western Digital support
        lenmin=8, lenmax=999, letters=1, num=1, history=3),
    (dom := 'wicklespickles.com'): PasswordGen(domain=dom,
        lenmin=12),
    (dom := 'zoom.us'): PasswordGen(domain=dom,
        lenmin=8, uc=1, lc=1, num=1),
    }  # end pswdGens

#for (domain, ruleset) in pswdGens.items():
#    if len(ruleset.domain) == 0:
#        ruleset.domain = domain


#   M A I N   C O D E

normalExit = 0  #  Linux result codes returned to OS:  0 = normal, else = abnormal

def selftest(args):
    fill = False
    noPause = False
    for n in range(0, len(args)):
        if args[n] == 'fill':
            fill = True
        elif args[n] == 'nopause':
            noPause = True

    try:
        pswdGens['testbadspecialchars'] = PasswordGen(
            lenmin=6, lenmax=10, specialchars='$x*3-')
    except UserError:
        pass

    pswdGens['testbadrun'] = PasswordGen(
        lenmin=6, lenmax=10, maxrun=0)
    pswdGens['testbad1stchar'] = PasswordGen(  # my Social Security
        lenmin=8, lenmax=64, specialchars='!@#$%^&*',
        firstchar=('uc', 'lc', 'num', 'junk'))
    pswdGens['short3of4'] = PasswordGen(
        lenmin=3, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec'))
    pswdGens['confusable'] = PasswordGen(
        allowconfusables=False, confusablechars='Il1|!O0',
        firstchar=('ltrs','num','spec'),
        n_of_m_groups=(2, 'ltrs','num','spec'),
        specialchars='`~@#%^&*()-_=+[]{}\\|;:\'",./<>?', otherchars='$!',
        extraspecialchars=GBP)

    costcopswd = pswdGens['costco.com'].genPassword(fill=fill)
    print(f'For costco.com (default preferred length):  {costcopswd}')

    costcopswd2 = pswdGens['costco.com'].genPassword(24, fill=fill)
    print(f'For costco.com (preferred length 24):       {costcopswd2}')

    badrun = pswdGens['testbadrun'].genPassword(7, test=True)
    print(f'For testbadrun (preferred length 7):        {badrun}')

    ssapswd = pswdGens['ssa.gov'].genPassword(fill=fill)
    print(f'For ssa.gov (1st char must be ltr or num):  {ssapswd}')

    homedepot = pswdGens['homedepot.com'].genPassword(3, fill=fill)
    print(f'For homedepot.com (3 of uc, lc, num, spec): {homedepot}')

    short3of4 = pswdGens['short3of4'].genPassword(3, fill=fill)
    print(f'For short3of4 (3 of uc, lc, num, spec):     {short3of4}')

    confused = pswdGens['confusable']
    confusedPswd = confused.genPassword(60)
    print(f'confused pswd = {confusedPswd}')
    print(f'Confused strings:\n\t specialchars = {confused.specialChars}'
          f'\n\t extraSpecialChars = {confused.extraSpecialChars}'
          f'\n\t otherchars = {confused.otherChars}'
          f'\n\t firstCharSpecialChars = {confused.firstCharSpecialChars}'
          f'\n\t Upper case: {confused.ascii_uppercase}'
          f'\n\t Lower case: {confused.ascii_lowercase}'
          f'\n\t Letters: {confused.ascii_letters}'
          f'\n\t Numerals: {confused.digits}'
          )
    strings = ('specialChars', 'extraSpecialChars',
               'otherChars', 'firstCharSpecialChars')
    for name in strings:
        for char in confused.confusableChars:
            if char in getattr(confused, name):
                print(f'Confusable "{char}" found in {name}.')
    for char in confused.confusableChars:
        if char in confusedPswd:
            print(f'Confusable {char} found in password.')
    try:
        bad1stcharpswd = pswdGens['testbad1stchar'].genPassword(fill=fill)
        print(f'For bad1stcharpswd (default preferred length):  {bad1stcharpswd}')
    except UserError:
        pass


    if not noPause:
        try:
            input('\nPausing so user can read output.'
                  '  Press "Enter" when ready. ')
        except EOFError:
            pass

    return normalExit

if __name__ == '__main__':
    sys.exit(selftest(sys.argv[1:]))  # skip module filename