# passwordgen.py
'''Establish sets of rules for generating passwords.'''

#   I M P O R T S
import random  # choice(), X-shuffle()-X
import string  # ascii_uppercase, ascii_lowercase, ascii_letters, digits,
               #    punctuation
import sys     # exit(), argv[]

from exceptions import *


#   M O D U L E   V A R I A B L E S

pswdGens = {}  # dict w/DNS domains for keys, PasswordGen instances for values.


class PasswordGen:
    '''Rules for generating passwords for a particular site.'''

    #   M E T H O D S

    def __init__(self, *, uc: int = 1, lc: int = 1, letters: int = 1,
                          num: int = 1,
#                         specials: str = '`~!@#$%^&*()-_=+[]{}\\|;:\'",./<>?',
                          specials: str = string.punctuation,
                          specialsqty = 1, minlen: int = 8, maxlen: int = 999,
                          maxrun: int | NoneType = None,
                          nofmgroups: tuple | NoneType = None,
                          firstchar: tuple | NoneType = None,
                          firstcharspecials: str | NoneType = None,
                          history: int = 0, spacesallowed: bool = False):
        '''Initializer sets the types and quantities of required characters.

        If a site specifies a number of required letters, but not numbers of
        required upper-case or lower-case letters, set uc and lc to zero.
        If a site specifies numbers of upper-case and lower-case letters, but
        not a number of letters with unspecified case, set letters to no more
        than the sum of uc & lc; or just set it to zero.
        '''

        if minlen > maxlen:
            raise UserError(f'Minimum password length ({minlen}) may'
                            f' not be greater than maximum length ({maxlen}).')
        self.uc = uc                  # nbr of req'd Upper-case letters
        self.lc = lc                  # nbr of req'd Lower-case letters
        self.letters = letters        # nbr of req'd letters (when uc & lc not
                                      #    specified)
        self.num = num                # nbr of req'd numerals
        self.specials = specials      # string of all allowable special chars
        self.specialsQty = specialsqty  # nbr of req'd special characters
        self.minLen = minlen          # minimum allowable length of password
        self.maxLen = maxlen          # maximum allowable length of password
        self.maxRun = maxrun          # allowable consecutive same character
        self.NofMgroups = nofmgroups  # req'r chars from n groups of m indicated
        self.firstChar = firstchar    # restrict 1st char to chars in these grps
        if firstcharspecials is None:
            self.firstCharSpecials = specials  # allowed in first char
        self.history = history        # pswd cannot match last n passwords
#       self.spacesAllowed = spacesallowed
        self.allChars = (string.ascii_letters
                         + string.digits
                         + specials
                         + (' ' if spacesallowed else '')
                        )

    def genPassword(self, preferredlen: int = 12, *, test=False):
        '''Generate a password for a particular site.'''

        def shuffle(chars: str) -> str:
            charsList = list(chars)
            shuffled = ''
            while len(charsList) > 0:
                shuffled += charsList.pop(random.randint(0, len(charsList)-1))
            return shuffled

        firstChrTypes = {'uc':   string.ascii_uppercase,
                         'lc':   string.ascii_lowercase,
                         'num':  string.digits,
                         'spec': self.firstCharSpecials,
                        }  # end firstChrTypes
        adjUc = self.uc
        adjLc = self.lc
        adjLtrs = self.letters
        adjNum = self.num
        adjSpecQty = self.specialsQty
        if self.firstChar is None:  # are there 1st char restrictions?
            firstCharacter = ''
            adjMinLen = self.minLen
            adjMaxLen = self.maxLen
            adjPrefLen = preferredlen
        else:                       # yes
            adjMinLen = self.minLen - 1
            adjMaxLen = self.maxLen - 1
            adjPrefLen = preferredlen - 1
        runsAcceptable = False
        while not runsAcceptable:
            if self.firstChar is not None:  # are there 1st char restrictions?
                firstChrAllowed = ''
                try:
                    for grp in self.firstChar:
                        firstChrAllowed += firstChrTypes[grp]
                except KeyError:
                    raise UserError(f'Illegal 1st char group name "{grp}".')
                firstCharacter = random.choice(firstChrAllowed)
                if firstCharacter in string.ascii_letters:
                    adjLtrs -= 1
                if firstCharacter in string.ascii_uppercase:
                    adjUc -= 1
                elif firstCharacter in string.ascii_lowercase:
                    adjLc -= 1
                elif firstCharacter in string.digits:
                    adjNum -= 1
                elif firstCharacter in self.specials:
                    adjSpecQty -= 1
            charTypeMins = ((string.ascii_uppercase, adjUc),
                            (string.ascii_lowercase, adjLc),
                            (string.ascii_letters, adjLtrs - adjUc - adjLc),
                            (string.digits, adjNum),
                            (self.specials, adjSpecQty),
                           )

            password = ''
            # Choose required quantity of characters of required types
            for (chars, qty) in charTypeMins:
                for n in range(qty):
                    password += random.choice(chars)
            # Choose additional characters to reach password's target length
            for n in range(max(adjMinLen,
                               min(adjMaxLen, adjPrefLen))
                           - len(password)):
                password += random.choice(self.allChars)
            password = firstCharacter + shuffle(password)
            # Check for illegally long runs of same character
            if self.maxRun is None:
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

#   R U L E   S E T S

# Mobile apps have a top-level domain of "app".

pswdGens = {
    'testbadrun': PasswordGen(
        minlen=6, maxlen=10, maxrun=0),
    'testbad1stchar': PasswordGen(  # my Social Security
        minlen=8, maxlen=64, specials='!@#$%^&*',
        firstchar=('uc', 'lc', 'num', 'junk')),
    'aaa.com': PasswordGen(
        minlen=6, maxlen=31, uc=0, lc=0, specials='^-!@#{}~$_', specialsqty=0),
    'onsolve.net': PasswordGen(  # Allegheny Alerts
        minlen=8, uc=0, lc=0, letters=0, num=0,
        specials='!@#$%^&*()', specialsqty=0),
    'badlandsranch.com': PasswordGen(
        minlen=8, specials='!&$%^*@'),
    'bit.ly': PasswordGen(
        minlen=6, uc=0, lc=0),
    'breville.com': PasswordGen(
        minlen=6, uc=0, lc=0, letters=0, specialsqty=0),
    'openai.com': PasswordGen(  # ChatGPT
        minlen=8, uc=0, lc=0, letters=0, num=0, specialsqty=0),
    'choicehotels.com': PasswordGen(
        minlen=8, maxlen=44, uc=0, lc=0, letters=0, num=0, specialsqty=0),
    'netacad.com': PasswordGen(  # Cisco Networking Academy
        minlen=8, history=3),
    'citi.com': PasswordGen(
        minlen=8, maxlen=64, uc=0, lc=0, maxrun=2,
        specials='~`!@#$%^&*()_-\\/|', specialsqty=0),
    'citizensbankonline.com': PasswordGen(
        minlen=8, maxlen=24, uc=0, lc=0, spacesallowed=False,
        specials='`~!@#$%^&*()-_=+[]{}|;:\',./<>?'),
    'costco.com': PasswordGen(
        minlen=8, maxlen=16, specials='!@#$&', spacesallowed=False),
    'cvs.com': PasswordGen(
        minlen=10, maxlen=64, specials='/@$%&'),
    'delish.com': PasswordGen(
        minlen=8, uc=0, lc=0, letters=0),
    'delta.com': PasswordGen(
        minlen=8, maxlen=20, specials='`~!#$%^&*()-_=+[]{}\\|;:\'",./>?'),
    'disneyplus.com': PasswordGen(
        minlen=6, uc=0, lc=0, letters=0),
    'dollarbank.com': PasswordGen(
        minlen=6, maxlen=10, uc=0, lc=0,
        specials='!@#$%&*_+-=?()', specialsqty=0),
    'e-zpassny.com': PasswordGen(
        minlen=8, maxlen=64, specials='!@#$%*()-_+=~;,.'),
    'experian.com': PasswordGen(
        minlen=8, maxlen=35, specials='_@~!?#$^*+=:;,|/()&{}[\\.-'),
    'fandango.com': PasswordGen(
        minlen=8, uc=0, lc=0, maxrun=3),
    'fcc.gov': PasswordGen(  # FCC Commission Registration System (CORES)
        minlen=12, maxlen=15, specials='@%+=/\'"!#$^?:;,(){}[]~`-_*&<>\\|.'),
    'fidelity.com': PasswordGen(
        minlen=6, maxlen=20, uc=0, lc=0, letters=2, num=0,
        specials='`~!@$%^()-_=+\\|;:",./?'),
    'gofundme.com': PasswordGen(
        minlen=12),
    'goodhousekeeping.com': PasswordGen(
        minlen=8, uc=0, lc=0, letters=0),
    'guardianprotection.com': PasswordGen(
        minlen=7, specialsqty=0),
    'guardianprotection.app': PasswordGen(
        minlen=10, uc=0, lc=0),
    'hbr.org': PasswordGen(  # Harvard Business Review
        minlen=8, specials='@!#$%^&+='),
    'hertz.com': PasswordGen(
        minlen=8, specials='#$%^&'),
    'pa.us': PasswordGen(  # HHS Keystone ID (PA Child Abuse clearances)
        minlen=8, maxlen=14, num=0, specials='@&*%$^'),
    'highmarkbcbs.com': PasswordGen(
        minlen=12, specials='`~!@#$%^&*()-_=[]{}\\|;:\'",./?'),
    'customerfeed.com': PasswordGen(  # Highmark BCBS Secure Msg Ctr
        minlen=8, specialsqty=0),
    'homedepot.com': PasswordGen(
        minlen=9),  # 3 of uc, lc, num, spec
    'homeagain.com': PasswordGen(  # HomeAgain Pet Recovery
        minlen=8),  # 3 of uc, lc, num, spec
    'hotels.com': PasswordGen(
        minlen=6, maxlen=20, uc=0, lc=0, letters=0, specialsqty=0),
    'hotmail.com': PasswordGen(
        minlen=8),  # 2 of uc, lc, num, spec
    'live.com': PasswordGen(  # Microsoft outlook hotmail
        minlen=8),  # 2 of uc, lc, num, spec
    'id.me': PasswordGen(  # ID.me (IRS)
        minlen=8, specialsqty=0),
    'irs.gov': PasswordGen(  # ID.me (IRS)
        minlen=8, specialsqty=0),
    'kraken.com': PasswordGen(
        minlen=8, uc=0, lc=0),
    'laundryvalue.app': PasswordGen(
        specials='', specialsqty=0),
    'lowes.com': PasswordGen(
        minlen=8, maxlen=128, uc=0, lc=0, specialsqty=0, maxrun=3),
    'marriott.com': PasswordGen(
        minlen=8, maxlen=20, specials='$!#&@?%=_'),
    'meetup.com': PasswordGen(
        minlen=10),
    'microsoft.com': PasswordGen(  # Microsoft account
        minlen=4, maxlen=127, uc=0, lc=0, letters=0, num=0, specialsqty=0),
    'MorganStanleyClientServ.com': PasswordGen(
        minlen=8, maxlen=20, uc=0, lc=0, specialsqty=0, history=3),
    'moveon.org': PasswordGen(
        minlen=8, uc=0, lc=0, letters=0, num=0, specialsqty=0),
    'ssa.gov': PasswordGen(  # my Social Security
        minlen=8, maxlen=64, specials='!@#$%^&*',
        firstchar=('uc', 'lc', 'num')),
    'bosch-home.com': PasswordGen(
        minlen=8, specialsqty=0),
    'hulu.com': PasswordGen(
        minlen=6, uc=0, lc=0, letters=0),  # 1 of num | spec
    'myequifax.com': PasswordGen(
        minlen=8, maxlen=20, specials='!@$*+-'),
    'mymedicare.gov': PasswordGen(
        minlen=8, maxlen=16, uc=0, lc=0, specials='@!$%^*()', history=6),
    'myprepaidcenter.com': PasswordGen(
        minlen=8, maxlen=20, specials='!@#$%&'),
    }  # end pswdGens


#   M A I N   C O D E

normalExit = 0

def selftest(args):
    costcopswd = pswdGens['costco.com'].genPassword()
    print(f'For costco.com (default preferred length):  {costcopswd}')
    costcopswd2 = pswdGens['costco.com'].genPassword(24)
    print(f'For costco.com (preferred length 24):       {costcopswd2}')
    badrun = pswdGens['testbadrun'].genPassword(7, test=True)
    print(f'For testbadrun (preferred length 7):        {badrun}')
    ssapswd = pswdGens['ssa.gov'].genPassword()
    print(f'For ssa.gov (1st char must be ltr or num):  {ssapswd}')
    bad1stcharpswd = pswdGens['testbad1stchar'].genPassword()
    print(f'For bad1stcharpswd (default preferred length):  {bad1stcharpswd}')
    return normalExit

if __name__ == '__main__':
    sys.exit(selftest(sys.argv[1:]))