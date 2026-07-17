# passwordgen.py
'''Establish sets of rules for generating passwords.'''
    
#   I M P O R T S
import random  # choice(), shuffle()
import string  # ascii_uppercase, ascii_lowercase, ascii_letters, digits,
               #    punctuation
import sys     # exit(), argv[]

from exceptions import *


#   M O D U L E   V A R I A B L E S

pswdGens = {}  # dict w/DNS domains for keys, PasswordGen instances for values.


class PasswordGen:
    '''Rules for generating passwords for a particular site.'''

    #   M E T H O D S

    def __init__(self, /, uc: int = 1, lc: int = 1, letters: int = 1,
                          num: int = 1,
#                         specials: str = '`~!@#$%^&*()-_=+[]{}\\|;:\'",./<>?',
                          specials: str = string.punctuation,
                          specialsqty = 1, minlen: int = 8, maxlen: int = 999,
                          maxrun: int | NoneType = None, history: int = 0,
                          spacesallowed: bool = False):
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
        self.history = history        # pswd cannot match last n passwords
#       self.spacesAllowed = spacesallowed
        self.allChars = (string.ascii_letters
                         + string.digits
                         + specials
                         + (' ' if spacesallowed else '')
                        )

    def genPassword(self, preferredlen: int = 12):
        '''Generate a password for a particular site.'''

        password = ''
        charTypes = ((string.ascii_uppercase, self.uc),
                     (string.ascii_lowercase, self.lc),
                     (string.ascii_letters, self.letters - self.uc - self.lc),
                     (string.digits, self.num),
                     (self.specials, self.specialsQty),
                    )
        for (chars, qty) in charTypes:
            for n in range(qty):
                password += random.choice(chars)
        for n in range(max(self.minLen,
                           min(self.maxLen, preferredlen))
                       - len(password)):
            password += random.choice(self.allChars)
        pswdletters = list(password)
        random.shuffle(pswdletters)
        password = ''.join(pswdletters)

        runsAcceptable = self.maxRun is None
        while not runsAcceptable:
            runTooMany = self.maxRun + 1
            for i in range(len(password) - self.maxRun - 1):
                if password[i:i+runTooMany] == (password[i] * runTooMany):
                    break
            else:  # didn't break out of loop
                runsAcceptable = True
        return password

#   R U L E   S E T S

aaadotcom = PasswordGen(minlen=6, maxlen=31, uc=0, lc=0,
                        specials='^-!@#{}~$_', specialsqty=0)
alleghenyalerts = PasswordGen(minlen=8, uc=0, lc=0, letters=0, num=0,
                              specials='!@#$%^&*()', specialsqty=0)
badlandsranch = PasswordGen(minlen=8, specials='!&$%^*@')
bitly = PasswordGen(minlen=6, uc=0, lc=0)
breville = PasswordGen(minlen=6, uc=0, lc=0, letters=0, specialsqty=0)
chatgpt = PasswordGen(minlen=8, uc=0, lc=0, letters=0, num=0, specialsqty=0)
choiceprivileges = PasswordGen(minlen=8, maxlen=44, uc=0, lc=0, letters=0,
                               num=0, specialsqty=0)
cisconetacad = PasswordGen(minlen=8, history=3)
citicards = PasswordGen(minlen=8, maxlen=64, uc=0, lc=0, maxrun=2,
                        specials='~`!@#$%^&*()_-\\/|', specialsqty=0)
citizensbank = PasswordGen(minlen=8, maxlen=24, uc=0, lc=0,
                           spacesallowed=False,
                           specials='`~!@#$%^&*()-_=+[]{}|;:\',./<>?')
costco = PasswordGen(minlen=8, maxlen=16, specials='!@#$&',
                     spacesallowed=False)
cvsdotcom = PasswordGen(minlen=10, maxlen=64, specials='/@$%&')
delish = PasswordGen(minlen=8, uc=0, lc=0, letters=0)
deltaskymiles = PasswordGen(minlen=8, maxlen=20,
                            specials='`~!#$%^&*()-_=+[]{}\\|;:\'",./>?')
disneyplus = PasswordGen(minlen=6, uc=0, lc=0, letters=0)
dollarbank = PasswordGen(minlen=6, maxlen=10, uc=0, lc=0,
                         specials='!@#$%&*_+-=?()', specialsqty=0)
ezpass = PasswordGen(minlen=8, maxlen=64, specials='!@#$%*()-_+=~;,.')
experian = PasswordGen(minlen=8, maxlen=35,
                       specials='_@~!?#$^*+=:;,|/()&{}[\\.-')
fandango = PasswordGen(minlen=8, uc=0, lc=0, maxrun=3)
fcccores = PasswordGen(minlen=12, maxlen=15,
                       specials='@%+=/\'"!#$^?:;,(){}[]~`-_*&<>\\|.')
fidelitydotcom = PasswordGen(minlen=6, maxlen=20, uc=0, lc=0, letters=0,
                             num=0, specials='`~!@$%^()-_=+\\|;:",./?')
gofundme = PasswordGen(minlen=12)
goodhousekeeping = PasswordGen(minlen=8, uc=0, lc=0, letters=0)
guardianprotection_billing = PasswordGen(minlen=7, specialsqty=0)
guardianprotection_app = PasswordGen(minlen=10, uc=0, lc=0)
harvardbusinessreview = PasswordGen(minlen=8, specials='@!#$%^&+=')
hertzgoldplusrewards = PasswordGen(minlen=8, specials='#$%^&')
hhskeystoneid = PasswordGen(minlen=8, maxlen=14, num=0, specials='@&*%$^')
highmark = PasswordGen(minlen=12, specials='`~!@#$%^&*()-_=[]{}\\|;:\'",./?')
highmarkbcbssecuremsgctr = PasswordGen(minlen=8, specialsqty=0)
homedepot = PasswordGen(minlen=9)  # 3 of uc, lc, num, spec
homeagaindotcom = PasswordGen(minlen=8)  # 3 of uc, lc, num, spec
hotelsdotcom = PasswordGen(minlen=6, maxlen=20, uc=0, lc=0, letters=0,
                           specialsqty=0)
hotmail = PasswordGen(minlen=8)  # 2 of uc, lc, num, spec
iddotme = PasswordGen(minlen=8, specialsqty=0)
kraken = PasswordGen(minlen=8, uc=0, lc=0)
laundryvalue = PasswordGen(specials='', specialsqty=0)
loweshardware = PasswordGen(minlen=8, maxlen=128, uc=0, lc=0, specialsqty=0,
                            maxrun=3)
marriott = PasswordGen(minlen=8, maxlen=20, specials='$!#&@?%=_')
meetupdotcom = PasswordGen(minlen=10)
microsoft = PasswordGen(minlen=4, maxlen=127, uc=0, lc=0, letters=0,
                        num=0, specialsqty=0)
morganstanley = PasswordGen(minlen=8, maxlen=20, uc=0, lc=0,
                            specialsqty=0, history=3)
moveondotorg = PasswordGen(minlen=8, uc=0, lc=0, letters=0, num=0,
                           specialsqty=0)
mysocialsecurity = PasswordGen(minlen=8, maxlen=64,
                               specials='!@#$%^&*')  # 1st char ltr or num
mybosch = PasswordGen(minlen=8, specialsqty=0)
mydisney = PasswordGen(minlen=6, uc=0, lc=0, letters=0)  # 1 of num | spec
myequifax = PasswordGen(minlen=8, maxlen=20, specials='!@$*+-')
mymedicaredotgov = PasswordGen(minlen=8, maxlen=16, uc=0, lc=0,
                               specials='@!$%^*()', history=6)
myprepaidcenter = PasswordGen(minlen=8, maxlen=20, specials='!@#$%&')


#   M A I N   C O D E

normalExit = 0

def selftest(args):
    costcopswd = costco.genPassword()
    print(costcopswd)
    costcopswd = costco.genPassword(24)
    print(costcopswd)
    return normalExit

if __name__ == '__main__':
    sys.exit(selftest(sys.argv[1:]))