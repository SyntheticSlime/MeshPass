# passwordgen.py
'''Establish sets of rules for generating passwords.'''

#   I M P O R T S
import random    # choice(), randint(), X- shuffle()-X
import string    # ascii_uppercase, ascii_lowercase, ascii_letters, digits,
                 #    punctuation
import sys       # exit(), argv[]
import warnings  # warn()

from exceptions import *


#   M O D U L E   V A R I A B L E S

pswdGens = {}  # dict w/DNS domains for keys, PasswordGen instances for values.


class PasswordGen:
    '''Rules for generating passwords for a particular site.'''

    #   M E T H O D S

    def __init__(self, *, uc: int = 0, lc: int = 0, letters: int = 0,
                          num: int = 0,
#                         specials: str = '`~!@#$%^&*()-_=+[]{}\\|;:\'",./<>?',
                          specials: str = string.punctuation,
                          specialsqty = 0, minlen: int = 12, maxlen: int = 63,
                          maxrun: int | NoneType = None,
                          n_of_m_groups: tuple | NoneType = None,
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
        remainder = set(specials) - set(string.punctuation)
        if len(remainder) > 0:
            raise UserError(f'Illegal character(s) in'
                            f' specials argument "{"".join(remainder)}"')
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
        self.NofMgroups = n_of_m_groups  # req'r chars from n groups of m indicated
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
        requiredlen = max(uc + lc, letters) + num + specialsqty # more later?
        if n_of_m_groups is not None:
            if not isinstance(n_of_m_groups[0], int):
                raise UserError(f'1st element of n_of_m_groups'
                                f' "{n_of_m_groups[0]}" must be an integer')
            groups = n_of_m_groups[1:]
            if len(groups) <= n_of_m_groups[0]:
                raise UserError(f'The number of groups ({len(groups)}) is not'
                                f'  greater than the # of required groups'
                                f'({n_of_m_groups[0]}).')
            for grp in groups:
                if grp not in ('uc', 'lc', 'ltrs', 'num', 'spec'):
                    raise UserError(f'Unknown group "{grp}" in N-of-M groups.')
            if ('ltrs' in groups
                and ('uc' in groups
                     or 'lc' in groups)):
                raise UserError('In n_of_m_groups cannot have "ltrs" together'
                                ' with "uc" or "lc".')
            if 'ltrs' in groups and (uc > 0 or lc > 0 or letters > 0):
                raise UserError('When "ltrs" is in an N-of-M group,'
                                'uc, lc, and letters must be zero.')
            if 'uc' in groups and uc > 0:
                raise UserError('When "uc" is in an N-of-M group,'
                                'uc must be zero.')
            if 'lc' in groups and lc > 0:
                raise UserError('When "lc" is in an N-of-M group,'
                                'lc must be zero.')
            if 'num' in groups and num > 0:
                raise UserError('When "unumc" is in an N-of-M group,'
                                'num must be zero.')
            if 'spec' in groups and specialsqty > 0:
                raise UserError('When "spec" is in an N-of-M group,'
                                'specialsqty must be zero.')
            requiredlen += n_of_m_groups[0]  # number of required groups
        if requiredlen > maxlen:
            raise UserError('Required length exceeds maximum length.')
        if requiredlen > minlen:
            warnings.warn(f'Minimum length ({minlen}) adjusted'
                          f' to required length ({requiredlen})')
            self.minlen = minlen = requiredlen

    def genPassword(self, preferredlen: int = 12,
                          *, test=False, fill=False) -> str | NoneType:
        '''Generate a password for a particular site.'''

        def shuffle(chars: str) -> str:
            charsList = list(chars)
            shuffled = ''
            while len(charsList) > 0:
                shuffled += charsList.pop(random.randint(0, len(charsList)-1))
            return shuffled

        def adjustQuotas(char: str):
            nonlocal adjLtrs, adjUc, adjLc, adjNum, adjSpecQty
            if char in string.ascii_letters:
                adjLtrs -= 1
            if char in string.ascii_uppercase:
                adjUc -= 1
            elif char in string.ascii_lowercase:
                adjLc -= 1
            elif char in string.digits:
                adjNum -= 1
            elif char in self.specials:
                adjSpecQty -= 1

        firstChrTypes = {'uc':   string.ascii_uppercase,
                         'lc':   string.ascii_lowercase,
                         'num':  string.digits,
                         'spec': self.firstCharSpecials,
                        }  # end firstChrTypes
        # May have to adjust required quantities, if 1st char restrictions used
        adjUc = self.uc                # adjusted qty of upper-case letters
        adjLc = self.lc                # adjusted qty of lower-case letters
        adjLtrs = self.letters         # adjusted qty of letters
        adjNum = self.num              # adjusted qty of numerals
        adjSpecQty = self.specialsQty  # adjusted qty of special chars
        if self.firstChar is None:  # are there 1st char restrictions?
            firstCharacter = ''  # the 1st char not treated specially
            adjMinLen = self.minLen    # adjusted minimum password length
            adjMaxLen = self.maxLen    # adjusted maximum password length
            adjPrefLen = preferredlen  # adjusted requested password length
        else:                       # yes, there are 1st char restrictions.
            adjMinLen = self.minLen - 1    # 1st char handled separately
            adjMaxLen = self.maxLen - 1    # so remainder of password is
            adjPrefLen = preferredlen - 1  # one character shorter.
        if self.firstChar is not None:  # Are there 1st char restrictions?
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
                return None
            adjustQuotas(firstCharacter)
        NofMgroupTable = {'uc':   string.ascii_uppercase,
                          'lc':   string.ascii_lowercase,
                          'ltrs': string.ascii_letters,
                          'num':  string.digits,
                          'spec': self.specials,
                         }  # end NofMgroupTable

        runsAcceptable = False  # runs of same char sufficiently short, init'y no
        while not runsAcceptable:
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

            # Satisfy required quantities of char types in rest of password
            charTypeMins = ((string.ascii_uppercase, adjUc),
                            (string.ascii_lowercase, adjLc),
                            (string.ascii_letters, adjLtrs - adjUc - adjLc),
                            (string.digits, adjNum),
                            (self.specials, adjSpecQty),
                           )
            for (chars, qty) in charTypeMins:
                for n in range(qty):
                    password += random.choice(chars)

            # Choose additional characters to reach password's target length
            for n in range(max(adjMinLen,
                               min(adjMaxLen, adjPrefLen))
                           - len(password)):
                if fill:  # Be careful with this feature.  It can create
                          #   illegal runs of same characters if
                          #   the site specifies that restriction.
                    password += '\xb0'  # degree sign
                else:
                    password += random.choice(self.allChars)

            # Shuffle password characters, except 1st char if restricted.
            # Then prepend the 1st char with restrictions to the password.
            password = firstCharacter + shuffle(password)

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

#   R U L E   S E T S

# Mobile apps have a top-level domain of "app".

pswdGens = {
    'aaa.com': PasswordGen(
        minlen=6, maxlen=31, num=1, letters=1,
        specials='^-!@#{}~$_', specialsqty=0),
    'badlandsranch.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1, specialsqty=1, specials='!&$%^*@'),
    'bit.ly': PasswordGen(
        minlen=6, letters=1, num=1, specialsqty=1),
    'bosch-home.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1),
    'breville.com': PasswordGen(
        minlen=6, num=1),
    'choicehotels.com': PasswordGen(
        minlen=8, maxlen=44, specialsqty=1, history=0),  # all specials OK
    'citi.com': PasswordGen(
        minlen=8, maxlen=64, letters=1, num=1, maxrun=2,
        specials='~`!@#$%^&*()_-\\/|', specialsqty=0),
    'citizensbankonline.com': PasswordGen(
        minlen=8, maxlen=24, letters=1, num=1, spacesallowed=False,
        specials='`~!@#$%^&*()-_=+[]{}|;:\',./<>?'),
    'costco.com': PasswordGen(
        minlen=8, maxlen=16, uc=1, lc=1, num=1, specialsqty=1,
        specials='!@#$&', spacesallowed=False),  # no < >
    'culturaldistrict.org': PasswordGen(  # Pgh Cultural District
        minlen=8, uc=1, num=1, specialsqty=1),
    'customerfeed.com': PasswordGen(  # Highmark BCBS Secure Msg Ctr
        minlen=8, uc=1, lc=1, num=1),
    'cvs.com': PasswordGen(
        minlen=10, maxlen=64, uc=1, lc=1, num=1, specialsqty=1,
        specials='/@$%&'),
    'delish.com': PasswordGen(
        minlen=8, num=1, specialsqty=1),
    'delta.com': PasswordGen(
        minlen=8, maxlen=20, uc=1, lc=1, num=1,  # max 3 specials
        specials='`~!#$%^&*()-_=+[]{}\\|;:\'",./>?'),
    'disneyplus.com': PasswordGen(
        minlen=6, n_of_m_groups=(1, 'num', 'spec')),
    'dollarbank.com': PasswordGen(
        minlen=6, maxlen=10, letters=1, num=1,  # case insensitive
        specials='!@#$%&*_+-=?()', specialsqty=0),
    'e-zpassny.com': PasswordGen(
        minlen=8, maxlen=64, uc=1, lc=1, num=1, specialsqty=1,
        specials='!@#$%*()-_+=~;,.'),
    'experian.com': PasswordGen(
        minlen=8, maxlen=35, uc=1, lc=1, num=1, specialsqty=1,
        specials='_@~!?#$^*+=:;,|/()&{}[\\.-'),
    'fandango.com': PasswordGen(
        minlen=8, lc=1, num=1, spacesallowed=False),  # maxrun=3 ?
    'fcc.gov': PasswordGen(  # FCC Commission Registration System (CORES)
        minlen=12, maxlen=15, uc=1, lc=1, num=1, specialsqty=1,
        specials='@%+=/\'"!#$^?:;,(){}[]~`-_*&<>\\|.'),
    'fidelity.com': PasswordGen(
        minlen=6, maxlen=20,
        specials='`~!@$%^()-_=+\\|;:",./?'),
    'gofundme.com': PasswordGen(
        minlen=12, uc=1, lc=1, num=1, specialsqty=1),
    'goingtocamp.com': PasswordGen(  # Wisconsin State Park System
        minlen=8, uc=1, lc=1, num=1, specialsqty=0),
    'goodhousekeeping.com': PasswordGen(
        minlen=8, num=1, specialsqty=1),
    'guardianprotection.com': PasswordGen(
        minlen=7, uc=1, lc=1, num=1),
    'guardianprotection.app': PasswordGen(
        minlen=10, letters=1, num=1, specialsqty=1),
    'hbr.org': PasswordGen(  # Harvard Business Review
        minlen=8, uc=1, lc=1, num=1, specialsqty=1, specials='@!#$%^&+='),
    'hertz.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1, specialsqty=1, specials='#$%^&'),
    'highmarkbcbs.com': PasswordGen(
        minlen=12, uc=1, lc=1, num=1, specialsqty=1,
        specials='`~!@#$%^&*()-_=[]{}\\|;:\'",./?'),
    'higi.com': PasswordGen(
        minlen=6, maxlen=30),
    'homedepot.com': PasswordGen(
        minlen=9, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'homeagain.com': PasswordGen(  # HomeAgain Pet Recovery
        minlen=8, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'hotels.com': PasswordGen(
        minlen=6, maxlen=20, num=1),
    'hotmail.com': PasswordGen(
        minlen=8, n_of_m_groups=(2, 'uc', 'lc', 'num', 'spec')),
    'hulu.com': PasswordGen(
        minlen=6, uc=0, lc=0, letters=0, n_of_m_groups=(1, 'num', 'spec')),
    'id.me': PasswordGen(  # ID.me (IRS)
        minlen=8, uc=1, lc=1, num=1),
    'idoxs.net': PasswordGen(  # PWSA
        minlen=8, maxlen=15, uc=1, lc=1, num=1, specialsqty=0,
        specials='!.#%&*'),
    'irs.gov': PasswordGen(  # ID.me (IRS)
        minlen=8, uc=1, lc=1, num=1),
    'kraken.com': PasswordGen(
        minlen=8, letters=1, num=1, specialsqty=1),
    'laundryvalue.app': PasswordGen(
        specials='', specialsqty=0),
    'live.com': PasswordGen(  # Microsoft outlook hotmail
        minlen=8, n_of_m_groups=(2, 'uc', 'lc', 'num', 'spec')),
    'logitech.com': PasswordGen(
        minlen=10),
    'lowes.com': PasswordGen(
        minlen=8, maxlen=128, letters=1, num=1, maxrun=3, spacesallowed=False),
    'manuscriptcentral.com': PasswordGen(  # Scholar One Manuscripts - Orcid
        minlen=8, num=2),
    'marriott.com': PasswordGen(
        minlen=8, maxlen=20, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec'),
        specials='$!#&@?%=_'),
    'meetup.com': PasswordGen(
        minlen=10),
    'microsoft.com': PasswordGen(  # Microsoft account
        minlen=4, maxlen=127),
    'MorganStanleyClientServ.com': PasswordGen(
        minlen=8, maxlen=20, specialsqty=0, history=3,
        specials='', spacesallowed=False),
    'moveon.org': PasswordGen(
        minlen=8),
    'myequifax.com': PasswordGen(
        minlen=8, maxlen=20, uc=1, lc=1, num=1,
        specialsqty=1, specials='!@$*+-'),
    'mymedicare.gov': PasswordGen(
        minlen=8, maxlen=16, letters=1, num=1, specialsqty=1,
        specials='@!$%^*()', history=6),
    'myprepaidcenter.com': PasswordGen(
        minlen=8, maxlen=20, uc=1, lc=1, num=1, specialsqty=1,
        specials='!@#$%&'),
    'mytrueidentity.com': PasswordGen(  # TransUnion
        minlen=10, maxlen=64),
    'nationwide.com': PasswordGen(
        minlen=6, maxlen=30, uc=1, lc=1, num=1, specialsqty=1,
        specials='!#$+,-./\\:=?@[]_{}|~', spacesallowed=False),
    'nbc.com': PasswordGen(
        minlen=10, uc=1, lc=1),
    'netacad.com': PasswordGen(  # Cisco Networking Academy
        minlen=8, uc=1, lc=1, num=1, specialsqty=1, history=3),
    'netflix.com': PasswordGen(
        minlen=6, maxlen=60),
    'newegg.com': PasswordGen(
        minlen=8, maxlen=30, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'nist.gov': PasswordGen(  # Voting TWiki
        minlen=12, maxlen=32, uc=1, lc=1, num=1, specialsqty=1),
    'nvidia.com': PasswordGen(
        minlen=9, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'onsolve.net': PasswordGen(  # Allegheny Alerts
        minlen=8, specials='!@#$%^&*()'),
    'openai.com': PasswordGen(  # ChatGPT
        minlen=8),
    'opendns.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1, specialsqty=1),
    'pa.us': PasswordGen(  # HHS Keystone ID (PA Child Abuse clearances)
        minlen=8, maxlen=14, uc=1, lc=1, specialsqty=1, specials='@&*%$^'),
    'panerabread.com': PasswordGen(
        minlen=6, maxlen=20),
    'partswarehouse.com': PasswordGen(
        minlen=8, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec')),
    'pbs.org': PasswordGen(
        minlen=8, letters=1, num=1),
    'penzeys.com': PasswordGen(
        minlen=4, maxlen=20),
    'peopleseaccount.com': PasswordGen(  # Peoples Natural Gas
        minlen=8, maxlen=32, uc=1, lc=1, num=1,
        specials='!@#$%*_-', specialsqty=1),
    'petco.com': PasswordGen(
        minlen=12, specials='!@#$%^&*',
        n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'pghartsmedia.org': PasswordGen(  # Pittsburgh Center for the Arts PF/PCA
        minlen=8, uc=1, lc=3, num=1, specialsqty=1),
    'pnc.com': PasswordGen(
        minlen=8, maxlen=20, letters=1, num=1, maxrun=2, spacesallowed=False,
        specials='`@#$%*()-_=+;:,.?'),
    'privateinternetaccess.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1),
    'promasterforum.com': PasswordGen(
        minlen=8),
    'quora.com': PasswordGen(
        minlen=8),
    'reserveamerica.com': PasswordGen(  # Pennsylvania (PA) State Parks - DCNR
        minlen=8, uc=1, lc=1, n_of_m_groups=(1, 'num', 'spec')),
    'scribd.com': PasswordGen(
        minlen=10, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec')),
    'securevetsource.com': PasswordGen(  # Point Breeze Vet Clinic pharmacy - Vetsource
        minlen=8, uc=1, lc=1, num=1),
    'sharefile.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1, specialsqty=1),
    'solaredge.com': PasswordGen(
        minlen=8, letters=1, num=1),
    'ssa.gov': PasswordGen(  # my Social Security
        minlen=8, maxlen=64, uc=1, lc=1, num=1, specialsqty=1,
        specials='!@#$%^&*', firstchar=('uc', 'lc', 'num')),
    'synology.com': PasswordGen(
        minlen=8, n_of_m_groups=(2, 'uc', 'lc', 'num')),
    'tiaa-cref.org': PasswordGen(
        minlen=6, maxlen=20, specials='', specialsqty=0),
    'ticketmaster.com': PasswordGen(
        minlen=8, letters=1, num=1),
    'topcoder.com': PasswordGen(
        minlen=8, letters=1, n_of_m_groups=(1, 'num', 'spec')),
    'trainingmagnetwork.com': PasswordGen(
        minlen=8),
    'tranehome.com': PasswordGen(
        uc=1, lc=1, num=1),
    'transunion.com': PasswordGen(
        minlen=12, maxlen=64),
    'tvguide.com': PasswordGen(
        minlen=6),
    'upmc.com': PasswordGen(  # HealthTrak
        minlen=8, uc=1, lc=1, num=1, specialsqty=1),
    'upmchealthplan.com': PasswordGen(
        minlen=8, maxlen=14, uc=1, lc=1, num=1),
    'ups.com': PasswordGen(  # My Choice
        minlen=12, maxlen=26, uc=1, lc=1, num=1,
        specials='!@#$%*', specialsqty=1),
    'vectorsecurity.com': PasswordGen(
        minlen=6, uc=1, n_of_m_groups=(1, 'num', 'spec')),
    'verizonwireless.com': PasswordGen(
        minlen=8, maxlen=20, letters=1, num=1),
    'vitalant.com': PasswordGen(
        minlen=8, uc=1, lc=1, num=1, specialsqty=1),
    'warwickhotels.com': PasswordGen(
        minlen=6, maxlen=17, num=1),
    'washingtonpost.com': PasswordGen(
        minlen=8, specials='!"#$%&\'()*+,-./:;=?@[\\]^_{}~', specialsqty=1),
    'wdc.com': PasswordGen(  # Western Digital support
        minlen=8, maxlen=999, letters=1, num=1, history=3),
    'wicklespickles.com': PasswordGen(
        minlen=12),
    'zoom.us': PasswordGen(
        minlen=8, uc=1, lc=1, num=1),
    }  # end pswdGens


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
        pswdGens['testbadspecials'] = PasswordGen(
            minlen=6, maxlen=10, specials='$x*3-')
    except UserError:
        pass

    pswdGens['testbadrun'] = PasswordGen(
        minlen=6, maxlen=10, maxrun=0)
    pswdGens['testbad1stchar'] = PasswordGen(  # my Social Security
        minlen=8, maxlen=64, specials='!@#$%^&*',
        firstchar=('uc', 'lc', 'num', 'junk'))
    pswdGens['short3of4'] = PasswordGen(
        minlen=3, n_of_m_groups=(3, 'uc', 'lc', 'num', 'spec'))

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