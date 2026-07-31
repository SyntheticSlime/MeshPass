# recTemplates_en_us.py
'''Templates in en-us language for pre-populating an MPrec with Fields.
'''

# = = = = =   B U I L T I N   M O D U L E S   = = = = =

import re  # search(), ASCII, IGNORECASE


# = = = = =   F U N C T I O N S   = = = = =

def classifyMasked(label: str) -> bool:
    return (re.search(r'password|pswd|passwd|passphrase|\bPIN\b|code\b',
            label, re.ASCII | re.IGNORECASE)
           is not None)

def classifyShare(label: str) -> bool:
    return (re.search(r'private|pvt|secret',
            label, re.ASCII | re.IGNORECASE)
           is     None)

def classifyPhone(label: str) -> bool:
    return (re.search(r'phone|\bTEL\b',
            label, re.ASCII | re.IGNORECASE)
           is not None)

def classifyMapAddr(label: str) -> bool:
    return (re.search(r'addr',
            label, re.ASCII | re.IGNORECASE)
           is not None)

def classifyEmail(label: str) -> bool:
    return (re.search(r'\bEMAIL',
            label, re.ASCII | re.IGNORECASE)
           is not None)

def classifyURL(label: str) -> bool:
    return (re.search(r'\bURL\b|SITE\b',
            label, re.ASCII | re.IGNORECASE)
           is not None)

def classifyAll(label: str) -> tuple[bool]:
    return (classifyMasked(label),
            classifyShare(label),
            classifyPhone(label),
            classifyMapAddr(label),
            classifyEmail(label),
            classifyURL(label),
           )  # end return of classifyAll


# = = = = =   C L A S S E S   = = = = =

class fldTmplt:
    def __init__(self, label:   str,
                       masked:  bool = False,
                       share:   bool = True,
                       phone:   bool = False,
                       mapaddr: bool = False,
                       email:   bool = False,
                       url:     bool = False) -> fldTmplt:
        self.label   = label
        self.masked  = masked
        self.share   = share
        self.phone   = phone
        self.mapAddr = mapaddr
        self.email   = email
        self.url     = url


# = = = = =   M A I N   = = = = =

recTemplates = {
	'Bank Account':   ('Acct#', 'PIN', 'Name', 'Branch', 'Phone#'),
	'Birthday':		  ('Date',),
	'Calling Card':	  ('Access Number', 'PIN'),
	'Clothes Size':	  ('Shirt Size', 'Pant Size', 'Shoe Size', 'Dress Size',
					   'Ring Size', 'Hat Size'),
	'Crypto Key':	  ('Key ID', 'Passphrase',
                       'Name', 'Key Fingerprint', 'eMail Address', 'Key Server'),
	'Lock Combination': ('Code',),
	'Credit Card': 	  (fldTmplt('Card#', masked=True), 'Expiry Date', 'Name',
                       'PIN', 'Bank'),
	'Email Account':  ('eMail Address', 'Password',
                       'POP3 Host/Port',
					   'IMAP4 Host/Port', 'SMTP Host/Port'),
	'Emergency Info': ('Phone#',),
	'File': 		  ('Location', 'Document Type', 'Creator', 'Date'),
	'Frequent Flyer': ('Flyer#', 'Name', 'Date'),
	'Identification': ('ID Type', 'ID#', 'Name', 'Date'),
	'Insurance': 	  ('Policy#', 'Group#', 'Name of Insured',
                       'Date', 'Phone#'),
	'Membership': 	  ('Account#', 'Name', 'Date'),
	'Person':         ('Address', 'Email', 'Phone', 'Chat', 'Birthday', 'Aniv'),
	'Prescription':	  ('Rx #', 'Name', 'Doctor', 'Doctor Phone', 'Pharmacy',
					   'Pharmacy Phone'),
	'RFID Pass': 	  ('Acct#', 'PIN', 'User name',
                       'RFID Tag #', 'URL', 'Phone', 'Owner'),
	'Serial Number':  ('Serial#', 'Date', 'Reseller'),
	'Server':		  ('Username', 'Password',
                       'IP Address'),
	'System Login':   ('UserID', 'Password', 'Domain',
                       'Password Expiry', 'Old Passwords',
                       'System Name/Address'),
	'Unfiled': 		  (),
	'Utility': 		  ('Account#', 'Phone', 'URL', 'Service Addr'),
	'Vehicle': 		  ('Lic Plate', 'VIN', 'Insurance', 'Year'),
	'Voice Mail': 	  ('Access#', 'PIN'),
    'Voice over IP':  ('Username', 'Password', 'URL', 'IP Phone#',
                       'Access Phone#'),
	'Web Login': 	  ('Username', 'Password', 'URL', 'Old Passwords'),
	'Wi-Fi Network':  ('Ntwk Name/SSID', 'Passphrase'),
	}  # end recTemplates