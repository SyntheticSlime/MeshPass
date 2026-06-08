# MPrec.py

'''MPrec Object to contain one record in MeshPass DB
'''

import random  # randrange()
import sys     # exit(), argv[]
import time    # time()


# = = = = =   C O N S T A N T S   = = = = =

version = 0
_maxRandom = 2 ** 32


# = = = = =   M O D U L E   V A R I A B L E S   = = = = =

_db = []


# = = = = =   F U N C T I O N S   = = = = =

def _timeStamp():
    '''timeStamp returns a timestamp for records and fields
    '''
    
    return time.time()  # floating-point seconds since 1/1/1970 00:00:00 UTC
    
def _add_id_to_db(id):
    _db.append(id)  # need a persistent store. This isn't it.
    
def _genRecID(db):
    id = random.randrange(_maxRandom)
    while id in db:
        id = random.randrange(_maxRandom)
    _add_id_to_db(id)
    return id
    
def time2str(timeValue):
    return time.ctime(timeValue)
   

# = = = = =   C L A S S E S   = = = = =

class Field:
    '''Field class contains the value of one field in a record
    '''
        
    def _setValue(self, value):
        self.value = value
        
    def getValue(self):
        return self.value
        
    def _setModTime(self, timeValue):
        self.modTime = timeValue
        
    def _getModTime(self):
        return self.modTime
    
    def __init__(self, rec, value):
        '''Initializer for Field class
        '''
        
        self.value = value
        self.modTime = _timeStamp()
        rec._setRecModTime(self.modTime)

class MPrec:
    '''MPrec class instance contains one record of multiple fields
    '''
    
    titleLabel = 'Title'  # the dict key for the title field in a record
        
    def _updateRecVersion(self):
        if self.version < version:
            pass  # add steps necessary to change version
            self.version = version
            
    def _initFields(self):
        self.fields = dict()

    def _setFieldValue(self, label, value):  # only for use by MPrec methods
        self.fields[label].value = value
        
    def _getFieldValue(self, label):  # only for use by MPrec methods
        return self.fields[label].value
        
    def _setFieldModTime(self, label, timeValue):
        self._getField(label)._setModTime(timeValue)
        
    def _setField(self, label, field):
        self.fields[label] = field
            
    def _getField(self, label):
        return self.fields[label]
        
    def _delField(self, label):
        # Can't actually delete field, because it could come back
        # after syncing with another of the user's devices that
        # hasn't deleted the field yet.
        self._setFieldValue(label, None)
        
    def _setRecModTime(self, timeValue):
        self.modTime = timeValue
        
    def getRecModTime(self):
        return self.modTime

    def addField(self, label, value):
        self._updateRecVersion()
        if label in self.fields:
            raise Exception(f'Record already has a field labeled {label}')
        rec = self
        self._setField(label, Field(rec, value))
        self._setRecModTime(self._getField(label)._getModTime())  # update rec modtime
            
    def __init__(self, title):
        '''Initializer for MPrec class
        '''
        
        self.version = version
        self.id = _genRecID(_db)
        self._initFields()
        self.addField(self.titleLabel, title)
        self.createTime = self._getField(self.titleLabel)._getModTime()
        self._setRecModTime(self.createTime)
        
    def changeFieldValue(self, label, value):
        self._updateRecVersion()
        self._setFieldValue(label, value)
        now = _timeStamp()
        self._setFieldModTime(label, now)
        self._setRecModTime(now)
        
    def changeFieldLabel(self, oldLabel, newLabel):
        if newLabel in self.fields:
            raise Exception(f'Record already has a field labeled {newLabel}')
        else:
            self._updateRecVersion()
            self.addField(newLabel, self._getFieldValue(oldLabel))
            self._delField(oldLabel)
            
            
# = = = = = M A I N   C O D E = = = = =

def testCode(args):
    ron = MPrec('Ron')
    print(f'RecID = {ron.id}')
    print(f'recCreateTime = {time2str(ron.createTime)}')
    print()
    
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time.ctime(ron._getField(label).modTime))

    time.sleep(1)
    print()
    ron.addField('IP address', '1.2.3.4')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time.ctime(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.addField('password', '1234')
    print(f'Rec modTime {time.ctime(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time.ctime(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.changeFieldValue('password', '5678')
    print(f'Rec modTime {time.ctime(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time.ctime(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.changeFieldLabel('password', 'pswd')
    print(f'Rec modTime {time.ctime(ron.getRecModTime())}')
    for label in ron.fields:
        value = ron._getFieldValue(label)
        print(label, '*defunct field*' if value is None else value, time.ctime(ron._getField(label).modTime))
        
    print()
    print('IDs in DB:')
    for id in _db:
        print(id)
    return 0

if __name__ == '__main__':
    sys.exit(testCode(sys.argv[1:]))