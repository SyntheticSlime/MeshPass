# MPrec.py

'''MPrec Object to contain one record in MeshPass DB
'''

import random  # randrange()
import sys     # exit(), argv[]
import time    # time()


# = = = = =   C O N S T A N T S   = = = = =

version = 0           # MPrec object version
_maxRandom = 2 ** 32  # Largest permissible value of recID + 1


# = = = = =   M O D U L E   V A R I A B L E S   = = = = =

_db = []  # development db of recIDs. Not persistent. Should be.


# = = = = =   F U N C T I O N S   = = = = =

def _timeStamp():
    '''timeStamp returns a timestamp for records and fields
    '''
    
    return time.time()  # floating-point seconds since 1/1/1970 00:00:00 UTC
    
def _add_id_to_db(id):
    '''Store of recIDs in MeshPass db.
    
    Should be persistent.  Isn't yet.
    '''
    
    _db.append(id)  # need a persistent store. This isn't it.
    
def _genRecID(db):
    '''Generate random number for recID.
    
    Uses random numbers so devices belonging to same user can both
    create records without fear of a conflict in recIDs when DBs are
    later synced.
    Possibly the creation timestamp could be used instead as the recID.
    '''
    
    id = random.randrange(_maxRandom)
    while id in db:
        id = random.randrange(_maxRandom)
    _add_id_to_db(id)
    return id
    
def time2str(timeValue):
    '''Convert a field or record timestamp to a readable string.
    '''
    
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
        '''Set modification timestamp of a Field.
        '''
        
        self.modTime = timeValue
        
    def _getModTime(self):
        '''Retrieve the modification timestamp of a Field.
        '''
        
        return self.modTime
    
    def __init__(self, value):
        '''Initializer for Field class
        '''
        
        self.value = str(value)
        self.modTime = _timeStamp()
        
    def __str__(self):
        '''Format the Field instance as a string.
        '''
        
        return self.value

    def __repr__(self):
        '''Format the Field instance as a string for developers.
        '''
        
        return f'{self.value} - modified {time2str(self.modTime)}'

class MPrec:
    '''MPrec class instance contains one record of multiple fields
    '''
    
    titleLabel = 'Title'  # the dict key for the title field in a record
        
    def _updateRecVersion(self):
        '''Ensure that record version in DB is
           the same as in the software.
        '''
        
        if self.version < version:
            pass  # add steps necessary to change version
            self.version = version
            
    def _initFields(self):
        '''Initialize the container of Fields for the new MPrec.
        '''
        
        self.fields = dict()

    def _setFieldValue(self, label, value):  # only for use by MPrec methods
        self.fields[label].value = value
        
    def _getFieldValue(self, label):  # only for use by MPrec methods
        return self.fields[label].value
        
    def _setFieldModTime(self, label, timeValue):
        self._getField(label)._setModTime(timeValue)
        
    def _setField(self, label, field):
        '''Sets only the Field in the MPrec.
        
        Makes no changes to other attributes.
        '''
        
        self.fields[label] = field
            
    def _getField(self, label):
        '''Retrieve a Field object from an MPrec by Field-label.
        '''
        
        return self.fields[label]
        
    def _delField(self, label):
        '''Mark a Field deleted.
        
        Can't actually delete it yet, since it could come back from
        another device belonging to the same user when a sync occurs,
        if that device still has the Field.
        Normally a Field value is always a string, even if it's an
        empty string.  So Field.value==None indicates a deleted Field
        '''
        
        if label != self.titleLabel:
            self._setFieldValue(label, None)
        
    def _setRecModTime(self, timeValue):
        self.modTime = timeValue
        
    def getRecModTime(self):
        return self.modTime

    def addField(self, label, value):
        '''Create a new Field and add it to a MPrec.
        '''
        
        self._updateRecVersion()
        if label in self.fields:
            raise Exception(f'Record already has a field labeled {label}')
        rec = self
        self._setField(label, Field(value))
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
        if oldLabel == self.titleLabel:
            raise Exception(f'Cannot change the label of a record title')
        if newLabel in self.fields:
            raise Exception(f'Record already has a field labeled {newLabel}')
        else:
            self._updateRecVersion()
            self.addField(newLabel, self._getFieldValue(oldLabel))
            self._delField(oldLabel)
            
    def __str__(self):
        '''Format the MPrec instance as a string.
        '''
        
        return self.fields[self.titleLabel].getValue()
        
    def __repr__(self):
        '''Format the MPrec instance as a string for developers
        '''
        
        result = self.fields[self.titleLabel].getValue()
        for fldLabel in self.fields:
            if fldLabel != self.titleLabel:
                result += f' \n{fldLabel}: {self.fields[fldLabel].getValue()}'
        return result
            
            
# = = = = = M A I N   C O D E = = = = =

normalExit = 0

def testCode(args):
    '''Function to test classes and methods.
    
    Runs if this module is run as a program, not imported.
    '''
    
    ron = MPrec('Ron')
    print(f'RecID = {ron.id}')
    print(f'recCreateTime = {time2str(ron.createTime)}')
    print()
    
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time2str(ron._getField(label).modTime))

    time.sleep(1)
    print()
    ron.addField('IP address', '1.2.3.4')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time2str(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.addField('password', '1234')
    print(f'Rec modTime {time.ctime(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time2str(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.changeFieldValue('password', '5678')
    print(f'Rec modTime {time.ctime(ron.getRecModTime())}')
    for label in ron.fields:
        print(label, ron._getFieldValue(label), time2str(ron._getField(label).modTime))
        
    time.sleep(1)
    print()
    ron.changeFieldLabel('password', 'pswd')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for label in ron.fields:
        value = ron._getFieldValue(label)
        print(label, '*defunct field*' if value is None else value, time2str(ron._getField(label).modTime))
        
    print()
    print('IDs in DB:')
    for id in _db:
        print(id)
    return normalExit  # to OS (sys.exit)

if __name__ == '__main__':
    sys.exit(testCode(sys.argv[1:]))