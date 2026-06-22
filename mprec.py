# MPrec.py

# Module docstring shouldn't exceed column 76.
# Top level class and [function] def docstrings shouldn't exceed column 77.
# Docstrings for [method] defs within a class shouldn't exceed column 75.

'''MPrec Object to contain one record in MeshPass DB
'''


# = = = = =   B U I L T I N   M O D U L E S   = = = = =

import random    # randrange()
import sys       # exit(), argv[]
import time      # time(), ctime()
import warnings  # warn()
from inspect import getframeinfo, currentframe  # used in _getFieldPosArg


# = = = = =   H O M E - G R O W N   M O D U L E S   = = = = =

from exceptions import *  # additional Exceptions


# = = = = =   C O N S T A N T S   = = = = =

version = 0           # MPrec object version
_maxRandom = 2 ** 32  # Largest permissible value of recID + 1


# = = = = =   M O D U L E   V A R I A B L E S   = = = = =

_db = []  # development db of recIDs. Not persistent. Should be.


# = = = = =   F U N C T I O N S   = = = = =

def _timeStamp() -> float:
    '''_timeStamp returns a timestamp for records and fields
    '''

    return time.time()  # floating-point seconds since 1/1/1970 00:00:00 UTC

def time2str(timeValue: float) -> str:
    '''Convert a Field or Rec timestamp to a readable string.
    '''

    return time.ctime(timeValue)

def _genRecID(db) -> int:
    '''Generate random number for recID.

    Uses random numbers so devices belonging to same user can both
    create records without fear of a conflict in recIDs when DBs are
    later synced.  Possibly the creation timestamp could be used
    instead as the recID.
    '''

    id = random.randrange(_maxRandom)
    while id in db:
        id = random.randrange(_maxRandom)
    _add_id_to_db(id)
    return id

def _add_id_to_db(id: int):
    '''Store of recIDs in MeshPass db.

    Should be persistent.  Isn't yet.
    '''

    _db.append(id)  # need a persistent store. This isn't it.


# = = = = =   C L A S S E S   = = = = =

class Field:
    '''Field class contains the value of one field in a record
    '''

    titleLabel = 'Title'  # the key for the title field

    def _setValue(self, value: str, *,
                        setmodtime: bool = True):
        '''Set the value attribute in a Field
        '''

        self.value = str(value)
        if setmodtime:
            self._setModTime(_timeStamp())

    def getValue(self) -> str:
        '''Get the value attribute's value and return it.
        '''

        return self.value

    def _setLabel(self, label: str, *,
                        setmodtime: bool = True):
        '''Set the label attribute in a Field.
        '''

        # exact title is OK; case variations are not
        if label != self.titleLabel:
            if label.upper() == self.titleLabel.upper():
                raise UserError(f'"{label}" is a reserved label.')

        self.label = label.strip()
        if setmodtime:
            self._setModTime(_timeStamp())

    def _getLabel(self) -> str:
        '''Get the label attribute's value and return it.
        '''

        return self.label

    def _setModTime(self, timeValue: float):
        '''Set modification timestamp of a Field.
        '''

        self.modTime = timeValue

    def _getModTime(self) -> float:
        '''Retrieve the modification timestamp of a Field.
        '''

        return self.modTime

    def _setMask(self, masked: bool, *,
                       setmodtime: bool = True):
        '''Set whether a Field value is masked when displayed
        '''

        self.masked = bool(masked)
        if setmodtime:
            self._setModTime(_timeStamp())

    def _getMask(self) -> bool:
        '''Retrieve whether a Field value is masked when displayed
        '''

        return self.masked

    def __init__(self, label: str, value: str, masked: bool = False):
        '''Initializer for Field class
        '''

        label = label.strip()
        # exact title is OK; case variations are not
        if label != self.titleLabel:
            if label.upper() == self.titleLabel.upper():
                raise UserError(f'"{label}" is a reserved label.')

        self._setLabel(label, setmodtime=False)
        self._setValue(value, setmodtime=False)
        self._setMask(masked, setmodtime=False)
        self._setModTime(_timeStamp())

    def __str__(self) -> str:
        '''Format the Field instance as a string.
        '''

        return self.value if not self.masked else '*****'

    def __repr__(self) -> str:
        '''Format the Field instance as a string for developers.
        '''

        return (f'{self.getValue()} - modified {time2str(self._getModTime())}'
                f' - Masked = {self._getMask()}')

class _RecIter:
    '''Create an iterator object for iterating through the Fields in a Rec.
    '''

    def __init__(self, rec: MPrec):
        '''Initialize an iterator object for stepping
        through Fields in an MPrec.
        '''

        self.ndx = 0
        self.fieldsByPos = rec.fieldsByPos

    def __next__(self) -> Field:
        '''Provide the next Field in sequence from an MPrec.
        '''

        if self.ndx >= len(self.fieldsByPos):
            raise StopIteration
        field = self.fieldsByPos[self.ndx]
        self.ndx += 1
        return field

class MPrec:
    '''MPrec class instance contains one record of multiple fields
    '''

    titleLabel = 'Title'  # the key for the title field in a record
    titlePos   = 0        # the record title is always in position zero.

    def __getitem__(self, pos: int) -> Field:
        '''Obtain a Field from the list of Fields in a Rec ordered by
        display-position.  The chosen Field is specified by indexing
        an MPrec.
        '''

        return self.fieldsByPos[pos]

    def __setitem__(self, pos: int, field: Field):
        '''Allow a Field to replace another in a Rec, or
        to be appended to the list of Fields in a Rec.  The chosen Field
        is specified by indexing an MPrec.
        '''

        assert isinstance(field, Field), ('Rec.__setitem__ argument must'
                                          ' be a Field instance')
        if pos == len(self.fieldsByPos):
            self.fieldsByPos.append(field)
        else:
            self.fieldsByPos[pos] = field

    def __iter__(self) -> _RecIter:
        '''Creat iterator object for iterating over the Fields in a Rec.
        '''

        return _RecIter(self)

    def index(self, fieldLabel: str) -> int:
        '''Find the position of the first Field in
        the Rec that has the requested Label.
        Raises ValueError if label not found.
        '''

        fieldLabel = fieldLabel.strip()
        ndx = 0
        for field in self.fieldsByPos:  # COULD JUST USE "SELF"
            if field._getLabel() == fieldLabel:
                return ndx
            else:
                ndx += 1
        raise ValueError(f'There is no field labeled "{fieldLabel}" in'
                         f' record "{self[titlePos].value}".')

    def __contains__(self, targetLabel: str) -> bool:
        '''Overload the "in" operator for labels in an MPrec
        '''

        return targetLabel in (field.label for field in self.fieldsByPos)

    def _setRecModTime(self, timeValue: float):
        '''Set the modTime of a record to the specified timestamp.
        '''

        self.modTime = timeValue

    def getRecModTime(self) -> float:
        '''Get the modTime of a record.
        '''

        return self.modTime

    def _updateRecVersion(self):
        '''Ensure that record version in DB is
           the same as in the software.
        '''

        if self.version < version:
            pass  # add steps necessary to change version
            self.version = version

    def _initFieldsByPos(self):
        '''Initializes fieldsByPos, an ordered [by
        display position] list of Field objects.

        The index in the list is the position of the associated Field in
        a record display of all Fields.  Initially, the Fields are in the
        order in which they were added to the record, but the user may
        reorder them later.
        '''

        self.fieldsByPos = []

    def _initDeletedFields(self):
        '''Keep a separate list of deleted Fields.
        The order of these Fields in this list does not matter.
        '''

        # If deleted Fields were kept in the same list as active Fields,
        # they would interfere in the numbering of active Fields.

        # Dict keys are Field labels.
        # Dict values are 2-tuples of Field position before deletion, and
        # the deleted Field.
        self._deletedFields = dict()

    def __init__(self, title: str):
        '''Initializer for MPrec class
        '''

        self.version = version
        self.id = _genRecID(_db)
        self._initFieldsByPos()
        self._initDeletedFields()
        pos = self.addField(self.titleLabel, title)
        assert pos == self.titlePos, ('The title Field of a'
                                      ' record must be Field zero')
        self.createTime = self[pos]._getModTime()
        self._setRecModTime(self.createTime)

    def _addToFieldsByPos(self, field: Field) -> int:
        '''Just add a Field to a MPrec.
        Return the new Field's position in the record.
        '''

        self.fieldsByPos.append(field)
        return len(self.fieldsByPos) - 1  # position of appended Field in MPrec

    def addField(self, label: str, value: str, masked: bool = False) -> int:
        '''Create a new Field and add it to a MPrec.
        Return the new Field's display position.
        '''

        self._updateRecVersion()
        label = label.strip()
        # exact title is OK; case variations are not
        if label != self.titleLabel:
            if label.upper() == self.titleLabel.upper():
                raise UserError(f'"{label}" is a reserved label.')
#       if label in self.fieldsByPos:
        if label in self:  # DOES THIS WORK?
            raise UserError(f'Record already has a field labeled "{label}"')
        pos = self._addToFieldsByPos(Field(label, value, masked=masked))
        now = _timeStamp()
        self[pos]._setModTime(now)  # Field modtime
        self._setRecModTime(now)    # record modtime
        return pos

    def _getFieldPosArg(self, /, *, pos:   int | None = None,
                                    label: str | None = None) -> int:
        '''Returns the position of`an existing Field in a MPrec,
        located either by display-position (pos), or by Field label.
        If locating via label and it isn't found, ValueError is
        raised [by method "index".
        '''

        # The "inspect" module provides the means to get the frame in which
        # the current function/method is running, then the previous frame that
        # called the current frame, and then the name of the function/method
        # in that frame.

        callingMethodName = getframeinfo(currentframe().f_back).function

        if pos is None and label is None:
            raise ProgrammerError(f'Either "pos" or "label" arguments must be'
                                  f' specified in call to {callingMethodName}.')
        if pos is not None and label is not None:
            raise ProgrammerError(f'You cannot specify both "pos" and "label"'
                                  f' arguments in call to {callingMethodName}.')
        if pos is None:
            pos = self.index(label)  # raises ValueError if label not found
        return pos

    def _getField(self, /, *, pos:   int | None = None,
                              label: str | None = None) -> Field:
        '''Returns an existing Field object in a MPrec, located
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        return self[pos]

    def _setField(self, /, field: Field, *, pos:   int | None = None,
                                            label: str | None = None):
        '''Replaces an existing Field object into a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        self[pos] = field
        self._setRecModTime(_timeStamp())

    def _setFieldValue(self, /, value: str, *, pos:   int | None = None,
                                               label: str | None = None):
        '''Replaces an existing Field object into a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        field._setValue(value)
        self._setRecModTime(field._getModTime())

    def _getFieldValue(self, /, *, pos:   int | None = None,
                                   label: str | None = None):
        '''Replaces an existing Field object into a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        return field._getValue()

    def _setFieldLabel(self, /, newLabel: str, *, pos:      int | None = None,
                                                  oldLabel: str | None = None):
        '''Change the label of a Field.  Locate the Field by display
        position (pos) or label.
        '''

        if oldLabel is not None:
            oldLabel = oldLabel.strip()
        newLabel = newLabel.strip()
        if pos == self.titlePos:
            raise ProgrammerError(f'Cannot change the label of a record title')
        if newLabel in (field.label for field in self.fieldsByPos):
            raise UserError(f'Record already has a field labeled "{newLabel}"')
        if newLabel != self.titleLabel:
            if newLabel.upper() == self.titleLabel.upper():
                raise UserError(f'"{newLabel}" is a reserved label.')
        pos = self._getFieldPosArg(pos=pos, label=oldLabel)  # ValueError posibl
        self._updateRecVersion()
        self[pos].label = newLabel
        now = _timeStamp()
        self._setFieldModTime(now, pos=pos)
        self._setRecModTime(now)

    def _getFieldLabel(self, /, pos: int) -> str:
        '''Get the label (str) of the specified (by position) Field.
        '''

        return self[pos].label

    def _setFieldMask(self, /, masked: bool, *, pos:   int | None = None,
                                                label: str | None = None):
        '''Change whether a Field is masked.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError posibl
        if pos != self.titlePos:
            self[pos]._setMask(masked)
        now = _timeStamp()
        self._setFieldModTime(now, pos=pos)
        self._setRecModTime(now)

    def _getFieldMask(self, /, *, pos:   int | None = None,
                                  label: str | None = None) -> bool:
        '''Retrieve Boolean for whether a Field is masked.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError posibl
        return self[pos]._getMask()

    def _setFieldModTime(self, /, timeValue: float, *,
                                  pos:       int | None = None,
                                  label:     str | None = None):
        '''Sets the modTime of a Field, located
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        field._setModTime(timeValue)
        self._setRecModTime(timeValue)

    def _getFieldModTime(self, /, *, pos:   int | None = None,
                                     label: str | None = None):
        '''Get the modTime of a Field, located
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        return field._getModTime()

    def _changeFieldPos(self, /, toPos: int, *, fromPos: int | None = None,
                                                label:   str | None = None):
        '''Change the position of a Field in a Rec from one position index
        (or label) to another position, where position 0 is the title Field.
        '''

        fromPos = self._getFieldPosArg(pos=fromPos, label=label)  # ValueError?
        if fromPos == self.titlePos or toPos == self.titlePos:
            raise ProgrammerError('Cannot move a Field to or from position zero')
        if fromPos < toPos:    # move Field to the right
            self.fieldsByPos.insert(toPos, self[fromPos])
            del self[fromPos]  # WILL THE "DEL" WORK WITH __GETITEM__ ?
        elif fromPos > toPos:  # move Field to the left
            field = self[fromPos]
            del self[fromPos]
            self.fieldsByPos.insert(toPos, field)  # WILL INSERT WORK WITH __GETITEM__ ?

    def _delField(self, /, *, pos:   int | None = None,
                              label: str | None = None):
        '''Delete a field from an MPrec, but keep it around for sync logic.

        Can't actually delete it yet, since it could come back from
        another device belonging to the same user when a sync occurs,
        if that device still has the Field.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        if pos != titlePos:
            field = self[pos]
            label = field._getLabel()
            if label in self.deletedFields:
                warning.warn('Duplicate Field label in deletedFields'
                             ' replaces old value.')
            self.deletedFields[label] = (pos, field)
            now = _timeStamp()
            field._setModTime(now)
            self._setRecModTime(now)
            del self[pos]  # or must it be "del self.fieldsByPos[pos]"

    def _undelField(self, /, label: str, force: bool = False) -> bool:
        if force or label not in self:
            pos, field = deletedFields[label]
            self.fieldsByPos.insert(pos, field)
            del deletedFields[label]
            return True   # success
        else:
            return False  # failure

    def __str__(self) -> str:
        '''Format the MPrec instance as a string.
        '''

        return self[self.titlePos].getValue()

    def __repr__(self) -> str:
        '''Format the MPrec instance as a string for developers
        '''

        result = self[self.titlePos].getValue()
        for field in self.fieldsByPos[self.titlePos+1:]:
            result += (f' \n  {field._getLabel()}: '
                       f'{field.getValue()}')
        return result


# = = = = = M A I N   C O D E = = = = =

normalExit = 0

def _selfTest(args: list[str]) -> int:
    '''Function to test classes and methods.

    Runs if this module is run as a program, not imported.
    '''

    print('New record')
    ron = MPrec('Ron')
    print(f'RecID = {ron.id}')
    print(f'recCreateTime = {time2str(ron.createTime)}')
    print()

    print('Title field')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field.label, field.value, time2str(field._getModTime()))

    time.sleep(1)
    print()
    print('Add field IP address')
    ron.addField('IP address', '1.2.3.4')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field.label, field.value, time2str(field._getModTime()))

    time.sleep(1)
    print()
    print('Add field password')
    pos = ron.addField('password', '1234')
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field.label, field.value, time2str(field._getModTime()))

    time.sleep(1)
    print()
    print('Change value password')
    ron._setFieldValue('5678', pos=pos)
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field.label, field.value, time2str(field._getModTime()))

    time.sleep(1)
    print()
    print('Change field label password -> pswd')
    ron._setFieldLabel('pswd', pos=pos)
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(f'Value = {field.value}, Type = {type(field.value)}')
        print(field.label,
              '*defunct field*' if field.value is None else field.value,
              time2str(field._getModTime()))

    time.sleep(1)
    print()
    print('Add field unseen, masked=True')
    pos = ron.addField('unseen', 'ABCD', masked=True)
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field.label, field.value, time2str(field._getModTime()))
    print(f'Masked field: {ron[pos]}')

    time.sleep(1)
    print()
    print('Change mask of unseen to False')
    ron._setFieldMask(masked=False, pos=pos)
    print(f'Rec modTime {time2str(ron.getRecModTime())}')
    for field in ron:
        print(field._getLabel(), field.getValue(), time2str(field._getModTime()))
    print(f'Now unmasked: {ron[pos]}')

    print()
    print('IDs in DB:')
    for id in _db:
        print(id)
    return normalExit  # to OS (sys.exit)

if __name__ == '__main__':
    sys.exit(_selfTest(sys.argv[1:]))