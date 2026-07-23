# MPrec.py

# Module docstring shouldn't exceed column 76.
# Top level class and [function] def docstrings shouldn't exceed column 77.
# Docstrings for [method] defs within a class shouldn't exceed column 75.

'''MPrec Object to contain one record in MeshPass DB
'''


# = = = = =   B U I L T I N   M O D U L E S   = = = = =

import random    # randrange()
import sys       # exit(), argv[]
import time      # time(), ctime(), sleep()
import warnings  # warn()
from inspect import getframeinfo, currentframe  # used in _getFieldPosArg


# = = = = =   H O M E - G R O W N   M O D U L E S   = = = = =

from exceptions import *  # additional Exceptions: UserError, ProgrammerError


# = = = = =   C O N S T A N T S   = = = = =

_MAXRANDOM = 2 ** 32  # Largest permissible value of recID + 1


# = = = = =   M O D U L E   V A R I A B L E S   = = = = =

_db = []  # development db of recIDs. Not persistent. Should be.


# = = = = =   F U N C T I O N S   = = = = =

#def _timeStamp() -> float:
#    '''_timeStamp returns a timestamp for records and fields
#    '''
#
#    return time.time()  # floating-point seconds since 1/1/1970 00:00:00 UTC

#def time2str(timeValue: float) -> str:
#    '''Convert a Field or Rec timestamp to a readable string.
#    '''
#
#    return time.ctime(timeValue)

def _genRecID(db) -> int:
    '''Generate random number for recID.

    Uses random numbers so devices belonging to same user can both
    create records without fear of a conflict in recIDs when DBs are
    later synced.  Possibly the creation timestamp could be used
    instead as the recID.
    '''

    id = random.randrange(_MAXRANDOM)
    while id in db:
        id = random.randrange(_MAXRANDOM)
    _add_id_to_db(id)
    return id

def _add_id_to_db(id: int):
    '''Store of recIDs in MeshPass db.

    Should be persistent.  Isn't yet.
    '''

    _db.append(id)  # need a persistent store. This isn't it.


# = = = = =   C L A S S E S   = = = = =

class TimeStamp:
    '''Encapsulate TimeStamps in a class so that we can change the
    representation of them, or the functions involved, all in one place.
    '''

    #   V A R I A B L E S
    tsformat = '%Y/%m/%d %H:%M:%S'
    GMT = False

    #   M E T H O D S

    def __init__(self, timeValue: float = None):
        '''Initialize new TimeStamp instance.
        If no timeValue is provided, it defaults to now.
        '''

        if isinstance(timeValue, TimeStamp):
            self._set(timeValue.get())
        else:
            self._set(timeValue)

    def _set(self, timeValue: float = None) -> float:
        '''Set the time value of an existing TimeStamp instance
        and also return that value.
        If no timeValue is provided, it defaults to now.
        '''

        if timeValue is None:
            self.value = self._now()
        else:
            # May raise ValueError.
            self.value = float(timeValue)  # find out early if timeValue
        return self.value                  # won't convert to float.

    def get(self) -> float:
        '''Obtain the time value from the object instance.
        '''

        return self.value

    @staticmethod
    def _now() -> float:
        '''Return the time value representing this moment in time.
        '''

        return time.time()  # floating-point seconds since 1/1/1970 00:00:00 UTC

    def __repr__(self) -> str:
        '''Convert timestamp value to readable text.
        If no __str__ method is defined, __repr__ will also serve str().
        '''

        return time.ctime(self.get())

    @classmethod
    def setTSformat(cls, tsformat: str,
                         custom: str = None,
                         *, GMT: bool = False):
        '''Set date/time format for TimeStamp class or one of its subclasses.

        tsformat is one of: USA, EUR, univ, local, or custom.
        If custom is specified, you must also provide a custom format string.
        If you want GMT instead of local time, specify GMT=True.
        Custom format directives include:
        DIRECTIVE   MEANING
        %a          Locale's abbreviated weekday name.
        %A          Locale's full weekday name.
        %b          Locale's abbreviated month name.
        %B          Locale's full month name.
        %c          Locale's appropriate date and time representation.
        %d          Day of the month as a decimal number [01,31].
        %f          Microseconds as a decimal number [000000,999999].
        %H          Hour (24-hour clock) as a decimal number [00,23].
        %I          Hour (12-hour clock) as a decimal number [01,12].
        %j          Day of the year as a decimal number [001,366].
        %m          Month as a decimal number [01,12].
        %M          Minute as a decimal number [00,59].
        %p          Locale's equivalent of either AM or PM.
        %S          Second as a decimal number [00,61].
        %U          Week number of the year (Sunday as the first day of the
                    week) as a decimal number [00,53]. All days in a new year
                    preceding the first Sunday are considered to be in week 0.
        %u          Day of the week (Monday is 1; Sunday is 7) as
                    a decimal number [1, 7].
        %w          Weekday as a decimal number [0(Sunday),6].
        %W          Week number of the year (Monday as the first day of the
                    week) as a decimal number [00,53]. All days in a new year
                    preceding the first Monday are considered to be in week 0.
        %x          Locale's appropriate date representation.
        %X          Locale's appropriate time representation.
        %y          Year without century as a decimal number [00,99].
        %Y          Year with century as a decimal number.
        %z          Time zone offset indicating a positive or negative time
                    difference from UTC/GMT of the form +HHMM or -HHMM,
                    where H represents decimal hour digits and M represents
                    decimal minute digits [-23:59, +23:59].
        %Z          Time zone name (no characters if no time zone exists).
                    Deprecated.
        %G          ISO 8601 year (similar to %Y but follows the rules for
                    the ISO 8601 calendar year). The year starts with the week
                    that contains the first Thursday of the calendar year.
        %V          ISO 8601 week number (as a decimal number [01,53]).
                    The first week of the year is the one that contains the
                    first Thursday of the year. Weeks start on Monday.
        %%          A literal '%' character.
        '''
        
        if tsformat == 'USA':
            cls.tsformat = '%m/%d/%Y %I:%M:%S %p'
        elif tsformat == 'EUR':
            cls.tsformat = '%d/%m/%Y %H:%M:%S'
        elif tsformat == 'univ':
            cls.tsformat = '%Y/%m/%d %H:%M:%S'
        elif tsformat == 'local':
            cls.tsformat = '%x %X'
        elif tsformat == 'custom':
            if custom is None:
                raise UserError('When tsformat is "custom," you must'
                                ' supply a custom format string')
            else:
                try:
                    time.strftime(custom, time.gmtime())
                except ValueError:
                    warnings.warn(f'Invalid custom timestamp format string:'
                                  f' {custom}')
                else:  # if there was no Exception
                    cls.tsformat = custom
        else:
            raise UserError('tsformat must be specified as one of:'
                            '  USA, EUR, univ, local, custom')
        cls.GMT = GMT  # True for GMT (UTC), False for local

    def __str__(self):
        '''Convert TimeStamp to readable text.
        User can specify a date/time format for the class.
        Create subclasses to have different formats for
        different types of TimeStamps.
        '''

        gmt = self.__class__.GMT
        tsformat = self.__class__.tsformat
        func = time.gmtime if gmt else time.localtime
        tstuple = func(self.get())
        return time.strftime(tsformat, tstuple) + (' GMT' if gmt else '')

    def __eq__(self, other: TimeStamp) -> bool:
        return self.get() == other.get()
    def __ne__(self, other: TimeStamp) -> bool:
        return self.get() != other.get()
    def __lt__(self, other: TimeStamp) -> bool:
        return self.get() <  other.get()
    def __le__(self, other: TimeStamp) -> bool:
        return self.get() <= other.get()
    def __gt__(self, other: TimeStamp) -> bool:
        return self.get() >  other.get()
    def __ge__(self, other: TimeStamp) -> bool:
        return self.get() >= other.get()

class CreationTimeStamp(TimeStamp):
    '''Subclass of TimeStamp to provide a different
    date/time format just for creation timestamps.
    '''

    #   V A R I A B L E S
    tsformat = '%x'
    GMT = False

class ModTimeStamp(TimeStamp):
    '''Subclass of TimeStamp to provide a different
    date/time format just for modification timestamps.
    '''

    #   V A R I A B L E S
    tsformat = '%x %X'
    GMT = False

class Field:
    '''Field class contains the value of one field in a record
    '''

    #   C O N S T A N T S
    titleLabel = 'Title'  # the key for the title field

    #   M E T H O D S

    def _setValue(self, value: str, *,
                        setmodtime: bool = True):
        '''Set the value attribute in a Field
        '''

        self.value = str(value)
        if setmodtime:
            self._setModTime(ModTimeStamp())  # now

    def _getValue(self) -> str:
        '''Get the value attribute's value and return it.
        '''

        return self.value

    def _setLabel(self, label: str, *,
                        setmodtime: bool = True):
        '''Set the label attribute in a Field.
        '''

        label = label.strip()
        # exact title is OK; case variations are not
        if (label != self.titleLabel
            and label.upper() == self.titleLabel.upper()):
                raise UserError(f'"{label}" is a reserved label.')
        if len(label) == 0:
            raise UserError('Field label may not be blank.')
        # Reserve * at start or end of label for search wildcards.
        if label[0] == '*' or label[-1] == '*':
            raise UserError('Field label may not start'
                            ' or end with an asterisk.')
        self.label = label
        if setmodtime:
            self._setModTime(ModTimeStamp())  # now

    def _getLabel(self) -> str:
        '''Get the label attribute's value and return it.
        '''

        return self.label

    def _setModTime(self, tstamp: TimeStamp):
        '''Set modification timestamp of a Field.
        '''

        self.modTime = tstamp

    def _getModTime(self) -> ModTimeStamp:
        '''Retrieve the modification timestamp of a Field.
        '''

        return self.modTime

    def _setMask(self, masked: bool, *,
                       setmodtime: bool = True):
        '''Set whether a Field value is masked when displayed
        '''

        self.masked = bool(masked)
        if setmodtime:
            self._setModTime(ModTimeStamp())  # now

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
        now = ModTimeStamp()
        self._setModTime(now)

    def __str__(self) -> str:
        '''Format the Field instance as a string.
        '''

        return self.value if not self.masked else '*****'

    def __repr__(self) -> str:
        '''Format the Field instance as a string for developers.
        '''

        return (f'{self._getLabel()} -> '
                f'{self._getValue()} - modified {self._getModTime()}'
                f' - Masked = {self._getMask()}')

class _RecIter:
    '''Create an iterator object for iterating through the Fields in a Rec.
    '''

    #   M E T H O D S

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

    #   C O N S T A N T S
    pgmRecVersion = 0     # MPrec object version
    titleLabel = 'Title'  # The label for the title field in a record.
    titlePos   = 0        # The record title is always in position zero.

    #   V A R I A B L E S
    mostRecentRecordTS = ModTimeStamp(0)  # zero seconds since 1/1/1970 00:00:00 UTC
                                       # Should be updated by a function that
                                       # scans all records.

    #   M E T H O D S

    def validateRecord(self) -> tuple[bool, ModTimeStamp, str]:
        '''Check reasonableness of MPrec and return modTime.

        Check that modTime and createTime make sense.
        Check that all members of fieldByPos are Fields.
        Return a 3-tuple with a bool for success[T]/failure[F]; modTime
        TimeStamp so an initial scan of all records can determine
        the TimeStamp of the most recent record, i.e., the TimeStamp
        of the DB of MPrecs; and a string of messages.
        '''

        now = TimeStamp()
        message = ''
        if self.createTime > self.modTime:  # create time after modTime?
            message += (f'{"\n" if len(message) > 0 else ''}'
                        f'Creation timestamp later than modification timestamp in record:'
                        f'  {self.getFieldValue(pos=self.titlePos)}')
        if self.modTime > now:  # record modTime in the future?
            message += (f'{"\n" if len(message) > 0 else ''}'
                        f'Modification timestamp is in the future in record:'
                        f'  {self.getFieldValue(pos=self.titlePos)}')
        if self.createTime > now:  # record create time in the future?
            message += (f'{"\n" if len(message) > 0 else ''}'
                        f'Modification timestamp is in the future in record:'
                        f'  {self.getFieldValue(pos=self.titlePos)}')
        for fld in self:
            if isinstance(fld, Field):
                if fld._getModTime() < self.createTime:  # field modTime before record creation?
                    message += (f'{"\n" if len(message) > 0 else ''}'
                                f'Field modTime < record createTime in record:'
                                f'  {self.getFieldValue(pos=self.titlePos)}')
                if fld._getModTime() > now:  # field modTime in the future?
                    message += (f'{"\n" if len(message) > 0 else ''}'
                                f'Field modTime is in the future in record:'
                                f'  {self.getFieldValue(pos=self.titlePos)}')
            else:
                message += (f'{"\n" if len(message) > 0 else ''}'
                            f'non-Field object in record:'
                            f'  {self.getFieldValue(pos=self.titlePos)}')
        for (fld, oldModTime, oldPos) in self._deletedFields:
            if not isinstance(fld, Field):
                message += (f'{"\n" if len(message) > 0 else ''}'
                            f'non-Field object in deleted Fields:'
                            f'  {self.getFieldValue(pos=self.titlePos)}')
            if not isinstance(oldModTime, TimeStamp):
                message += (f'{"\n" if len(message) > 0 else ''}'
                            f'Non-TimeStamp object in deleted Fields:'
                            f'  {self.getFieldValue(pos=self.titlePos)}')
            if not isinstance(oldPos, int) or oldPos <= self.titlePos:
                message += (f'{"\n" if len(message) > 0 else ''}'
                            f'Saved position not a positive integer in deleted Fields:'
                            f'  {self.getFieldValue(pos=self.titlePos)}')
            if oldModTime > fld.modTime:  # saved modTime later than deletion time?
                message += (f'{"\n" if len(message) > 0 else ''}'
                            f'Saved modTime after deletion time in deleted Fields:'
                            f'  {self.getFieldValue(pos=self.titlePos)}')
        OK = len(message) == 0
        return (OK, self.getRecModTime(), message)

    def validateTimeStamp(self, tstamp: TimeStamp):
        if tstamp < self.mostRecentRecordTS:
            raise UserError('Current time is prior to TimeStamp on'
                            ' most recent record.')

    def newerRecord(self, tstamp: ModTimeStamp):
        if tstamp < self.__class__.mostRecentRecordTS:
            raise UserError('Current time is prior to TimeStamp on'
                            ' most recent record.')
        else:
            self.__class__.mostRecentRecordTS = tstamp

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

    def __delitem__(self, pos: int):
        '''Delete a Field from an MPrec by display-position.
        '''

        del self.fieldsByPos[pos]

    def __iter__(self) -> _RecIter:
        '''Creat iterator object for iterating over the Fields in a Rec.
        '''

        return _RecIter(self)

    def index(self, fieldLabel: str,
                    start: int = 1) -> int:
        '''Find the position of the first Field in
        the Rec that has the requested Label.
        Raises ValueError if label not found.
        '''

        fieldLabel = fieldLabel.strip()
        ndx = start
        for field in self[start:]:
            if field._getLabel() == fieldLabel:
                return ndx
            else:
                ndx += 1
        raise ValueError(f'There is no field labeled "{fieldLabel}" in'
                         f' record "{self[self.titlePos].value}".')

    def __contains__(self, targetLabel: str) -> bool:
        '''Overload the "in" operator for labels in an MPrec
        '''

        return targetLabel in (field.label for field in self.fieldsByPos)

    def _setRecModTime(self, tstamp: TimeStamp):
        '''Set the modTime of a record to the specified timestamp.
        '''

        self.modTime = tstamp

    def getRecModTime(self) -> ModTimeStamp:
        '''Get the modTime of a record.
        '''

        return self.modTime

    def getCreateTime(self) -> TimeStamp:
        '''Get the createTime of a record.
        '''

        return self.createTime

    def _updateRecVersion(self):
        '''Ensure that record version in DB is
           the same as in the software.
        '''

        if self.version < MPrec.pgmRecVersion:
            if self.version == 0:
                if MPrec.pgmRecVersion == 1:
                    pass  # add steps necessary to upgrade rec v0->v1
                elif MPrec.pgmRecVersion == 2:
                    pass  # add steps necessary to upgrade rec v0->v2
            elif self.version == 1:
                if MPrec.pgmRecVersion == 2:
                    pass  # add steps necessary to upgrade rec v1->v2
            self.version = MPrec.pgmRecVersion

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
        The order of these Fields in this list is chronological
        by time of deletion; earliest first, latest last.
        Can also be used to purge all fields from _deletedFields.
        '''

        # If deleted Fields were kept in the same list as active Fields,
        # they would interfere in the numbering of active Fields.

        # Values are 3-tuples of the deleted Field, the modTime before
        # deletion, and the Field position before deletion.
        self._deletedFields = []

    def __init__(self, title: str):
        '''Initializer for MPrec class
        '''

        self.version = MPrec.pgmRecVersion
        self.id = _genRecID(_db)
        self._initFieldsByPos()
        self._initDeletedFields()
        pos = self.addField(self.titleLabel, title)
        assert pos == self.titlePos, ('The title Field of a'
                                      ' record must be Field zero')
        modTime = self[pos]._getModTime()
        self.createTime = CreationTimeStamp(modTime)
        self._setRecModTime(modTime)
        self.newerRecord(modTime)

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
        if label in self:
            raise UserError(f'Record already has a field labeled "{label}"')
        now = ModTimeStamp()
        self.validateTimeStamp(now)
        pos = self._addToFieldsByPos(Field(label, value, masked=masked))
        self._setModTimes(now, pos=pos)  # set Field and Record modTimes
        self.newerRecord(now)
        return pos

    def _getFieldPosArg(self, start: int = 1,
                              *, pos:   int | None = None,
                                 label: str | None = None) -> int:
        '''Returns the position of`an existing Field in a MPrec,
        located either by display-position (pos), or by Field label.
        Label may have an asterisk at the beginning, the end, or both,
        denoting wildcards.
        If locating via label and it isn't found, ValueError is
        raised [by method "index"].
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
        if pos is None:  # search by field label
            pos = start
            if label[0] == '*' and label[-1] == '*':  # contains
                for fld in self.fieldsByPos[start:]:  # can we omit .fieldsByPos ?
                    if label in fld.label:
                        break
                    else:
                        pos += 1
                else:
                    raise ValueError(f'There is no field label containing'
                                     f' "{fieldLabel}" in'
                                     f' record "{self[self.titlePos].value}".')
            elif label[0] == '*':                     # ends with
                for fld in self.fieldsByPos[start:]:  # can we omit .fieldsByPos ?
                    if fld.label.endswith(label):
                        break
                    else:
                        pos += 1
                else:
                    raise ValueError(f'There is no field label ending with'
                                     f' "{fieldLabel}" in'
                                     f' record "{self[self.titlePos].value}".')
            elif label[-1] == '*':                    # starts with
                for fld in self.fieldsByPos[start:]:  # can we omit .fieldsByPos ?
                    if fld.label.startswith(label):
                        break
                    else:
                        pos += 1
                else:
                    raise ValueError(f'There is no field label starting with'
                                     f' "{fieldLabel}" in'
                                     f' record "{self[self.titlePos].value}".')
            else:  # search for field by complete and exact match of label.
                pos = self.index(label, start=start)  # raises ValueError if label not found
        return pos

    def getField(self, *, pos:   int | None = None,
                          label: str | None = None) -> Field:
        '''Returns an existing Field object in a MPrec, located
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        return self[pos]

    def _setField(self, field: Field, *, pos:   int | None = None,
                                         label: str | None = None):
        '''Replaces an existing Field object in a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        assert isinstance(field, Field), ('Rec._setField argument must'
                                          ' be a Field instance')
        self[pos] = field
        now = ModTimeStamp()
        self._setRecModTime(now)
        self.newerRecord(now)

    def setFieldValue(self, value: str, *, pos:   int | None = None,
                                           label: str | None = None):
        '''Replaces an existing Field object into a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        field._setValue(value)
        modTime = field._getModTime()
        self._setRecModTime(modTime)
        self.newerRecord(modTime)

    def getFieldValue(self, *, pos:   int | None = None,
                               label: str | None = None):
        '''Replaces an existing Field object into a MPrec,
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        return field._getValue()

    def setFieldLabel(self, newlabel: str, *, pos:      int | None = None,
                                              oldlabel: str | None = None):
        '''Change the label of a Field.  Locate the Field by display
        position (pos) or label.
        '''

        if oldlabel is not None:
            oldlabel = oldlabel.strip()
        newlabel = newlabel.strip()
        if pos == self.titlePos:
            raise ProgrammerError(f'Cannot change the label of a record title')
        if newlabel in (field.label for field in self.fieldsByPos):
            raise UserError(f'Record already has a field labeled "{newlabel}"')
        if newlabel != self.titleLabel:
            if newlabel.upper() == self.titleLabel.upper():
                raise UserError(f'"{newlabel}" is a reserved label.')
        pos = self._getFieldPosArg(pos=pos, label=oldlabel)  # ValueError posibl
        self._updateRecVersion()
        self[pos].label = newlabel
        now = ModTimeStamp()
        self._setModTimes(now, pos=pos)  # set Field and Record modTimes
        self.newerRecord(now)

    def getFieldLabel(self, pos: int) -> str:
        '''Get the label (str) of the specified (by position) Field.
        '''

        return self[pos].label

    def setFieldMask(self, masked: bool,
                           *, pos:   int | None = None,
                              label: str | None = None):
        '''Change whether a Field is masked.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError posibl
        if pos != self.titlePos:
            self[pos]._setMask(bool(masked))
        now = ModTimeStamp()
        self._setModTimes(now, pos=pos)  # set Field and Record modTimes
        self.newerRecord(now)

    def getFieldMask(self, *, pos:   int | None = None,
                              label: str | None = None) -> bool:
        '''Retrieve Boolean for whether a Field is masked.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError posibl
        return self[pos]._getMask()

#   def _setFieldModTime(self, timeValue: float,
#                              *, pos:       int | None = None,
#                                 label:     str | None = None):
#       '''Sets the modTime of a Field, located
#       either by display-position (pos), or by Field label.
#       '''

#       pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
#       field = self[pos]
#       field._setModTime(timeValue)
#       self._setRecModTime(timeValue)

    def _setModTimes(self, tstamp: TimeStamp,
                           *, pos:       int | None = None,
                              label:     str | None = None):
        '''Sets the modTime of a Field, located
        either by display-position (pos), or by Field label.
        Also, sets MPrec modTime.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        field._setModTime(tstamp)
        self._setRecModTime(tstamp)

    def getFieldModTime(self, *, pos:   int | None = None,
                                 label: str | None = None) -> TimeStamp:
        '''Get the modTime of a Field, located
        either by display-position (pos), or by Field label.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        field = self[pos]
        return field._getModTime()

    def changeFieldPos(self, topos: int, *, frompos: int | None = None,
                                            label:   str | None = None):
        '''Change the position of a Field in a Rec from one position index
        (or label) to another position, where position 0 is the title Field.
        '''

        frompos = self._getFieldPosArg(pos=frompos, label=label)  # ValueError?
        if frompos == self.titlePos or topos == self.titlePos:
            raise ProgrammerError('Cannot move a Field to or from position zero')
        field = self[frompos]
        del self[frompos]
        self.fieldsByPos.insert(topos, field)
        now = ModTimeStamp()
        self._setRecModTime(now)
        self.newerRecord(now)

    def delField(self, *, pos:   int | None = None,
                          label: str | None = None):
        '''Delete a field from an MPrec, but keep it around for sync logic.

        Can't actually delete it yet, since it could come back from
        another device belonging to the same user when a sync occurs,
        if that device still has the Field.
        '''

        pos = self._getFieldPosArg(pos=pos, label=label)  # ValueError possible
        if pos == self.titlePos:
            raise ProgrammerError('Cannot delete the title field.')
        else:
            field = self[pos]
            label = field._getLabel()
            if label in (fld.label for (fld, _, _) in self._deletedFields):
                warnings.warn('Duplicate Field label in deletedFields'
                             ' replaces old value.')
            self._deletedFields.append((field, field._getModTime(), pos))
            now = ModTimeStamp()
            field._setModTime(now)  # deleted Field now contains deletion time
            self._setRecModTime(now)
            self.newerRecord(now)
            del self[pos]

    def listDeletedFields(self) -> tuple[tuple]:
        '''Return a tuple of tuples of deleted Fields that can be undeleted.

        Each inner tuple contains the following about a deleted Field:
        1) the Field object
        2) the modification timestamp that the Field had before deletion
        3) the display-position that the Field had before deletion
        '''

        return tuple(self._deletedFields)

    def undelField(self, label: str | None = None,
                         *, force: bool = False) -> bool:
        '''Undelete a Field back into an MPrec.
        '''

        if label is None:  # undelete last deleted Field
            try:
                field, modTime, origPos = self._deletedFields.pop()
            except IndexError:
                warnings.warn('There are no undeleted Fields to undelete.')
                return False
        else:              # undelete specified Field
            try:
                pos = [fld.label for (fld, _, _)
                       in self._deletedFields   ].index(label)
            except ValueError:
                warnings.warn(f'There is no deleted Field with title "{label}"')
                return False
            field, modTime, origPos = self._deletedFields.pop(pos)
        if force or label not in self:
            field._setModTime(modTime)
            self.fieldsByPos.insert(origPos, field)
            now = ModTimeStamp()
            self._setRecModTime(now)
            self.newerRecord(now)
            return True   # success
        else:
            return False  # failure

    def __str__(self) -> str:
        '''Format the MPrec instance as a string.
        '''

        return self[self.titlePos]._getValue()

    def __repr__(self) -> str:
        '''Format the MPrec instance as a string for developers
        '''

        result = self[self.titlePos]._getValue()
        for field in self.fieldsByPos[self.titlePos+1:]:
            result += (f' \n  {field._getLabel()}: '
                       f'{field._getValue()}')
        return result


# = = = = = M A I N   C O D E = = = = =

normalExit = 0

def _selfTest(args: list[str]) -> int:
    '''Function to test classes and methods.

    Runs if this module is run as a program, not imported.
    '''

    print('New record')
    r1 = MPrec('Ron')
    print(f'RecID = {r1.id}')
    print(f'recCreateTime = {r1.createTime}')
    print()

    print('Title field')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nAdd field IP address')
    r1.addField('IP address', '1.2.3.4')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nRelabel field IP address, locating Field by old label')
    r1.setFieldLabel('IPv4 address', oldlabel='IP address')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nAdd field password')
    pos = r1.addField('password', '1234')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nChange value password')
    r1.setFieldValue('5678', pos=pos)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nChange field label password -> pswd')
    r1.setFieldLabel('pswd', pos=pos)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(f'Value = {field.value}, Type = {type(field.value)}')
        print(field.label,
              '*defunct field*' if field.value is None else field.value,
              field._getModTime())

    time.sleep(1)
    print('\nAdd field unseen, masked=True')
    pos = r1.addField('unseen', 'ABCD', masked=True)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())
    print(f'Masked field: {r1[pos]}')

    time.sleep(1)
    print('\nChange mask of unseen to False')
    r1.setFieldMask(masked=False, pos=pos)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field._getLabel(), field._getValue(), field._getModTime())
    print(f'Now unmasked: {r1[pos]}')

    time.sleep(1)
    print('\nAdd two more fields')
    r1.addField('Phone', '412-999-9999')
    r1.addField('Acct#', '123-44-5678')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nMove field 4 (Phone) to position 2 (to the left)')
    r1.changeFieldPos(2, frompos=4)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nMove field "IPv4 address" to position 4 (to the right)')
    r1.changeFieldPos(4, label='IPv4 address')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nDelete field 3 (unseen)')
    r1.delField(pos=3)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nDelete field "IPv4 address"')
    r1.delField(label='IPv4 address')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nDelete field 1 (Phone)')
    r1.delField(pos=1)
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    print('\nList deleted Fields')
    df_s = r1.listDeletedFields()
    for (field, origModTime, origPos) in df_s:
        print(field.label, origModTime, f'pos={origPos}')

    time.sleep(1)
    print('\nUndelete last field deleted (Phone)')
    r1.undelField()
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nUndelete field "unseen"')
    r1.undelField(label='unseen')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    print('\nUndelete nonexistent field "Wxyz"')
    r1.undelField(label='Wxyz')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    time.sleep(1)
    print('\nUndelete field "IPv4 address"')
    r1.undelField(label='IPv4 address')
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    print('\nUndelete last field deleted when there are none')
    r1.undelField()
    print(f'Rec modTime {r1.getRecModTime()}')
    for field in r1:
        print(field.label, field.value, field._getModTime())

    print('\nIDs in DB:')
    for id in _db:
        print(id)
    return normalExit  # to OS (sys.exit)

if __name__ == '__main__':
    sys.exit(_selfTest(sys.argv[1:]))