'''Define Exceptions for Programmer & User errors
'''

import sys  # exit()

class _MPException (Exception):
    pass

class ProgrammerError (_MPException):
    def __init__ (self, message=''):
        super().__init__(message)  # for ancestor class
        sys.exit('Programming error - program terminating.')

class UserError (_MPException):
    def __init__ (self, message=''):
        super().__init__(message)  # for ancestor class