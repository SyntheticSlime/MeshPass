'''Define Exceptions for Programmer & User errors
'''

import sys  # exit()

class _MPException (Exception):
    def __init__(self, message=''):
        if len(message) > 0:
            sys.exit(message)
        return

class ProgrammerError (_MPException):
    def __init__ (self, message=''):
        super().__init__(message)  # for ancestor class
        sys.exit('Programming error - program terminating.')

class UserError (_MPException):
    def __init__ (self, message=''):
        super().__init__(message)  # for ancestor class
        sys.exit('User error not handled by program - program terminating.')
