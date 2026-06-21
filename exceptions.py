'''Define Exceptions for Programmer & User errors
'''

import sys  # exit()

class _MPException (Exception):
  def __init__(self, message=''):
# def __init__(self, errno, message):
#   self.errno = errno
    self.message = message
    self.args = (message,)
#   self.args = (errno, message)
    return

class ProgrammerError (_MPException):
  def __init__ (self, message=''):
    super().__init__(message)  # for ancestor class
    if len(message) == 0:
      sys.exit('Programming error - program terminating.')
    else:
      sys.exit(message)
    return

class UserError (_MPException):
  def __init__ (self, message=''):
    super().__init__(message)  # for ancestor class
    if len(message) == 0:
      sys.exit('User error not handled by program - program terminating.')
    else:
      sys.exit(message)
    return