from logging import *


def logForLevel(self, message, *args, **kwargs):
    if self.isEnabledFor(DEBUG + 5):
        self._log(DEBUG + 5, message, args, **kwargs)


def logToRoot(message, *args, **kwargs):
    log(DEBUG + 5, message, *args, **kwargs)


addLevelName(DEBUG + 5, 'VERBOSE')
VERBOSE = DEBUG + 5
setattr(getLoggerClass(), 'verbose', logForLevel)
verbose = logToRoot
