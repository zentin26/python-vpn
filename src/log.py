#!/usr/bin/python
import sys
import logging


class _LessThanFilter(logging.Filter):
    def __init__(self, exclusive_maximum, name=''):
        super(_LessThanFilter, self).__init__(name)
        self.max_level = exclusive_maximum

    def filter(self, record):
        # non-zero return means we log this message
        return 1 if record.levelno < self.max_level else 0

def get_logger(level='DEBUG'):
    logger = logging.getLogger()

    # parse log level
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError("Invalid log level: {}".format(loglevel))
    logger.setLevel(numeric_level)

    formatter = logging.Formatter('%(asctime)s - %(filename)s/%(funcName)s - %(levelname)s: %(message)s')

    # info to stdout
    logging_handler_out = logging.StreamHandler(sys.stdout)
    logging_handler_out.setLevel(logging.DEBUG)
    logging_handler_out.setFormatter(formatter)
    logging_handler_out.addFilter(_LessThanFilter(logging.WARNING))
    logger.addHandler(logging_handler_out)

    # errors to stderr
    logging_handler_err = logging.StreamHandler(sys.stderr)
    logging_handler_err.setLevel(logging.WARNING)
    logging_handler_err.setFormatter(formatter)
    logger.addHandler(logging_handler_err)

    return logger
