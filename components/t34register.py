from inspect import cleandoc
from config.t34_instructions import *
from config.misc import __tab__


class T34Register:
    def __init__(self, size, name, description):
        self.val = 0
        self.size = size
        self.name = name
        # noinspection PyStringFormat
        self.__doc__ += "\n{s:}Description:\n{s:}{s:}{}\n".format(description, s=__tab__)

    def get(self):
        return self.val

    def set(self, v):
        mask = (1 << self.size) - 1
        self.val = mask & v
        return self.val
