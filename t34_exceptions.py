def raise_(ex):
    raise ex

class T34Sig(Exception):
    def __init__(self, message, errorcode):
        self.errorcode = errorcode
        self.message = message
        super().__init__("Machine Halted - {}".format(message))


class Halted(T34Sig):
    """A HALT instruction was executed. (Normal Termination)"""

    def __init__(self):
        super().__init__("HALT instruction executed", 0)


class UndefinedOpcode(T34Sig):
    """An opcode which was not defined was encounted. (ErrorCode 1)"""

    def __init__(self):
        super().__init__("undefined opcode", 1)


class UnimplementedOpcode(T34Sig):
    """An opcode which has not been implemented was encountered. (ErrorCode 2)"""

    def __init__(self):
        super().__init__("unimplemented opcode", 2)


class IllegalAddressingMode(T34Sig):
    """An invalid mode was specified in instruction. (ErrorCode 3)"""

    def __init__(self):
        super().__init__("illegal addressing mode", 3)


class UnimplementedAddressingMode(T34Sig):
    """An addressing mode which has not been implemented was encountered. (ErrorCode 4)"""

    def __init__(self):
        super().__init__("unimplemented addressing mode", 4)
