from inspect import cleandoc
from config.t34_exceptions import *
from config.t34_instructions import *


class T34Instruction:
    def __init__(self, name, description, illegal_am):
        self.name = name
        self.description = description
        self.illegal_am = illegal_am
        self.op1 = 0
        self.op2 = 0

    def op(self):
        raise NotImplemented

    def get_operands(self, binary_instruction, machine):
        addr, _, mode, ir = T34Instruction.parse(binary_instruction)
        self.op1 = T34Instruction.__getOperand1__(machine)
        self.op2 = T34Instruction.__getOperand2__(addr, mode, ir, machine)

    @staticmethod
    def parse(binary_instruction):
        addr = T34Instruction.__getAddr__(binary_instruction)
        opcode = T34Instruction.__getOp__(binary_instruction)
        mode, ir = T34Instruction.__getMode__(binary_instruction)
        return addr, opcode, mode, ir

    @staticmethod
    def __extf__(binary_instruction, bits):
        top, bot = bits
        mask = (1 << (top - bot + 1)) - 1
        return (binary_instruction >> bot) & mask

    @staticmethod
    def __getOperand1__(machine):
        return machine.regfile['AC'].get()

    @staticmethod
    def __getOperand2__(addr, mode, ir, machine):
        if mode not in machine.address_path:
            raise IllegalAddressingMode
        return machine.address_path[mode](addr, ir)

    @staticmethod
    def __getAddr__(binary_instruction):
        bits = instruction_format['ADDR']['bits']
        return T34Instruction.__extf__(binary_instruction, bits)

    @staticmethod
    def __getOp__(binary_instruction):
        bits = instruction_format['OP']['bits']
        return T34Instruction.__extf__(binary_instruction, bits)

    @staticmethod
    def __getMode__(binary_instruction):
        bits_ir = instruction_format['AM']['IR']['bits']
        bits_mode = instruction_format['AM']['MODE']['bits']
        ir = T34Instruction.__extf__(binary_instruction, bits_ir)
        mode = T34Instruction.__extf__(binary_instruction, bits_mode)
        return mode, ir


class HALT(T34Instruction):
    def __init__(self):
        code = instruction_format['HALT']
        super().__init__(**instruction_format[code])

    def op(self, machine):
        raise Halted

