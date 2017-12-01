"""Welcome to the T34 emulator!

Project: CSC317_PA1
Author: Noah Brubaker
Instructor: Dr. Karllson

The T34 is a 24-bit word-addressable accumulator architecture.
It supports up to 64 instructions, 4 addressing modes, and 4096 words of memory.

Program One demonstrates the memory and instruction parsing for the emulator.

Usage:
$ python t34.py [--help] | <t34_obj_file> [-v] [t34_script]
T34>> <cmd> {args}

Examples:
$ python t34.py hello.obj demo.t34
T34>> dump
T34>> parse 0F8
T34>> parse 0F8 100
T34>> help
T34>> help parse
T34>> exit
$
"""
import sys
from t34_exceptions import *
from t34_instructions import *
from t34_regfile import *


class T34:
    """Welcome to the T34 Emulator!

    Available commands:

        help:
            Prints documentation for the emulator with no arguments or the
            documentation for a the single command listed as an argument

        dump:
            Prints the location and data for all memory addresses containing
            non-zero data

        parse:
            Parses the instruction at a given memory address or range of addresses
            into the corresponding operand addr, opcode, and addressing mode.

    """

    def __init__(self, fname):
        """
        Loads the specified T34 object file into memory

        ARGS:
            <fname>: the path to a valid T34 object file
        """
        # command list
        T34.cmds = {
            "dump": T34.dump,
            "parse": T34.parse,
        }

        # Set up addressing mode lookups
        self.addr = {k: v for k, v in addressing_modes.items()}
        self.addr[0b0000]["op"] = self.__am_direct__
        self.addr[0b0001]["op"] = self.__am_immediate__
        self.addr[0b0010]["op"] = self.__am_indexed__
        self.addr[0b0100]["op"] = self.__am_indirect__
        self.addr[0b0110]["op"] = self.__am_indexed_indirect__

        # Set up instruction lookups
        self.decoded_instr = 0, 0, 0, 0
        self.instr = {k: v for k, v in instructions.items()}
        self.instr[0b000000]["op"] = self.__instr_halt__
        self.instr[0b000001]["op"] = self.__instr_nop__
        self.instr[0b110011]["op"] = self.__instr_jp__
        self.instr[0b010000]["op"] = self.__instr_ld__
        self.instr[0b010001]["op"] = self.__instr_st__
        self.instr[0b010010]["op"] = self.__instr_em__
        self.instr[0b011000]["op"] = self.__instr_ldx__
        self.instr[0b011001]["op"] = self.__instr_stx__
        self.instr[0b011010]["op"] = self.__instr_emx__
        self.instr[0b100000]["op"] = self.__instr_add__
        self.instr[0b100001]["op"] = self.__instr_sub__
        self.instr[0b100010]["op"] = self.__instr_clr__
        self.instr[0b100011]["op"] = self.__instr_com__
        self.instr[0b100110]["op"] = self.__instr_xor__
        self.instr[0b101000]["op"] = self.__instr_addx__
        self.instr[0b101001]["op"] = self.__instr_subx__
        self.instr[0b101010]["op"] = self.__instr_clrx__
        self.instr[0b110000]["op"] = self.__instr_j__
        self.instr[0b110001]["op"] = self.__instr_jz__
        self.instr[0b110010]["op"] = self.__instr_jn__
        self.instr[0b100100]["op"] = self.__instr_and__
        self.instr[0b100101]["op"] = self.__instr_or__

        # setup registers from config
        self.regfile = {k: v for k, v in reginfo.items()}
        for k in reginfo:
            self.setr(k, 0)
        self.mem = [0] * 4096

        # Load file
        try:  # try to load the object file
            with open(fname) as f:
                for l in f:
                    l = list(x.strip() for x in l.split())
                    if len(l) == 1:
                        # terminated with line with single word which is the pc
                        self.setr("IC", int(l[0], 16))
                        break
                    else:
                        # first is the address, next is number of data entries
                        # finally the actual data that needs to be stored at addr
                        addr = int(l[0], 16)
                        n = int(l[1])
                        self.mem[addr:addr + n] = list(int(x, 16) for x in l[2:])
        except Exception as e:
            print(e)

    @staticmethod
    def __sign_extend__(val, target_size, current_size):
        sbit = val >> current_size - 1
        m1 = (sbit << current_size) - 1
        m2 = (sbit << target_size) - 1
        return val ^ m1 ^ m2

    # Addressing Control Path functions
    def __get_ea__(self):
        addr, opcode, mode, ir = self.decoded_instr
        ic = False
        if mode not in self.addr:
            raise IllegalAddressingMode
        if opcode & 0b110000 == 0:
            ic = True
        self.addr[mode]["op"](addr, ir)

    def __am_direct__(self, addr, *_):
        self.setr('MAR', addr)

    def __am_immediate__(self, addr, *_):
        s1 = self.regfile['MAR']['size']
        s2 = self.regfile['MDR']['size']
        self.setr('MDR', T34.__sign_extend__(addr, s2, s1))

    def __am_indexed__(self, addr, ir):
        raise UnimplementedAddressingMode
        # offset = self.regfile['X{}'.format(ir)]
        # self.setr('MAR', addr + offset)

    def __am_indirect__(self, addr, *_):
        raise UnimplementedAddressingMode
        # addr = self.mem[addr] >> 12
        # self.setr('MAR',addr)

    def __am_indexed_indirect__(self, addr, ir):
        raise UnimplementedAddressingMode
        # offset = self.regfile['X{}'.format(ir)]
        # addr = self.mem[addr + offset]
        # setr('MAR',addr)

    # Data path functions
    def __load__(self):
        self.setr("MDR", self.mem[self.getr("MAR")])

    def __load_instr__(self):
        self.setr("IR", self.mem[self.getr("IC")])

    def __next_instr__(self):
        self.setr("IC", self.getr("IC") + 1)

    def __store__(self):
        self.mem[self.getr("MAR")] = self.getr("MDR")

    # Instruction definitions
    def __instr_halt__(self):
        raise Halted

    def __instr_nop__(self):
        pass

    def __instr_ld__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        self.setr("AC", self.getr("MDR"))

    def __instr_st__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        self.setr("MDR", self.getr("AC"))
        self.__store__()

    def __instr_em__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        self.__load__()
        self.setr("DBUS", self.getr("MDR"))
        self.setr("MDR", self.getr("AC"))
        self.setr("AC", self.getr("DBUS"))
        self.__store__()

    def __instr_ldx__(self):
        raise UnimplementedOpcode

    def __instr_stx__(self):
        raise UnimplementedOpcode

    def __instr_emx__(self):
        raise UnimplementedOpcode

    def __instr_add__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        v1 = self.getr("AC")
        v2 = self.getr("MDR")
        self.setr("AC", v1 + v2)

    def __instr_sub__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        v1 = self.getr("AC")
        v2 = self.getr("MDR")
        self.setr("AC", v1 - v2)

    def __instr_clr__(self):
        self.setr("AC", 0)

    def __instr_com__(self):
        self.setr("AC", ~self.getr("AC"))

    def __instr_and__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        v1 = self.getr("AC")
        v2 = self.getr("MDR")
        self.setr("AC", v1 & v2)

    def __instr_or__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        v1 = self.getr("AC")
        v2 = self.getr("MDR")
        self.setr("AC", v1 | v2)

    def __instr_xor__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.addr[mode]["name"] != "Immediate":
            self.__load__()
        v1 = self.getr("AC")
        v2 = self.getr("MDR")
        self.setr("AC", v1 ^ v2)

    def __instr_addx__(self):
        raise UnimplementedOpcode

    def __instr_subx__(self):
        raise UnimplementedOpcode

    def __instr_clrx__(self):
        raise UnimplementedOpcode

    def __instr_j__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        self.setr("IC", self.getr("MAR"))

    def __instr_jz__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.getr("AC") == 0:
            self.setr("IC", self.getr("MAR"))

    def __instr_jn__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        if self.getr("AC") >> self.regfile["AC"]["size"] - 1 == 1:
            self.setr("IC", self.getr("MAR"))

    def __instr_jp__(self):
        addr, opcode, mode, ir = self.decoded_instr
        if mode not in self.addr or self.addr[mode]["name"] in self.instr[opcode]["illegal_am"]:
            raise IllegalAddressingMode
        self.__get_ea__()
        v1 = self.getr("AC")
        if v1 != 0 and v1 >> self.regfile["AC"]["size"] - 1 == 0:
            self.setr("IC", self.getr("MAR"))

    def getr(self, name):
        return self.regfile[name]['value']

    def setr(self, name, val):
        mask = (1 << self.regfile[name]['size']) - 1
        self.regfile[name]['value'] = val & mask
        return val & mask

    def __parse_instr__(self):
        """
        Parses the data stored at the given address or range of addresses. The first
        12 bits are interpreted as the operand address, the next 6 bits are the opcode
        and the last 6 bits are the addressing mode.

        When using range, it only parses non-zero memory locations

        0 < start_addr < 0x1000

        Must provide addresses in hexadecimal format.

        USAGE:
            T34>> parse <start_addr> [end_addr]

        ARGS:
            <start_addr>: The address to parse or the starting address of range

            [end_addr]: The end address of the range (not inclusive)
        """
        instr = self.getr("IR")
        t_addr, s_addr = instruction_format["ADDR"]["bits"]
        t_op, s_op = instruction_format["OP"]["bits"]
        t_mode, s_mode = instruction_format["MODE"]["bits"]
        t_ir, s_ir = instruction_format["IR"]["bits"]
        m_addr = (1 << t_addr + 1) - 1
        m_op = (1 << t_op + 1) - 1
        m_mode = (1 << t_mode + 1) - 1
        m_ir = (1 << t_ir + 1) - 1
        addr = (instr & m_addr) >> s_addr
        opcode = (instr & m_op) >> s_op
        mode = (instr & m_mode) >> s_mode
        ir = (instr & m_ir) >> s_ir
        self.decoded_instr = addr, opcode, mode, ir

    def trace(self):
        halted = False
        trace = {}
        msg = ""
        while not halted:
            try:
                trace.update(ic=self.getr("IC"))
                self.__load_instr__()
                trace.update(ir=self.getr("IR"))
                self.__parse_instr__()
                opcode = self.decoded_instr[1]
                if opcode not in self.instr:
                    raise UndefinedOpcode
                trace.update(op=self.instr[opcode]["name"])
                self.instr[opcode]["op"]()
            except Halted as e:
                msg = str(e)
                trace.update(ea="   ")
                halted = True
            except UndefinedOpcode as e:
                msg = str(e)
                trace.update(op="????")
                trace.update(ea="IMM")
                halted = True
            except UnimplementedOpcode as e:
                msg = str(e)
                trace.update(ea="IMM")
                halted = True
            except IllegalAddressingMode as e:
                msg = str(e)
                trace.update(ea="???")
                halted = True
            except UnimplementedAddressingMode as e:
                msg = str(e)
                trace.update(ea="???")
                halted = True
            else:
                mode = self.decoded_instr[2]
                if self.addr[mode]["name"] == "Immediate":
                    trace.update(ea="IMM")
                    self.__next_instr__()
                elif trace["op"] in {"J", "JN", "JZ", "JP"}:
                    trace.update(ea=self.getr("IC"))
                else:
                    trace.update(ea=self.getr("MAR"))
                    self.__next_instr__()
            finally:
                trace.update(ac=self.getr("AC"),
                             x0=self.getr("X0"),
                             x1=self.getr("X1"),
                             x2=self.getr("X2"),
                             x3=self.getr("X3"))
                trace['ea'] = "{:03x}".format(trace["ea"]) if type(trace["ea"]) is int else "{:<3s}".format(trace["ea"])
                print("{ic:03x}:  {ir:06x}  {op:<4s}  {ea:}  AC[{ac:06x}]  X0[{x0:03x}]  "
                      "X1[{x1:03x}]  X2[{x2:03x}]  X3[{x3:03x}]".format(**trace))
        print(msg)

    def parse(self, start_addr, end_addr=None):
        """
        Parses the data stored at the given address or range of addresses. The first
        12 bits are interpreted as the operand address, the next 6 bits are the opcode
        and the last 6 bits are the addressing mode.

        When using range, it only parses non-zero memory locations

        USAGE:
            T34>> parse <start_addr> [end_addr]

        ARGS:
            <start_addr>: The address to parse or the starting address of range

            [end_addr]: The end address of the range (not inclusive)
        """
        header = "          ADDR       OP     AM"
        fstr = "{:03x}:  {:012b} {:06b} {:06b}"
        if end_addr is None:
            start_addr = int(start_addr, 16)
            print(header)
            val = self.mem[start_addr]
            print(fstr.format(start_addr, val >> 12, (val >> 6) & 63, val & 63))
        else:
            start_addr, end_addr = int(start_addr, 16), int(end_addr, 16)
            print(header)
            for addr, val in enumerate(self.mem[start_addr:end_addr], start_addr):
                if val > 0:
                    print(fstr.format(addr, val >> 12, (val >> 6) & 63, val & 63))
        print()

    def dump(self):
        """
        Prints information at every memory location where the stored data is not zero.

        USAGE:
            T34>> dump

        ARGS: None
        """
        fstr = "{:03x}:  {:06x}"
        print("\n".join(list(fstr.format(i, m) for i, m in enumerate(self.mem) if m > 0)))
        print()


# Command line interface for T34
if __name__ == "__main__":
    if len(sys.argv) == 2:
        fname = sys.argv[1]
        try:
            verbose = False
            em = T34(fname)
            em.trace()
        except FileNotFoundError as e:
            print(e)
            # except Exception as e:
            #   print(e)
    else:  # Show usage if no arguments were provided
        u1 = __doc__.find('Usage:')
        u2 = __doc__.find('Examples:')
        print("\n" + __doc__[u1:u2])
