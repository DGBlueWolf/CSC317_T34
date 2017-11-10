"""Welcome to the T34 emulator!

Project: CSC317_PA1
Author: Noah Brubaker
Instructor: Dr. Karllson

The T34 is a 24-bit word-addressable accumulator architecture.
It supports up to 64 instructions, 4 addressing modes, and 4096 words of memory.

Program One demonstrates the memory and instruction parsing for the emulator. 

Usage:
$ python t34.py <t34_obj_file> [t34_script]
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
import config.t34_instructions as instr
import config.t34_regfile as reg
from components.t34register import T34Register
from components.t34instruction import T34Instruction
from config.t34_exceptions import T34Sig
from argparse import ArgumentParser
from inspect import cleandoc
from traceback import print_exc

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
        '''
        Loads the specified T34 object file into memory

        ARGS:
            <fname>: the path to a valid T34 object file
        '''
        T34.cmds = {
            "help": T34.help,
            "dump": T34.dump,
            "parse": T34.parse,
        }
        self.pc = 0
        self.mem = [0] * 4096
        # Load file
        with open(fname) as f:
            for l in f:
                l = list(x.strip() for x in l.split())
                if len(l) == 1:
                    self.pc = int(l[0], 16)
                else:
                    addr = int(l[0], 16)
                    n = int(l[1])
                    self.mem[addr:addr + n] = list(int(x, 16) for x in l[2:])

    def help(self, cmd=None):
        '''
        Prints the docstring describing the usage of the the given command.

        ARGS:
            [cmd]: name of the command 
        '''
        if cmd is None:
            print(cleandoc(self.__doc__[self.__doc__.find("Available"):]))
        else:
            print(cleandoc(T34.cmds[cmd].__doc__))

    def parse(self, start_addr, end_addr=None):
        '''
        Parses the data stored at the given address or range of addresses. The first 
        12 bits are interpretted as the operand address, the next 6 bits are the opcode
        and the last 6 bits are the addressing mode. 

        When using range, it only parses non-zero memory locations

        USAGE: 
            T34>> parse <start_addr> [end_addr]
            
        ARGS:
            <start_addr>: The address to parse or the starting address of range
            
            [end_addr]: The end address of the range (not inclusive)
        '''
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
        '''
        Prints information at every memory location where the stored data is not zero.

        USAGE:
            T34>> dump 
            
        ARGS: None
        '''
        fstr = "{:03x}:  {:06x}"
        print("\n".join(list(fstr.format(i, m) for i, m in enumerate(self.mem) if m > 0)))
        print()

    def trace(self, instr):
        pass

    def run(self, from_script=False, verbose=False, *, script_name=None):
        '''
        Starts the T34 Emulator with the desired interface.

        ARGS:
            [from_script]: Flag indicating the emulator should run commands from a script
                provided at the command line
            
            [verbose]: Flag indicating whether commands should be echoed when running
                a script.
                
            [script_name]: Name of the script file to be loaded.
        '''
        if not from_script or verbose:
            print("\n" + cleandoc(__doc__))

        if from_script:
            f = open(script_name)

        while (True):
            raw = f.readline() if from_script else input("T34>> ")
            args = list(arg.strip() for arg in raw.split())

            if len(args) == 0:
                continue

            cmd, *args = args
            if cmd == "exit":
                return

            try:
                T34.cmds[cmd](self, *args)
            except KeyError:
                print("Command '{}' not recognized".format(cmd))
            except TypeError:
                print("Incorrect usage of '{}' command: \n".format(cmd))
                msg = cleandoc(T34.cmds[cmd].__doc__)
                msg = msg[msg.find('USAGE'):]
                print(msg)
            except BaseException as e:
                print_exc()


# Command line interface for T34
if __name__ == "__main__":
    desc = cleandoc(__doc__)
    desc = desc[:desc.find('Usage:')]
    parser = ArgumentParser(description=desc)
    parser.add_argument('obj', required=True)
    parser.add_argument('-i', '--interactive')
    parser.add_argument('-d', '--debug')
    parser.add_argument('--file')
    parser.add_argument('-v', '--version', version='T34 -- CSC317_F17_PA2')
    args = parser.parse_args()

    if len(sys.argv) == 2:
        fname = sys.argv[1:]
        em = T34(fname)
        try:
            em = T34(fname)
            em.run()
        except T34Sig as e:
            print(e)
            exit(e.errorcode)
        except BaseException as e:
            print(e)
            exit(-1)
    else:
        u1 = __doc__.find('Usage:')
        u2 = __doc__.find('Examples:')
        print("\n" + __doc__[u1:u2])
