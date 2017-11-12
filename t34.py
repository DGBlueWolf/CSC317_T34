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
        """
        Loads the specified T34 object file into memory

        ARGS:
            <fname>: the path to a valid T34 object file
        """
        # command list
        T34.cmds = {
            "help": T34.help,
            "dump": T34.dump,
            "parse": T34.parse,
        }
        # self.addr = {}
        # self.instr = {}
        # setup registers from config
        # self.regfile = {}
        self.pc = 0
        self.mem = [0] * 4096
        # Load file
        try:  # try to load the object file
            with open(fname) as f:
                for l in f:
                    l = list(x.strip() for x in l.split())
                    if (len(l) == 1):
                        # terminated with line with single word which is the pc
                        self.pc = int(l[0], 16)
                        break
                    else:
                        # first is the address, next is number of data entries
                        # finally the actual data that needs to be stored at addr
                        addr = int(l[0], 16)
                        n = int(l[1])
                        self.mem[addr:addr + n] = list(int(x, 16) for x in l[2:])
                        # TODO: Handle exceptions caused by the object file more nicely
        except Exception as e:
            print(e)

    def help(self, cmd=None):
        """
        Prints the docstring describing the usage of the the given command.
        
        ARGS:
            [cmd]: name of the command
        """
        if cmd is None:  # no arg means print command list
            print(self.__doc__[self.__doc__.find("Available"):])
        else:
            try:  # print help for cmd or catch key error
                print(T34.cmds[cmd].__doc__)
            except KeyError:
                print("'{}' is not a valid command.".format(cmd))

    def parse(self, start_addr, end_addr=None):
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

    def run(self, from_script=False, verbose=False, *, script_name=None):
        """
        Starts the T34 Emulator with the desired interface.

        ARGS:
            [from_script]: Flag indicating the emulator should run commands from a script
                provided at the command line

            [verbose]: Flag indicating whether commands should be echoed when running
                a script.

            [script_name]: Name of the script file to be loaded.
        """
        # Print a nice startup message if running in the terminal if verbose
        if verbose and not from_script:
            print("\n" + self.__doc__)

        if from_script:
            f = open(script_name)

        while True:
            if from_script:  # If input is from a script get input from script
                raw = f.readline()
                if verbose: print("T34>>", raw)
            else:  # Get input from user
                raw = input("T34>> ")

            args = list(arg.strip() for arg in raw.split())  # Get space-sep args

            if len(args) == 0:  # If no input, do nothing
                continue

            cmd, *args = args
            if cmd == "exit":  # Exit on 'exit'
                break

            try:  # Try to interpret the users command
                T34.cmds[cmd](self, *args)
            except KeyError:  # Key error will happen if commannd not in cmd-dict
                print("Command '{}' not recognized.".format(cmd))
            except TypeError:  # Type error will happen if command improperly used
                print("Incorrect usage of '{}' command: \n".format(cmd))
                msg = T34.cmds[cmd].__doc__
                msg = msg[msg.find('USAGE'):]
                print(msg)
            except IndexError:
                print("Error: Parse recieved an index outside range 0x0000 to 0x1000.")
            except ValueError:
                print("Must provide address(es) as hexadecimal integer(s).")
            # For other errors show stack trace and 
            except BaseException as e:
                print_exc()
            finally:
                break

        # Cleanup
        if from_script:
            f.close()


# Command line interface for T34
if __name__ == "__main__":
    if len(sys.argv) > 1:
        fname, *args = sys.argv[1:]
        try:
            verbose = False
            em = T34(fname)
            if "--help" in args:
                print("\n" + __doc__)
            if "-v" in args:
                verbose = True
                del args[args.index("-v")]
            if len(args) == 1:
                em.run(from_script=True, verbose=verbose, script_name=args[0])
            elif len(args) > 1:
                print("Unrecognized arguments provided, use the --help to see usage examples.")
            else:
                em.run()
        except FileNotFoundError as e:
            print(e)
        except Exception as e:
            print(e)
    else:  # Show usage if no arguments were provided
        u1 = __doc__.find('Usage:')
        u2 = __doc__.find('Examples:')
        print("\n" + __doc__[u1:u2])
