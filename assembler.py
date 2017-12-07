import sys

from t34_instructions import *

start = 0
prog_start = 0
labels = {}
variables = {}


def tocode(addr, instr, mode, ir):
    return (addr << 12) + (instr << 6) + (mode << 2) + ir


# Pass one: get labels
with open(sys.argv[1]) as f:
    ic = 0
    lines = f.readlines()
    for s in lines:
        # print(s)
        if len(s.split()) == 0 or s.split()[0][0] == "#":
            continue

        elif s.split()[0] in instructions or s.split()[0] == "return":
            ic += 1

        elif s.split()[0] == "link":
            ic += 3

        elif s.split()[0] == "lab":
            _, lab, *_ = s.split()
            labels[lab] = ic

        elif s.split()[0] == "def":
            _, lab, val = s.split()
            # print(val)
            if val[:2] == "0x":
                variables[lab] = int(val, 16)
            elif val in variables:
                variables[lab] = variables[val]
            else:
                raise Exception("You dummy, you gave me a bad file")

        elif s.split()[0] == "param":
            labs = s[s.find("param") + len("param"):].split(",")
            offset = 0
            # print(labs)
            for lab in labs:
                z = lab.strip().split()
                if len(z) == 1:
                    variables[z[0]] = offset
                    offset += 1
                elif z[1][:2] == "0x":
                    variables[z[0]] = int(z[1], 16)
                elif z[1] in variables:
                    variables[z[0]] = variables[z[1]]
                else:
                    raise Exception("You dummy, you gave me a bad file")

        elif s.split()[0] == "returns":
            labs = s[s.find("returns") + len("returns"):].split(",")
            offset = 0
            for lab in labs:
                z = lab.strip().split()
                if len(z) == 1:
                    variables[z[0]] = offset
                    offset += 1
                elif z[1][:2] == "0x":
                    variables[z[0]] = int(z[1], 16)
                elif z[1] in variables:
                    variables[z[0]] = variables[z[1]]
                else:
                    raise Exception("You dummy, you gave me a bad file")

        elif s.split()[0] == "local":
            labs = s[s.find("local") + len("local"):].split(",")
            offset = 0xfff
            # print(labs)
            for lab in labs:
                z = lab.strip().split()
                if len(z) == 1:
                    variables[z[0]] = offset
                    offset -= 1
                elif z[1][:2] == "0x":
                    variables[z[0]] = int(z[1], 16)
                elif z[1] in variables:
                    variables[z[0]] = variables[z[1]]
                else:
                    raise Exception("You dummy, you gave me a bad file")

        elif s.split()[0] == "start":
            _, v = s.split()
            start = int(v, 16)
            prog_start = start - ic

    #print(variables)
    #print(labels)
    ic = 0
    prog_instr = []
    for s in lines:
        #print(s)
        if len(s.split()) == 0 or s.split()[0][0] == "#":
            continue

        elif s.split()[0] in instructions:
            instr, mode, *rest = s.split()
            if instr[-1] == "X" or mode == "Indexed" or mode == "Indexed-Indirect":
                ir, addr = rest
            else:
                addr = rest[0]
                ir = "X3"
            if instr[0] == "J":
                addr = labels[addr] + prog_start
            elif addr in variables:
                addr = variables[addr]
            elif addr.find("0x") == 0:
                addr = int(addr, 16)
            instr = instructions[instr]
            mode = addressing_modes[mode.replace("-", " ")]
            ir = int(ir[1])
            #print(type(addr), type(mode), type(ir), type(instr))
            prog_instr.append("{:06x}".format(tocode(addr,instr,mode,ir)))
            #print("{:03x} 1 {:06x}".format(ic + prog_start, tocode(addr, instr, mode, ir)))
            ic += 1

        elif s.split()[0] == "set":
            _, addr, *vals = s.split()
            if addr in variables:
                addr = variables[addr]
            else:
                addr = int(addr, 16)
            data = []
            for v in vals:
                if v[:2] == "0x":
                    data.append("{:06x}".format(int(v, 16)))
                elif v in variables:
                    data.append("{:06x}".format(variables[v]))
            print("{:03x}".format(addr), len(data), *data)

        elif s.split()[0] == "setp":
            _, addr, *vals = s.split()
            if addr in variables:
                addr = variables[addr]
            else:
                addr = int(addr, 16)
            data = []
            for v in vals:
                if v[:2] == "0x":
                    data.append("{:03x}000".format(int(v, 16)))
                elif v in variables:
                    data.append("{:03x}000".format(variables[v]))
            print("{:03x}".format(addr), len(data), *data)

        elif s.split()[0] == "link":
            addr = prog_start + ic + 3
            instr = instructions["LDX"]
            ir = 2
            mode = addressing_modes["Immediate"]
            prog_instr.append("{:06x}".format(tocode(addr, instr, mode, ir)))
            #print("{:03x} 1 {:06x}".format(ic + prog_start, tocode(addr, instr, mode, ir)))
            ic += 1
            addr = variables["LR"]
            instr = instructions["STX"]
            ir = 2
            mode = addressing_modes["Direct"]
            prog_instr.append("{:06x}".format(tocode(addr, instr, mode, ir)))
            #print("{:03x} 1 {:06x}".format(ic + prog_start, tocode(addr, instr, mode, ir)))
            ic += 1
            addr = labels[s.split()[1]] + prog_start
            instr = instructions["J"]
            ir = 3
            mode = addressing_modes["Direct"]
            prog_instr.append("{:06x}".format(tocode(addr, instr, mode, ir)))
            #print("{:03x} 1 {:06x}".format(ic + prog_start, tocode(addr, instr, mode, ir)))
            ic += 1

        elif s.split()[0] == "return":
            addr = variables["LR"]
            instr = instructions["J"]
            mode = addressing_modes["Indirect"]
            ir = 3
            prog_instr.append("{:06x}".format(tocode(addr, instr, mode, ir)))
            #print("{:03x} 1 {:06x}".format(ic + prog_start, tocode(addr, instr, mode, ir)))
            ic += 1

    print("{:03x}".format(prog_start), len(prog_instr), *prog_instr)
    print("{:03x}".format(start))
