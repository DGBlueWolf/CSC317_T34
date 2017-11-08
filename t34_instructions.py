instruction_format = {
    "ADDR": {
        "bits": (23,12), "name": "Operand Address",
        "description": "Holds the address of the operand.",
    },
    "OP": {
        "bits": (11,6), "name": "Opcode",
        "description": "Holds the operation to be executed.",
    },
    "AM": {
        "bits": (5,0), "name": "Addressing Mode",
        "description": "Describes how memory in operand address is to be accessed.",
        "IR": {
            "bits": (1,0), "name": "Index Resister Number",
            "description": "The index of the index register to access.",
        },
        "MODE": {
            "bits": (5,2), "name": "Mode",
            "description": "The mode label.",
        },
    },
}

addressing_modes = {
    0b0000: { "name": "Direct", 
        "description": "EA is the contents of the address field."
    },
    0b0001: { "name": "Immediate",
        "description": "There is no EA - the operand data is the sign-extended address field contents.",
    },
    0b0010: { "name": "Indexed",
        "description": "EA is the sum of the address field and the specified index register.",
    },
    0b0100: { "name": "Indirect",
        "description": "Address field contains the address of an indirect word in memory; the EA is the upper 12 bits of that word.",
    },
    0b0110: { "name": "Indexed Indirect",
        "description": "Perform indexing; the result is the address of an indirect word, whose upper 12 bits is the EA",
    },
} 
addressing_modes.update( { v['name']: k for k,v in addressing_modes.items() } )

instructions = {
    0b000000: { "name": "HALT",
        "description": "Halt the machine.",
        "illegal_am": None,
    }, 
    0b000001: { "name": "NOP",
        "description": "Do nothing.",
        "illegal_am": None,
    }, 
    0b010000: { "name": "LD",
        "description": "Load the accumulator from memory.",
        "illegal_am": set(),
    },
    0b010001: { "name": "ST",
        "description": "Store the accumulator into memory.",
        "illegal_am": {"Immediate"},
    },
    0b010010: { "name": "EM",
        "description": "Exchange the accumulator with memory.",
        "illegal_am": {"Immediate"},
    },
    0b011000: { "name": "LDX",
        "description": "Load the specified index register from the upper half of a memory word.",
        "illegal_am": {"Indexed","Indirect","Indexed Indirect"},
    },
    0b011001: { "name": "STX",
        "description": "Store the specified index register into the upper half of a memory word.",
        "illegal_am": {"Indexed","Indirect","Indexed Indirect","Immediate"},
    },
    0b011010: { "name": "EMX",
        "description": "Exchange the specified index register with the upper half of a memory word.",
        "illegal_am": {"Indexed","Indirect","Indexed Indirect","Immediate"},
    },
    0b100000: { "name": "ADD",
        "description": "Add memory to the accumulator.",
        "illegal_am": set(),
    },
    0b100001: { "name": "SUB",
        "description": "Subtract memory from the accumulator.",
        "illegal_am": set(),
    },
    0b100010: { "name": "CLR",
        "description": "Clear the accumulator.",
        "illegal_am": None,
    },
    0b100011: { "name": "COM",
        "description": "Complement the accumulator.",
        "illegal_am": None,
    },
    0b100100: { "name": "AND",
        "description": "AND memory to the accumulator.",
        "illegal_am": set(),
    },
    0b100101: { "name": "OR",
        "description": "OR memory to the accumulator.",
        "illegal_am": set(),
    },
    0b100110: { "name": "XOR",
        "description": "XOR memory to the accumulator.",
        "illegal_am": set(),
    },
    0b101000: { "name": "ADDX",
        "description": "Add memory to the specified index register.",
        "illegal_am": {"Indexed","Indirect","Indexed Indirect"},
    },
    0b101001: { "name": "SUBX",
        "description": "Subtract memory from the specified index register.",
        "illegal_am": {"Indexed","Indirect","Indexed Indirect"},
    },
    0b101010: { "name": "CLRX",
        "description": "Clear the specified index register.",
        "illegal_am": None,
    },
    0b110000: { "name": "J",
        "description": "Jump to the specified memory address.",
        "illegal_am": {"Immediate"},
    },
    0b110001: { "name": "JZ",
        "description": "Jump to the memory address if the accumulator contains zero.",
        "illegal_am": {"Immediate"},
    },
    0b110010: { "name": "JN",
        "description": "Jump to the memory address if the accumulator contains a negative number.",
        "illegal_am": {"Immediate"},
    },
    0b110011: { "name": "JP",
        "description": "Jump to the memory address if the accumulator contains a positive number.",
        "illegal_am": {"Immediate"},
    },
}
instructions.update( { v['name']: k for k, v in instructions.items() } )


