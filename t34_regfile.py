reginfo = {
    "MAR": {
        "size": 12, "name": "Memory Address Register", 
        "description": "Address of the memory location which is to be loaded from or stored into.",
    },
    "IC": { 
        "size": 12, "name": "Instruction Counter",
        "description": "Address of the next instruction to be fetched, decoded, and executed.",
    },
    **{ "X{}".format(i): {
        "size": 12, "name": "Index Registers",
        "description": "Contain values to be used in calculating memory addresses",
    } for i in range(4) },
    "ABUS": {
        "size": 12, "name": "Address Bus",
        "description": "Used when addresses are to be moved.",
    },
    "MDR": {
        "size": 24, "name": "Memory Data Register", 
        "description": "Data to be written into, or data most recently read from, memory."
    },
    "AC": {
        "size": 24, "name": "Accumulator",
        "description": "The accumulator register.",
    },
    "ALU": {
        "size": 24, "name": "Arithmetic-Logic Unit",
        "description": "Peforms computations",
    },
    "IR": {
        "size": 24, "name": "Instruction Register",
        "description": "Instruction to be decoded and executed.",
    },
    "DBUS": {
        "size": 24, "name": "Data Bus",
        "description": "Used when data and instructions are to be moved."
    },
}
