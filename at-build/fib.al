{
    "frames": [
        {
            "INSTRUCTION_ORDINAL": 0,
            "INSTRUCTION_ADDRESS": 4096,
            "MNEUMONIC": "push",
            "OPERANDS": "rbp"
        },
        {
            "INSTRUCTION_ORDINAL": 1,
            "INSTRUCTION_ADDRESS": 4097,
            "MNEUMONIC": "mov",
            "OPERANDS": "rbp, rsp"
        },
        {
            "INSTRUCTION_ORDINAL": 2,
            "INSTRUCTION_ADDRESS": 4100,
            "MNEUMONIC": "mov",
            "OPERANDS": "dword ptr [rbp - 8], edi"
        },
        {
            "INSTRUCTION_ORDINAL": 3,
            "INSTRUCTION_ADDRESS": 4103,
            "MNEUMONIC": "cmp",
            "OPERANDS": "dword ptr [rbp - 8], 1"
        },
        {
            "INSTRUCTION_ORDINAL": 4,
            "INSTRUCTION_ADDRESS": 4107,
            "MNEUMONIC": "jg",
            "OPERANDS": "0x101c"
        },
        {
            "INSTRUCTION_ORDINAL": 5,
            "INSTRUCTION_ADDRESS": 4113,
            "MNEUMONIC": "mov",
            "OPERANDS": "eax, dword ptr [rbp - 8]"
        },
        {
            "INSTRUCTION_ORDINAL": 6,
            "INSTRUCTION_ADDRESS": 4116,
            "MNEUMONIC": "mov",
            "OPERANDS": "dword ptr [rbp - 4], eax"
        },
        {
            "INSTRUCTION_ORDINAL": 7,
            "INSTRUCTION_ADDRESS": 4119,
            "MNEUMONIC": "jmp",
            "OPERANDS": "0x1066"
        },
        {
            "INSTRUCTION_ORDINAL": 8,
            "INSTRUCTION_ADDRESS": 4198,
            "MNEUMONIC": "mov",
            "OPERANDS": "eax, dword ptr [rbp - 4]"
        },
        {
            "INSTRUCTION_ORDINAL": 9,
            "INSTRUCTION_ADDRESS": 4201,
            "MNEUMONIC": "pop",
            "OPERANDS": "rbp"
        },
        {
            "INSTRUCTION_ORDINAL": 10,
            "INSTRUCTION_ADDRESS": 4202,
            "MNEUMONIC": "ret",
            "OPERANDS": ""
        }
    ]
}