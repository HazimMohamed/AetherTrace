from turtle import back
from unicorn import *
from unicorn.x86_const import *
from lief import MachO

# Sample x86 machine code: mov eax, 0x1234; mov [0x1000], eax; ret;
elf_file = MachO.parse('fib').take(MachO.Header.CPU_TYPE.X86_64)
elf_text = elf_file.get_section('__text').content.tobytes()
with open('./fib_ass', 'w+') as f:
    f.write(elf_text.hex(sep=' '))

# Setup memory layout.
HEAP_ADDRESS = 0x1000
HEAP_SIZE = 10 * 0x1000 #4kb
STACK_MAX_SIZE = 0x1000 #4kb

# Stack grows down so STACK_END < STACK_START
STACK_END = 0x800000
STACK_START = (STACK_END + STACK_MAX_SIZE) & ~0xF

#End of the line is a memory space that's the "caller" of the program.
# If RIP points to anything from EoTL the program will exit.
END_OF_THE_LINE_ADDRESS = STACK_START + 0x5000

# Create emulator
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Map heap memory
mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)

# Write machine code to memory
mu.mem_write(HEAP_ADDRESS, elf_text)

# Setup stack
mu.mem_map(STACK_END, STACK_MAX_SIZE * 2)

# Setup EoTL
mu.mem_map(END_OF_THE_LINE_ADDRESS, 0x2000)

# Stack grows downward so start at the top
mu.mem_write(STACK_START - 8, END_OF_THE_LINE_ADDRESS.to_bytes(8, 'little'))
mu.reg_write(UC_X86_REG_RSP, STACK_START - 0x8)
# Write a recognizable value to caller RBP for debugging purposes
mu.reg_write(UC_X86_REG_RBP, 0xDEADFED)

# Hook memory accesses
def hook_mem_access(uc, access, address, size, value, user_data):
    access_type = "READ" if access == UC_MEM_READ else "WRITE"
    print(f"[{access_type}] addr={hex(address)} size={hex(size)} val={hex(value)}")

# For some god forsaken reason the memory is stored BEHIND the variable it references. In other words,
# EBP points to the byte AFTER the value it references. 
def read_64_as_str(uc: Uc, memory_addr):
    backwards_read = uc.mem_read(memory_addr, 8)
    backwards_hex = backwards_read.hex(' ')
    return ' '.join(backwards_hex.split(' '))
    

def print_stack(uc):
    print(f"STACK:")
    stack = {}
    for address in range(STACK_START, STACK_START - 0x20, -8):
        stack[address] = read_64_as_str(uc, address)

    for address, value in reversed(sorted(stack.items(), key=lambda a: a[0])):
        print(f"{hex(address)}: {value}")

def hook_code(uc, address, size, user_data):
    if address >= END_OF_THE_LINE_ADDRESS:
        uc.emu_stop()

    print()
    print(f"Executing instruction at {hex(address)}, size = {size}")
    rbp  = uc.reg_read(UC_X86_REG_RBP)
    rsp  = uc.reg_read(UC_X86_REG_RSP)
    print(f"RBP = {hex(rbp)}")
    print(f"RSP = {hex(rsp)}")
    print_stack(uc)


mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

# Run code
mu.emu_start(HEAP_ADDRESS, HEAP_ADDRESS + len(elf_text))
