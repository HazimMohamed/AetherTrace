import subprocess
import os
from config import parse_config, Config

from unicorn import *
from unicorn.x86_const import *
from lief import MachO

from logger import AetherLog

DEBUG_EXEC = False
COMPILER_FLAGS = [
    "-O0", "-fno-builtin", "-fno-inline",
    "-fno-unroll-loops", "-g"
]

FORCE_RECOMPILE = True

# Setup memory layout.
HEAP_ADDRESS = 0x1000
HEAP_SIZE = 10 * 0x1000 #4kb
STACK_MAX_SIZE = 0x1000 #4kb

# Stack grows down so STACK_END < STACK_START
STACK_END = 0x800000
STACK_START = (STACK_END + STACK_MAX_SIZE) & ~0xF

#End of the line is a memory space that's the "caller" of the program.
# If RIP points to anything from EoTL the program will exit.
END_OF_THE_LINE_ADDRESS = STACK_START + (2 * STACK_MAX_SIZE)

def compile_if_necessary(config: Config):
    compile_file = True
    # We allow users to run executables directly so if there's no C file, we just skip the compilation step and
    # hope the executable already exists
    if not os.path.exists(f'./c/{config.target}.c'):
        compile_file = False

    # Don't recompile something
    if os.path.exists(f'./exec/{config.target}') and not FORCE_RECOMPILE:
        compile_file = False

    if compile_file:
        subprocess.check_call(["gcc", *COMPILER_FLAGS, f"./c/{config.target}.c",
                              *[f'./c/{f}' for f in config.static_libraries],
                              "-o", f"./exec/{config.target}"])

    print(f'Recompiled {config.target}')

# Hook memory accesses
def hook_mem_access(uc, access, address, size, value, logger):
    access_type = "READ" if access == UC_MEM_READ else "WRITE"
    if DEBUG_EXEC:
        print(f"[{access_type}] addr={hex(address)} size={hex(size)} val={hex(value)}")

    if access_type == UC_MEM_READ:
        logger.log_memory_read(address)
    elif access_type == UC_MEM_WRITE:
        logger.log_memory_write(address, value)


# For some god forsaken reason the memory is stored BEHIND the variable it references. In other words,
# EBP points to the byte AFTER the value it references. 
def read_64_as_be_str(uc: Uc, memory_addr):
    backwards_read = uc.mem_read(memory_addr, 8)
    backwards_hex = backwards_read.hex(' ')
    return ' '.join(reversed(backwards_hex.split(' ')))
    

def print_stack(uc):
    print(f"STACK (Stored big endian for readability):")
    stack = {}
    for address in range(STACK_START - 8, STACK_START - 0x20, -8):
        stack[address + 0x8] = read_64_as_be_str(uc, address)

    for address, value in reversed(sorted(stack.items(), key=lambda a: a[0])):
        print(f"{hex(address)}: {value}")

def hook_code(uc, address, size, logger):
    if address >= END_OF_THE_LINE_ADDRESS:
        uc.emu_stop()
        return

    if DEBUG_EXEC:
        print()
        print(f"Executing instruction at {hex(address)}, size = {size}")
        rbp  = uc.reg_read(UC_X86_REG_RBP)
        rsp  = uc.reg_read(UC_X86_REG_RSP)
        print(f"RBP = {hex(rbp)}")
        print(f"RSP = {hex(rsp)}")
        print_stack(uc)

    instruction_bytes = uc.mem_read(address, size)
    logger.log_instruction(
        address,
        instruction_bytes
    )


def init_vm():
    # Create emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map heap memory
    mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)

    # Setup stack
    mu.mem_map(STACK_END, STACK_MAX_SIZE * 2)

    # Setup EoTL
    mu.mem_map(END_OF_THE_LINE_ADDRESS, 0x1000)

    # Stack grows downward so start at the top. "push" a value onto the stack representing the return instruction to EoTL
    mu.mem_write(STACK_START - 0x8, END_OF_THE_LINE_ADDRESS.to_bytes(8, 'little'))
    mu.reg_write(UC_X86_REG_RSP, STACK_START - 0x8)
    # Write a recognizable value to caller RBP for debugging purposes
    mu.reg_write(UC_X86_REG_RBP, 0xDEADFED)

    return mu

def trace(filename):
    mu = init_vm()

    target_exec_path = f'./exec/{filename}'
    if not os.path.exists(target_exec_path):
        raise FileNotFoundError('Cannot find the target for compilation or execution')

    # Sample x86 machine code: mov eax, 0x1234; mov [0x1000], eax; ret;
    elf_file = MachO.parse(target_exec_path).take(MachO.Header.CPU_TYPE.X86_64)
    elf_text = elf_file.get_section('__text').content.tobytes()

    # Write out the assembly code for debugging purposes.
    with open(f'./at-build/{filename}.ass', 'w+') as f:
        f.write(elf_text.hex(sep=' '))

    log = AetherLog()

    # Write machine code to memory
    mu.mem_write(HEAP_ADDRESS, elf_text)

    # These hooks need to be registered in this order. TECHNICALLY unicorn doesn't guarentee hook order, but in practice it calls them in the order
    # they're registered. If they change this then I'll need to find a work around.
    mu.hook_add(UC_HOOK_CODE, hook_code, log)
    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access, log)

    # Run code
    print(HEAP_ADDRESS, elf_file.entrypoint)
    mu.emu_start(HEAP_ADDRESS + elf_file.entrypoint, HEAP_ADDRESS + len(elf_text))

    with open(f'./at-build/{filename}.al', 'w') as f:
        f.write(log.to_json(indent=4))

def main():
    config = parse_config()
    compile_if_necessary(config)

    trace(config.target)

if __name__ == "__main__":
    main()