import subprocess
import os
from config import parse_config, Config

from qiling import Qiling
from lief import MachO

from logger import AetherLog

FORCE_RECOMPILE = False
DEBUG_EXEC = False
COMPILER_FLAGS = [
    "-O0", "-fno-builtin", "-fno-inline",
    "-fno-unroll-loops", "-g"
]

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
        static_libraries = [f'./c/{f}' for f in config.static_libraries] if config.static_libraries else []
        subprocess.check_call(["gcc", *COMPILER_FLAGS, f"./c/{config.target}.c",
                              *static_libraries,
                              "-o", f"./exec/{config.target}"])

    print(f'Recompiled {config.target}')
#
# # Hook memory accesses
# def hook_mem_access(uc, access, address, size, value, logger):
#     access_type = "READ" if access == UC_MEM_READ else "WRITE"
#     if DEBUG_EXEC:
#         print(f"[{access_type}] addr={hex(address)} size={hex(size)} val={hex(value)}")
#
#     if access_type == UC_MEM_READ:
#         logger.log_memory_read(address)
#     elif access_type == UC_MEM_WRITE:
#         logger.log_memory_write(address, value)
#
#
# # For some god forsaken reason the memory is stored BEHIND the variable it references. In other words,
# # EBP points to the byte AFTER the value it references.
# def read_64_as_be_str(uc: Uc, memory_addr):
#     backwards_read = uc.mem_read(memory_addr, 8)
#     backwards_hex = backwards_read.hex(' ')
#     return ' '.join(reversed(backwards_hex.split(' ')))
#
#
# def print_stack(uc):
#     print(f"STACK (Stored big endian for readability):")
#     stack = {}
#     for address in range(STACK_START - 8, STACK_START - 0x20, -8):
#         stack[address + 0x8] = read_64_as_be_str(uc, address)
#
#     for address, value in reversed(sorted(stack.items(), key=lambda a: a[0])):
#         print(f"{hex(address)}: {value}")
#
# def hook_code(uc, address, size, logger):
#     if address >= END_OF_THE_LINE_ADDRESS:
#         uc.emu_stop()
#         return
#
#     if DEBUG_EXEC:
#         print()
#         print(f"Executing instruction at {hex(address)}, size = {size}")
#         rbp  = uc.reg_read(UC_X86_REG_RBP)
#         rsp  = uc.reg_read(UC_X86_REG_RSP)
#         print(f"RBP = {hex(rbp)}")
#         print(f"RSP = {hex(rsp)}")
#         print_stack(uc)
#
#     instruction_bytes = uc.mem_read(address, size)
#     logger.log_instruction(
#         address,
#         instruction_bytes
#     )

def trace(filename):
    target_exec_path = f'./exec/{filename}'
    if not os.path.exists(target_exec_path):
        raise FileNotFoundError('Cannot find the target for compilation or execution')

    emu = Qiling([target_exec_path], './runtime-fs/x8664_linux')
    emu.run()

    # with open(f'./at-build/{filename}.al', 'w') as f:
        # f.write(log.to_json(indent=4))

def main():
    config = parse_config()
    compile_if_necessary(config)

    trace(config.target)

if __name__ == "__main__":
    main()