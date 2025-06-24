from capstone import *
import json
from typing import List

class AetherLog:

    class AetherLogFrame:
        def __init__(self, instruction_address: int, mneumonic: str, operands: List[str]) -> None:
            self.instruction_address = instruction_address
            self.mneumonic = mneumonic
            self.operands = operands
            self.read_mem = None
            self.write_mem = None

        def add_read(self, addr):
            self.read_mem = addr

        def add_write(self, addr, val):
            self.write_mem = {
                address: addr,
                value: val
            }
            
        def to_dict(self):
            out = {
                'INSTRUCTION_ADDRESS': self.instruction_address,
                'MNEUMONIC': self.mneumonic,
                'OPERANDS': self.operands,
            }
            if (self.read_mem or self.write_mem) and not 'MEMORY' in out:
                out['MEMORY'] = {}
            if self.read_mem:
                out['MEMORY']['READ'] = self.read_mem
            if self.write_mem:
                out['MEMORY']['WRITE'] = self.write_mem
            return out
    
    def __init__(self) -> None:
        self.frames: List[AetherLogFrame] = []
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Creates a new frame and logs the instruction for the frame
    def log_instruction(self, addr, instruction_bytes):
        print(instruction_bytes)
        dis_ass_instruction = list(self.cs.disasm(instruction_bytes, addr))
        assert(len(dis_ass_instruction) == 1)
        dis_ass_instruction = dis_ass_instruction.pop()
        self.frames.append(self.AetherLogFrame(
            instruction_address=addr,
            mneumonic=dis_ass_instruction.mnemonic,
            # operands=dis_ass_instruction.operands
            operands=[]
        ))

    def log_memory_read(self, addr):
        self.frames[-1].add_read(addr)

    def log_memory_write(self, addr, val):
        self.frames[-1].add_write(addr, val)

    def to_json(self, **kwargs) -> str:
        return json.dumps({
            "frames": [p.to_dict() for p in self.frames],
        }, **kwargs)
