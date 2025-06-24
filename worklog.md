06/02/25

So I'm still working on being able to hook into memory. I'm trying to start up the Unicorn engine and I've managed to
extract what I believe to be the assembly code into the emulator, but I'm getting a write error.

Here's what the bytes are for the machine error:

55 48 89 e5 c7 45 fc 00 00 00 00 b8 04 00 00 00 5d c3

Here are what it apparently disassembles to:

0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
b:  b8 04 00 00 00          mov    eax,0x4
10: 5d                      pop    rbp
11: c3                      ret

I need to decipher this to understand what's probably causing my issue.

According to ChatGPT lines 0 and 1 appear to be some kind of function preamble. We move 4 to the stack frame. Then
return 4. Cool. Where is the memory issue happening? Maybe I can create a CPU hook so I can see which instructions are
being executed and which ones crash the system.

So it turns out I had wrote the following code:

mu.mem_map(STACK, 4 * 0x1000)
mu.reg_write(UC_X86_REG_ESP, STACK)

but I forgot to make it so RSP, the stack pointer pointed to the HIGHEST memory address, so the stack had room to grow
down. I fixed it by changing:

mu.reg_write(UC_X86_REG_ESP, STACK) => mu.reg_write(UC_X86_REG_ESP, STACK + 0x1000)

Now the only issue is that I don't have anywhere to return to...

Now I'm getting a new issue on the 6a line of the following assembly code:

0:  55                      push   rbp
1:  48 89 e5                mov    rbp,rsp
4:  89 7d f8                mov    DWORD PTR [rbp-0x8],edi
7:  83 7d f8 01             cmp    DWORD PTR [rbp-0x8],0x1
b:  0f 8f 0b 00 00 00       jg     0x1c
11: 8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
14: 89 45 fc                mov    DWORD PTR [rbp-0x4],eax
17: e9 4a 00 00 00          jmp    0x66
1c: c7 45 f4 00 00 00 00    mov    DWORD PTR [rbp-0xc],0x0
23: c7 45 f0 01 00 00 00    mov    DWORD PTR [rbp-0x10],0x1
2a: c7 45 e8 02 00 00 00    mov    DWORD PTR [rbp-0x18],0x2
31: 8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
34: 3b 45 f8                cmp    eax,DWORD PTR [rbp-0x8]
37: 0f 8f 23 00 00 00       jg     0x60
3d: 8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
40: 03 45 f0                add    eax,DWORD PTR [rbp-0x10]
43: 89 45 ec                mov    DWORD PTR [rbp-0x14],eax
46: 8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
49: 89 45 f4                mov    DWORD PTR [rbp-0xc],eax
4c: 8b 45 ec                mov    eax,DWORD PTR [rbp-0x14]
4f: 89 45 f0                mov    DWORD PTR [rbp-0x10],eax
52: 8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
55: 83 c0 01                add    eax,0x1
58: 89 45 e8                mov    DWORD PTR [rbp-0x18],eax
5b: e9 d1 ff ff ff          jmp    0x31
60: 8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
63: 89 45 fc                mov    DWORD PTR [rbp-0x4],eax
66: 8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
69: 5d                      pop    rbp
6a: c3                      ret
6b: 0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
70: 55                      push   rbp
71: 48 89 e5                mov    rbp,rsp
74: 48 83 ec 10             sub    rsp,0x10
78: bf 0a 00 00 00          mov    edi,0xa
7d: e8 7e ff ff ff          call   0x0
82: 89 45 fc                mov    DWORD PTR [rbp-0x4],eax
85: 31 ff                   xor    edi,edi
87: b0 00                   mov    al,0x0
89: e8 08 00 00 00          call   0x96
8e: 31 c0                   xor    eax,eax
90: 48 83 c4 10             add    rsp,0x10
94: 5d                      pop    rbp
95: c3                      ret

So at 0x69 we're setting our RIP (instruction pointer) to  the value at the base of RBP, which at this point
seems try to return to the caller, which, in this emulated environment is garbage memory address. I wonder
how emulated programs usually handle this type of problem (thinking emoji).

06/23/25

Before I try and fix what may or may not be the actual problem, let me validate my theory by checking what address,
the program is trying to return to. So I know that the `ret` command pops the value of.

So I just spent a few hours trying to debug my memory layout alongside the assembly and I'm really hitting a wall. 
It seems like no matter what I do I keep ending up with a memory error around the return. I almost certain I'm
just running into orientation (reading up/down) errors. I just got to keep in mind while moving forward:

1. The writes and reads are always forward looking. If I read (64 bit) at `0x100000` then I'm reading [`0x100000` - `0x100008`]
2. The stack grows motherfucking downward. So a low stack value is the "top" of the stack. You can see how this could get confusing.
3. When a `pop` is run it reads 8 bytes starting at `RSP` then increments `RSP` by 8. This is the logical deduction of (1) and (2). If it read first then it would be reading the value (logically) below it on the stack.
4. When a `push` decrements by 8 first then writes.
5. `ret` is equivalent to `pop RIP`. In other words it:
    a. Reads `[RSP, RSP+8]`
    b. Decrements `RSP` by 8
    c. Sets the next instruction (`RIP`) to that value
6. Everything is in little endian which is where the highest memory value is the most significant. THIS IS OPPOSITE OF HOW DECIMAL IS USUALLY NOTATED (assuming high memory addresses are to the right)!!!

I'm going to memorize this shit as best I can and trace through it tomorrow. For now I need to go home and walk off this headache.


06/24/25

Okay today we're doing the thing!

So in order to have `pop RIP` pop the address of EOTL then we need to have RSP equal to the address where EOTL is stored - 8 bytes based on the above rules. The instruction prior to the `ret` instruction which is giving me so many damn problems is `pop rbp` to restore the value of RBP back to where it was when the execution started. I really don't care what RBP is when we move the instruction pointer to the EOTL address so that doesn't really matter, but what does matter is I suspect that it's actually popping my EOTL address into the RBP pointer. To fix this I'm going to try to write my EOTL address above the stack (equivalent to calling `push rip` prior to function execution). To accomodate this I also need to make sure that RSP points the `STACK_BEGIN - 8` to stack off with so I don't end up overwriting my EOTL address. RBP shouldn't matter at the beginning (since the instructions at EOTL don't really use the stack), so I'll set it to a distinctive value for debugging purposes.

Also I noticed an issue in how I'm logging reads. They're spaced in block with the subsequent instruction instead of the correct (previous) instruction that executes the read.

Praise the lord! It works now! The only issue is I suspect my logging system is broken, or there's some sort of canceling offsets. I commited to git to make sure I don't lose my precious and now I'm working to make sure that there's no series of self-canceling bugs. I also fixed the logging error with the memory!

Okay so I learned I was operating under false assumptions of what `RSP` actually points to. According to [this](https://cs.brown.edu/courses/csci0300/2021/notes/l08.html) `RSP` points to the last byte that is part of the current functions stack frame. I changed the above rules to reflect that fact.

So for my logging convention I'm going to have:

```
[highest memory address associated with that 8 byte chunk]: [8 bytes written in big endian because I find it easier to read]
```

Okay. Now I'm tasked with outputting all this data in a format where I can start to play with possible visualizations. Of course I could just store it in a datastructure but I want a little more persistence and readabiity than that so writing to HDD seems appropriate. I want the format to be vaguely human readable, but also still easy to parse by a machine. It's essentially going to be a series of time frames, which increment per instruction. 

I'm thinking of using JSON, but how big can I realistically make a JSON? ChatGPT claimed around 100MB = 1 million lines. Assuming maybe an average of 10 lines worth of information stored per instruction frame we're going to be limited to around 100,000 instructions. I'm not married to this format, but for development purposes I think the libraries available for and readability of JSON will be ideal. I can always come back and create a different output format later.

So here's the idea to begin with:

```
{
    "frames": [
        {
            "INSTRUCTION_ADDRESS": ...,
            "MNEUMONIC": ...,
            "OPERANDS": ...,
            "MEMORY": {
                "READ": ...,
                "WRITE": ...
            }
        },
        ...
    ]
}
```

I can include register information as well, but let's see what we can make with just the instruction and memory information for now. We'll call this `AetherLog` format and give it a `.al` extension.

Cool let's code this up and generate a `fib.al` file.

