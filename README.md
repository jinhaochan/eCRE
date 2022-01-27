# eCRE
Personal Notes on eCRE

## 1. Registers

### General Purpose Registers
---

Capacity: 32 bits / 4 bytes

| Register | Description                                                                             | Low 16 bits (XX) | Top 8 bits of XX | Bottom 8 bits of XX |
|----------|-----------------------------------------------------------------------------------------|------------------|------------------|---------------------|
| EAX      | Accumulator for operands and results data                                               | AX               | AH               | AL                  |
| EBX      | Pointer to DS segment                                                                   | BX               | BH               | BL                  |
| ECX      | Counter for strings and looping operations                                              | CX               | CH               | CL                  |
| EDX      | I/O pointer                                                                             | DX               | DH               | DL                  |
| ESI      | Pointer to data in segment pointed by DS register; Source pointer for string operations | SI               | -                | -                   |
| EDI      | Pointer to data in segment pointed by ES register; Dest pointer for string operations   | DI               | -                | -                   |
| ESP      | Stack pointer                                                                           | SP               | -                | -                   |
| EBP      | Base pointer                                                                            | BP               | -                | -                   |


![image](https://user-images.githubusercontent.com/7328587/151006738-2a43d608-13a0-46bc-bacf-aaede4e2a9fb.png)



### EFLAGS
---

Information about:

- Status Flags
- Control Flags
- System Flags

| Flag Type    | Description                                                                                                                                                                   | Flags              | Example                                                                                                                                                                                                                                      |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status Flag  | Operational Flags                                                                                                                                                             | OF, SF, ZF, AF, PF | `repe cmpsb` compares two strings, and if they are equal, ZF = 1                                                                                                                                                                             |
| Control Flag | Related to String Processing  ESI and EDI relies on these flags, and needs to point to the string before any operation ECX needs to contain the number of bytes to operate on | DF                 | `cld` clears directional flag DF = 0. Strings auto-increment from low (start of string) to high (end of string) address `std` set directional flag DF = 1. Strings auto-decrement from high (end of string) to low (start of string) address |
| System Flag  | Involved with operating system operations                                                                                                                                     | Trap flag          |     -                                                                                                                                                                                                                                        |

### Segment Registers
---

Segment Registers are 16 bit registers that contain pointers call Segment Selectors that identify different types of segments in memory

To access a particular segment in memory, the appropriate Segment Register must contain the correct Segment Selector

| Segment Register | Description             |
|------------------|-------------------------|
| CS               | Points to Code Segment  |
| SS               | Points to Stack Segment |
| DS               | Points to Data Segment  |
| ES               | Points to Data Segment  |
| FS               | Points to Data Segment  |
| GS               | Points to Data Segment  |

![image](https://user-images.githubusercontent.com/7328587/151010788-62ef17be-296c-40d2-a7bb-714332e25697.png)

Each Segment Register points to a specific type of storage: code, data or stack.



### Instruction Pointer Register
---

EIP, also called the PC, points to the next instruction to be executed.

Everytime an instruction is executed, EIP points to the next one.

EIP cannot be access directly.



### Debug Registers
---

-Hardware BreakPoints = HWBP
-Software BreakPoints = SWBP

There are 8 debug registers `DR0 - DR7` used to control debug operations of the processor

For debugging, we are concerns only with the first four `DR1`, `DR2`, `DR3`, `DR4` that stores the HWBP

Specific conditions (e.g. memory access, execution) on these address will pause the program, and allow us to debug

Debug registers are privileged resources, and we cannot access them from Ring 3 (Userland). We need to access Ring 3 API to transfer execution to the kernel to set these debug registers.

Each HWBP is specific to its own thread within the process. If a HWBP has been set on a thread for memory access, and the CPU spawns a new thread for memory access, the new thread will not trigger the HWBP, because it has its own context.

If a debugger can debug multi-threaded applications, it can update every thread context with the HWBP.

SWBP works by substituting the original byte with a `0xCC` byte, or `INT3h`. Since this modifies the code in memory, it always triggers regardless of multi-threaded or not.



### Machine Specific Registers
---

Also called Model Specific Registers, they handle system related functions.

They are NOT accessible to applications, EXCEPT for Time-Stamp Counter.

Time-Stamp Counter is a 64-bit register whose contents can be read with `RDTSC` instruction, or Read Time-Stamp Counter

When `RDTSC` is called:
- Low-Order 32 bits -> EAX
- High Order 32 bits -> EDX

Time-Stamp Counter is increased by the processor at every clock cycle, and resets to zero when processor is reset



## 2. Program Operations

### Calling Functions
---

When the program calls a function, the IP jumps to the function's address. However, it needs to know where to return to after the function has completed.

Assembling required parameters and the return value is done using the Stack. This resides in the Stack Segment (SS)

A function is triggered using the `CALL` instruction:
- Processor `PUSH` return address on the stack
- Load address of function into EIP

A function exits when `RET` is called:
- Processor `POP` the return address into the EIP
- Return execution to the next instruction of `CALL`
- Parameters can be added to `RET` to clean up the stack from the parameters required by the function. (`__stdcall` and `__fastcall`)


### The Stack
---

The manipulation of the Stack is done with `PUSH` and `POP` to modify the Top Of the Stack (TOS). Whenever a `PUSH` or `POP` is called, the ESP decrements to point to the new time on the TOS.

The Stack grows downwards from Higher Address to Lower Address. When you put `PUSH` data on the stack, the ESP is decremented. When you `POP` data off the stack, the ESP is incremented.

The Stack's width is 32 bits (4 bytes), which means every "unit" of the stack is 4 bytes large.

![image](https://user-images.githubusercontent.com/7328587/151102785-e513692c-5d63-4b0f-9b43-b27fc90d3764.png)

The Stack is divided into several Stack Frames, and each Stack Frame is assigned to a context of a single function.

When we enter a function, a Stack Frame is initialized via the Function Prologue.

When we exit a function, we need to free up the Stack Frame, and restore ESP and EBP registers via the Function Epilogue, which `POP` these data back into the registers.

![image](https://user-images.githubusercontent.com/7328587/151104038-a9e270b4-babe-449e-92d7-cd9eb7718308.png)


### Calling Conventions
---

Calling Conventions refers to the way parameters required by the function are `PUSH` onto the stack

`__stdcall`, `__fastcall` and `__cdecl` and types of Calling Conventions.

`__stdcall` and `__cdecl`:
- Parameters are `PUSH` onto the Stack in reverse order
- `__stdcall` cleans up the Stack by calling `POP` INSIDE the function
- `__cdecl` cleans up the Stack by calling `POP` OUTSIDE the function (the Caller does the cleanup)
- Binaries using `__stdcall` is therefore smaller than `__cdecl` because of lesser Stack cleanup code

`__fastcall`:
- Parameters are `PUSH` both onto the Stack as well as registers (Makes use of less Stack)
- Clean up is done by calling `POP` INSIDE the function

Windows API (Win32 API) uses `__stdcall` Calling Convention

Examples:

`__stdcall` and `__fastcall` Function Prologue:

![image](https://user-images.githubusercontent.com/7328587/151105051-96b8b6f8-d133-4d20-b649-6f12171e2155.png)


`__stdcall` and `__fastcall` Function Epilogue:

![image](https://user-images.githubusercontent.com/7328587/151105078-ab6a1605-04ec-45c2-b105-561320a1a796.png)

`__cdecl` Function Prologue:
 
![image](https://user-images.githubusercontent.com/7328587/151105138-1947db81-9a31-4c01-ae74-85c483436162.png)

 `__cdecl` Function Epilogue:
  
![image](https://user-images.githubusercontent.com/7328587/151105112-b7825dbd-0f4e-4dbe-8f45-d62888a44523.png)

 
 
### Reading the EIP
---

Since we can't read EIP directly, we can create a function to return EIP to EAX

Move the Return Address to EAX, which is the address of the next instruction, and call `ret`

![image](https://user-images.githubusercontent.com/7328587/151105450-dd0909b6-7b17-43ba-956d-de1e80a4daac.png)

Or

Call next instruction and `POP` the Return Address to EAX

![image](https://user-images.githubusercontent.com/7328587/151105465-1324b9ee-b171-40ee-be3a-345bba59aba5.png)



### Processes and Threads
---

Each thread within a process has its own stack

Threads share the same virtual address space within a process

## 3. Heap and Exceptions


### The Heap

The Heap is the memory area that is dynamically allocated during runtime, and used to store data that does not have a fix size, or can't fit onto the Stack

### Handles

Handles are references to various resources, and is used by the operating system to control resource access (read, write, etc)

### Exceptions

Exceptions occurs during the execution of an application, and are associated with specific Exception Handlers. which are blocks of code to handle the specific exception

There are two types os Exceptions:
- Hardware
    -  Caused by execution of bad sequence of instructions, such as division by zero, or accessing invalid memory
    -  HW Exceptions are initiated by the CPU
- Software
    - Software exceptions are generated by the application or the OS

Structured Exception Handling: Windows Exception to handle both Hardware and Software exceptions

### Windows Ring3 Internal Structures

THREAD_ENVRIONMENT_BLOCK (TEB)
- Address of top and bottom of currnet thread's stack
- Thread identifier
- Identifier of the process of the thread
- Code of last error that occured during thread execution
- Address of Thread Local Storage (TLS)
- Address of PEB

PROCESS_ENVRIONMENT_BLOCK (PEB)
- Image base of the process
- Address of the loader data strcuture PEB_LDR_DATA
- NtGlobalFlag (Used for anti-debug)
- Major/minor versions of Windows
- Number of processors available
- BeingDebugged flag (Used for anti-debug)

CONTEXT
- Keeps track of all necessary CPU states (e.g. value of registers necessary to continue execution of a thread)


### Windows APIs

Windows APIs are Ring3 operating system functions to communicate with the underlying OS

Categories:
- Administration and Mangement
- Diagnostics
- Graphics and Multimedia
- Networking
- System Services
- Windows User Interface


### Reversing Tools

- Hex Editor
    - Reads file as hex
- Decompiler
    - Translates low level code to high level code
    - Operates best on java or .NET as they are converted to Intermediary Languages (IL)
- Disassembler
    - Translates binary to ASM
    - Usually in a debugger
- Debugger Tool
    - Hex Editing
    - Disassembler
    - Control execution flow
- System Monitoring Tools
    - Access to files/registry keys
- Windows API Monitoring Tools
    - Access to Windows API calls

Debuggers are either Ring 0 (Kernel mode) or Ring 3 (User mode).
- Ring 0 (Kernel mode) debuggers are more powerful, and can evade anti-debugging techniques
- Ring 3 (User mode) debuggers can be detected by anti-debugging techniques
- Ring 3 (User mode) debuggers can only access memory address that are part of the process we are debugging
