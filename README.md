# eCRE
Personal Notes on eCRE


## Tips

- Within a function, if accessing `EBP - x`, it is a local variable within the function. If accessing `EBP + x`, its either a parameter or a global variable.
- To remove items from the stack, you can change the `RET` value. e.g. `RET 4` remove 1 item from the stack
- Find Expression `TerminateProcess`, and set SWBP there. You can then see what were the function calls before terminate process was called.
- `cmp eax ebx` does a subtraction of `eax` and `ebx`, while `test eax ebx` does a logical AND between `eax` and `ebx`
- Set a breakpoint on `GetProcAddress` to see what is getting the address of processes. Could be used for IAT protection using relative addressing.
- Set a breakpoint on `CreateThread` or `CreateRemoteThread` and look at the previous stack frame to see what is spawning threads.
- You can create your own exit prologue by modifying the end of the function to be

```
push ebp (Push EBP of the caller on the stack)
mov ebp, esp (Set the EBP of the function to be the current ESP)
sub esp, 12 (Allocate memory for the function)

...

mov esp ebp (Restore ESP)
pop ebp (Restore callers EBP)
ret (Return to address in EIP)

...

add esp 8 (Rebalancing the stack)

```

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

Segment Registers are 16 bit registers that contain pointers called Segment Selectors that identify different types of segments in memory

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

- Hardware BreakPoints = HWBP
- Software BreakPoints = SWBP

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

## 4. Offsets and PE File Format

### VA/RVA/Offset

Applications do not access physical memory directly, but through virtual addresses

Virtual addresses are deceptively contiguous, but the mapped physical addresses are not

Relative virtual addresses (RVA) is the difference between two VAs, and refers to the higher one.

![image](https://user-images.githubusercontent.com/7328587/151284479-fc986c92-1c51-4963-905d-3b19733a180b.png)

Offsets refer to the physical memory, file on disk, or raw data

Offset is the difference between the locations of 2 bytes

### PE File format

Every PE file starts with a small MS-DOS executable

First bytes of the PE file is called `IMAGE_DOS_HEADER` which contains
- `e_magic`
    - 16-bit word which must be 0x5A4D ("MZ")
    - Called the `IMAGE_DOS_SIGNATURE`
- `e_lfanew`
    - At offset 0x3C
    - Contains file offset of start of the PE header
    - Called the `IMAGE_NT_HEADERS`

PE Header is formed by combining various structures together (Signature 0x50450000 "PE\0\0" in ASCII)

![image](https://user-images.githubusercontent.com/7328587/151286035-dccffaa4-546a-4792-b055-bdd3bcc24f06.png)

`IMAGE_FILE_HEADER` within `IMAGE_NT_HEADERS`

![image](https://user-images.githubusercontent.com/7328587/151286269-24f88dd7-1013-4a18-9bd7-b003238f048e.png)

`IMAGE_FILE_HEADER` Contains information about the executable
- Target CPU architecture
- Number of Sections
- `SizeOfOptionalHeader` structure, which must be set to 0xE0. This is required, not optional
- Characteristics about the executable

`IMAGE_OPTIONAL_HEADER` contains:
- Magic member defining if its 32 bit or 64 bit
- `AddressOfEntryPoint` holds the RVA of the `EntryPoint` of the module where the first instruction is executed
- `BaseOfCode` and `BaseOfData` holds the RVA to start of Code and Data sections
- `ImageBase` contains ImageBase module, which is the preferred VA of the PE file to be loaded in memory
    - Defaults to 0x00400000 for applications and 0x10000000 for DLLs
- `SectionAlignment` and `FileAlignment` indicate the alignment of the sections
- `SizeOfImage` indicates the memory size occupied by the PE at runtime
    - Has to be multiples of `SectionAlignment` value
- `DataDirectory` points to the first member of `IMAGE_DATA_DIRECTORY`


Each `IMAGE_DATA_DIRECTORY` contains:
- RVA and size of specific data inside the PE image on runtime
- Is 16 bytes large
- `ExportTableAddress`
- `ImportTableAddress`
- `ResourceTable`
- `ImportAddressTable` (IAT)

![image](https://user-images.githubusercontent.com/7328587/151287198-5119a39a-ba38-47b5-a6df-31aeb05a5e0a.png)


The section table is an array of `IMAGE_SECTON_HEADER` structures which holds information about associated sections
- location
- size
- charactistics
- access permissions

- DD = DWORD (32 bits, 4 bytes)
- DW = WORD (16 bits, 2 bytes)
- VirtualSize
    -  Size of section in memory without padding
-  VirtualAddress
    -  RVA of the section in memory
    - VirtualSize + VirtualAddress + Padding = Address of next Section
- SizeOfRawData
    - Actual size of section within the file
- PointerToRawData
    - Offset where the Raw Data section within the file
- Chracteristics
    - Access permissions for the section

Common Sections names:
- `.text`
- data: initialized data of the application such as strings
- .rdata/idata: Used for sections where the import table is located. Also lists the Windows API/DLLs used by the applications
- .rsrc: resource container section (images etc)

### Memory and File Alignment

Default alignment of sections in a file is 0x200 (SectionAlignment in `IMAGE_OPTIONAL_HEADER`)

Default alignment of memory is 0x1000 (FileAlignment in `IMAGE_OPTIONAL_HEADER`)

0x0 is padded to fulfil the alignment

## 5. String References and Basic Patching

### VA Offset Manual Calculation

If we want to manually find the offset for address 0x00402E77

Given the following IMAGE_SECTION_HEADER:

![image](https://user-images.githubusercontent.com/7328587/151741691-21cdc20a-ba20-4120-aa9c-efd1a6b52d9f.png)


0x00400000 is the default Base Image address of Windows executables

`Byte_Offset = Byte_VA - (Image_Base + Section_RVA) + PointerToRawData`

Where in the `.text` section:
- Byte_VA = 0x00402E77
- Image_Base = 0x400000
- Section_RVA (Section VirtualAddress) = 0x1000
- PointerToRawData = 0x600

## 5. String References and Basic Patching

Naked functions are functions that do not generate a function prologue or epilogue

### String References

You can search for strings in debuggers, and find their references in the programs

### Basic Memory Patching

`0x00402E76  75  1F  JNZ  00402E97`

0x00402E76 = VA of 75

75 = Opcode for JNZ

1F = number of bytes to skip (0x00402E76 + 2 (for JNZ and 1F) + 1F = 0x00402E97)

We can patch this instruction via:
1. NOP (Opcode 0x90)
2. Changing JNZ to JE (Opcode 0x74)
3. Changing jump value to zero (75 00)


## 6. Exploring the Stack

While the program is executing, you can pause the program and explore the variables that were placed on the stack

We find the piece of code that shows the error dialog box, and we "Follow in Disassembler" to find the function that executes this

![image](https://user-images.githubusercontent.com/7328587/152627955-8393058c-ce55-49b3-9977-e49ec598140a.png)

We find the function that calls it, and set a breakpoint at the start of it. When we execute it again and step through it, we see the password being printed

![image](https://user-images.githubusercontent.com/7328587/152628001-c8234039-3b60-4bd0-89d1-c1eccd8b4c0a.png)

## 7. Algo Reversing

## 8. Windows Registry Manipulation

### Getting Registry Values

`RegOpenKeyEx` = access key in Windows Registry

![image](https://user-images.githubusercontent.com/7328587/152670497-670d1a4a-cbc7-4d13-b0e6-ee03dc303feb.png)


`RegQueryValueEx` = obtain value associated with the key

![image](https://user-images.githubusercontent.com/7328587/152670500-555c86b6-2730-416c-943c-60eb14765751.png)


On success, the API returns the handle to the key. If failed, the API returns 0

Other Registry Commands:
- `RegDeleteKey`
- `RegDeleteValue`
- `RegGetValue`
- `RegOpenKey`
- `RegQueryValue`
- `RegSetValue`
- `RegSetValueEx`


### Hardware Breakpoints

We can use HWBP to monitor when specific data is being accessed.

We can set a HWBP on a memory address of interest, so that when the program eventually calls it, it will break


## 9. File Manipulation

Reading files can be done via the `CreateFile`  API with the correct parameters passed to it

On success, it will return the handle ot the file. If it fails to open the file, it will return -1 or 0xFFFFFFFFh

![image](https://user-images.githubusercontent.com/7328587/152733459-2553e9f2-771b-4535-9056-13d34b9bb6ae.png)

Getting file paths can be done via the `GetSystemDirectory` API

Getting the size of a file can be done via `GetFileSize` API, which returns the number of bytes in a file.

Other File Manipulation Commands:
- `WriteFile`
- `DeleteFile`
- `MoveFile`
- `FindfirstFile`
- `FindNextFile`
- `CopyFile`
- `GetFileType`

## 10. Anti-Debugging Tricks

Ring 3 anti-debugging (userland)


### PEB (Process Envrionemnt Block) - Direct Debugger Detection

Gets information from TEB/PEB

`BeingDebugged` == 1 (Change EAX to 0 to bypass)

![image](https://user-images.githubusercontent.com/7328587/152919927-192104f2-9a97-483d-a35c-2dcfd754b2b5.png)

`NtGlobalFlag` == 70h

![image](https://user-images.githubusercontent.com/7328587/152919955-f2b46432-0b63-46d9-bdca-dd8f4ebe0638.png)

This information is stored in `FS[30]` at various offsets, where the address of FS is here:

![image](https://user-images.githubusercontent.com/7328587/153549148-005a993f-25b5-480e-9ed1-c80119899909.png)


### `CheckRemoteDebuggerPresent` - Direct Debugger Detection

Detects if the calling process is being debugged in ring 3. Also checks if another process is being debugged.

Calls `ZwQueryInformationProcess` underneath.

Returns non-zero is there is a debugger

![image](https://user-images.githubusercontent.com/7328587/152920197-63b9bcfa-7d36-4ea5-bbe5-db15db2440d3.png)


### `OutputDebugString` - Indirect Debugger Detection

Sends a string to the debugger itself.

Windows XP returns 1 if it's NOT being debugged, otherwise return an address

Windows Vista and above returns 0 if it's NOT being debugged, otherwise return an address

In Windows XP, call `GetLastError` after `OutputDebugString` will throw an error if a NO debugger is present. If EAX == 0, then a debugger IS present.

In Windows XP and above, call `SEH` after `OutputDebugString` will throw an error if a NO debugger is present. If EAX == 0, then a debugger IS present.

An error is thrown after calling `GetLastError` or `SEH` because if `OutputDebugString` returns 1 or 0, `GetLastError` and `SEH` will try to access it, but those are not valid addresses to access.


### olly specific crash - Indirect Debugger Detection

Sending `%s%s%s` to olly will crash the debugger

### `OpenProcess` - Indirect Debugger Detection

The debugee usually would not have privileges enabled, and cannot open system processes e.g. services.exe

If the debugee is able to open system process, it probably has it's privileges escalated by a debugger


### `FindWindow` / `EnumWindows` - Indirect Debugger Detection

We can get the window name of the running process by calling `FindWindow`. e.g. if running Ollydbg.exe, `Ollydbg` will be returned

We compare the window name with a typical debugger names

![image](https://user-images.githubusercontent.com/7328587/152921412-29723ccc-1484-4f2a-b1dc-5aa3e6acdf77.png)

`EnumWindows` can be called to find the name of all open windows instead


### Process Debugger Detection - Indirect Debugger Detection

Inspect the names of all running processes

`CreateToolhelp32SnapShot` creates a snapshot of all running processing using `TH32CS_SNAPPROCESS` flag

`Process32First` obtains information about the first process of the snapshot

`Process32Next` iterates through the processes in the snapshot

![image](https://user-images.githubusercontent.com/7328587/153365188-ea6027d0-e28a-4255-8c30-4a72e72b14b2.png)


### Parent Process Detection - Indirect Debugger Detection

A process opened "normally" will have `explorer.exe` as it's parent process

A process opened in a debugger will have the debugger name as it's parent process

- Obtain PID of the malware
- `CreateToolhelp32SnapShot` with `TH32CS_SNAPPROCESS` flag and `Process32Next` to iterate through all processes
- Find the PID == malware
- Find the Parent PID
- Iterate again through all processes, and check if PPID == `explorer.exe`

The malware could check for multiple `explorer.exe` or checking the parent of `explorer.exe` to check if it's the spoofed.


### Module Debugger Detection

`CreateToolhelp32SnapShot` creates a snapshot of all loaded modules of a specific process using `TH32CS_SNAPMODULE` flag

`Module32First` obtains first module in the process

`Module32Next` iterates through the modules in the process

- `CreateToolHelp32SnapShot` with `TH32CS_SNAPPROCESS` flag and `Process32Next` to iterate through all processes
- `CreateToolHelp32SnapShot` with `TH32CS_SNAPMODULE` flag and `Module32Next` to iterate through all modules in the process

![image](https://user-images.githubusercontent.com/7328587/153366791-3eebe13f-4935-4cf1-a076-d7c379bb653d.png)


### Execution Time Detection

Evaluate time taken to complete the execution of code

There are various ways to get time:
- `RDTSC` to read time stamp counter
- `GetTickCount`
- `timeGetTime`
- `QueryPerformanceCounter`
- etc.


### Words about Breakpoints

A Software Breakpoint (SWBP) is placed by substituting the byte originally located at the memory address by a software interrrupt `INT 3h`, or opcode `0xCC`

When the EIP reaches that memory address, it executes `INT 3h` which raises a SWBP exception (0x800000003h). If the process is being debugged, the debugger will stop the execution at that memory address.

SWBP however only works on the code under execution, not for memory access, which is done by Hardware Breakpoints (HWBP) (HWBP can alos be set on running code)

You can put unlimited SWBP. It is not possible to have more than 4 HWBP per thread at the same time, Since there are only 4 registers to keep track of them DR0-DR3

SWBP modifies the code, while HWBP does not modify any code, which can be helpful for anti-debugging)


### Presence of Software Breakpoints

![image](https://user-images.githubusercontent.com/7328587/153375914-7f79b8fd-634f-49ef-a4c9-0702aca71744.png)


### Presence of Hardware Breakpoints

- `OpenThread` to a handle of a thread
- `GetThreadContext` to read the thread context, and inspect DR0-DR3 for any HWBP stored

OR

- Generate an exception
- Inside the exception handler, find the context record location from ESP + 0x0C
- Check values of DR0-DR3

Values inside DR0-DR3 will be 0 if no HWBP are set


### Ring0 Debuggers and System Monitoring Tools Detection

Call `CreateFile` API to try and open handles to:
- `\\.\NTICE` -> Softice software
- `\\.\FILEM` -> FileMon software
- `\\.REGSYS` -> RegMon software

If valid handles are obtained, it means that these programs are running


### Structured Exception Handling (SEH)

Debugger Detection through Exception Generation

Can also be used for redirecting execution flow

`INT 3h` is set to indicate a SWBP. If a debugger is running, it will handle the exception, and set the EIP to the next instruction `move eax 1`

If no debugger is present, `_exception_handler` will handle it.

This means that if no debugger is present, we go to `xor eax eax`. If a debugger is present, we go to `mov eax 1`.

By evaluating `eax`, if it has a value of 1, a debugger is present. If it has a value of 0, no debugger is present.

![image](https://user-images.githubusercontent.com/7328587/153610675-d8a612fe-497f-4672-90ff-5f3bc541bf25.png)

Besides `INT 3h`, `DebugBreak` can also be used 


### Unhandled Exception Filter

Uses a specific Exception Handler `UnhandledExceptionFilterAPI`, which is normally used when there are no appropriate handlers to handle the exception

If the process is being debugged, after called `UnhandledExceptionFilterAPI`, the process will exit inside of continuing

`UnhandledExceptionFilterAPI` calls `ZwQueryInformationProcessAPI` asking for `ProcessDebugPort` information, which will return `0xFFFFFFFF` or a non-zero value if the process is being debugged by a Ring 3 debugger, and returns `0x0` if it's not being debugged.

We can force `UnhandledExceptionFilterAPI` to always return 0x0 in order for `SetUnhandledExceptionFilterAPI` to be called which transfers execution to the custom exception handler


### VM Detection

VMWARE

1. Places `VMXh` which is a the magic number for VMware into EAX
2. Prepares the function for getting VMware version `mov ecx 0Ah`
3. Prepares the port to communicate with VMware `mov edx 5658h`
4. Calls the function, which if VMware is running, it will return the magic number == EAX

Usually, `in eax dx` is a privileged instruction, and can only be executed in Ring 0, not Ring 3

However, the virtual CPU will allow the instruction will run inside a virtual machine

This trick requires an Exception Handler, as if the application is not running in a VM, it will raise an exception `0xC0000096h`

![image](https://user-images.githubusercontent.com/7328587/153620566-e22cac03-0545-4297-b2b5-5fc1ee30b43f.png)


VIRTUALPC

VirtualPC can decode `db 0Fh 3Fh 7 0Bh` which are unqiue instructions

If the application is NOT running in VirutalPC VM, it will raise an exception

![image](https://user-images.githubusercontent.com/7328587/153621893-934fca56-fd9b-4b92-8f72-c3819756d276.png)


VIRTUALBOX

VirtualBox can be easily detected through the Window Class Name of a tray icon that it place in the task bar.

![image](https://user-images.githubusercontent.com/7328587/153622162-31794a4a-dace-42f7-b186-c6dcf2179759.png)


## 11. Code Obfuscation

Obfuscated code needs to be "Cleaned"

### Logic Flow Obfuscation

By inserting plenty of `jne`, `jl` `jg` etc, it acts like a bunch of if-else statments that make the flow confusing

Straight forward code can also be convoluted.

Switching between `cmp` and `test`, where `cmp` does a subtraction while `test` does a AND operation

### NOP obfuscation

Not just putting in NOPs, but combining operations that when put together, has no effect on the program

![image](https://user-images.githubusercontent.com/7328587/153697267-1445126a-5fab-4d7a-9b34-0536b82fbeb6.png)

### Anti-Disassembler Code Obfuscation

Inserts junk bytes between instructions such at the disassembler interprets them and displays incorrect instructions

![image](https://user-images.githubusercontent.com/7328587/153697451-45ac1cdd-71b6-4dad-a10f-a53e66e5bde2.png)


After junk bytes are added in RED. `jmp` instructions are used to keep the code functional by jumping to the correct address offset

![image](https://user-images.githubusercontent.com/7328587/153697465-a173c918-069d-450f-85e8-cce8a0ad536f.png)

### Trampolines

Places code at random places instead of one after the other, uses unconditional `jmp` to make things messy

### Instruction Permutations

Substitutes simple instructions with others that have the same meaning

```
xor eax eax

becomes

push EAX
sub ESP EAX
pop EAX



mov eax ebx

becomes

push edx
xor edx edx
xor edx ebx
push edx
pop eax
pop edx
```



## 12. Packed Binaries

Retriving the original executable code that runs independently from layers of code that were added by the packer

Packers compress, encrypt and obfuscate the orignal code

### Well Known Entry Points

To get the orignal executable, we need to find the Original Entry Point (OEP)

This is the first line of code to be executed when the process is created by the Windows Loader

Example Entry Points:

![image](https://user-images.githubusercontent.com/7328587/153811565-18a6827d-24c4-4424-bc65-bb18e927818d.png)

![image](https://user-images.githubusercontent.com/7328587/153811588-7f5fb55b-3003-49f1-adfc-9dc1b7d1b484.png)

![image](https://user-images.githubusercontent.com/7328587/153811614-cfd6e22c-8e18-4cb6-8ecc-8969c2bd686e.png)

### Methods to reach OEP

1. Instructions like these could be jumping to the OEP:
- `jmp eax`
- `call ebx`
- `jmp/call ds:[031320]`
- `jmp/call ds:[eax]`

2. Look out for loops of XORing, which could be deobfuscating the original code (See WinUpack)

Click on Memory, select the PE header for the binary and "Dump in CPU"

![image](https://user-images.githubusercontent.com/7328587/154016234-7a882e00-e325-4d2e-a47f-de32400e550a.png)

Get the AddressOfEntryPoint

![image](https://user-images.githubusercontent.com/7328587/154016388-324e9522-3f5a-4987-97f5-14f2795fc3f3.png)

Navigate to the entry point of the packer at 400000 + AddressOfEntryPoint and set a breakpoint there. In this case, its 400000 + 1018 = 401018

![image](https://user-images.githubusercontent.com/7328587/154016599-04af4fb5-374c-47af-8005-d318badd9b0a.png)

Step through the code, and skip past any loops by setting a breakpoint after the loop


3. Some packers save register values before doing the packing. They then restore the register values and enter the OEP. By tracking `PUSHAD` and `POPAD`, we can determine where the packing starts and ends (See ASPack)

Set a breakpoint on POPAD, and continue execution from there

![image](https://user-images.githubusercontent.com/7328587/154001308-a763bf22-00a3-43ba-939a-98693b675ca5.png)

![image](https://user-images.githubusercontent.com/7328587/154001725-83fb2782-ae50-4f2e-8475-bba0ae465f5e.png)


4. Packers can make use of exceptions to change the flow of the program. We can monitor and follow the SEH to see where the program flows to (See PeCompact)

Memory Access Violation

![image](https://user-images.githubusercontent.com/7328587/154001905-c3cf11a9-9a45-4314-a441-f200cf8a12bb.png)

Follow the expression of the SEH

![image](https://user-images.githubusercontent.com/7328587/154001938-0d1eb6bd-558e-4080-a108-4f04faab9c07.png)

In the SEH, scroll down and set a Hardware Breakpoint on execution on the `jmp` instruction, which jumps to the packed program

![image](https://user-images.githubusercontent.com/7328587/154002109-a623cea1-c4c6-4945-8721-0930dccff419.png)


5. Exception Counting. Some packers only run the program after x number of exceptions has been triggered

6. Stack Trace-Back. By looking at what functions were called, we can try to deduce where address the OEP is (See PeUpack_b)

After we pass the exception to the SEH, we see another exception being called, and a return address. We trace that address to find the function called before it

![image](https://user-images.githubusercontent.com/7328587/154189715-7be00a18-42d7-474a-87b1-d2e3b49a3003.png)

The highlighted instruction was where we returned to, so we narrow the call to EDI above, which inside checks if there is a debugger present

![image](https://user-images.githubusercontent.com/7328587/154189847-f64b46fb-1e12-4c8f-89c1-3a6be78d7c06.png)


### Packers and Tools being used

To perform unpacking, we need plugins to Olly

Some common packers are:
- UPX
- WinUpack
- ASPack
- PECompact
- FSG

### Extract packed programs in Olly

- After entering the packed program, use OllyDump plugin to dump the application to `dumped.exe`
- Use Import REConstructor attached to the original program and view the entry point of the packed program (first 5 bytes of address) to extract the IAT and get imports
- After getting the IAT and imports, click `Fix Dump` and select `dumped.exe` to patch the IAT of `dumped.exe`
- Within the Debugger, you can view the memory address of the IAT, and click `Long-> Address with ASCII dump`

![image](https://user-images.githubusercontent.com/7328587/153826234-d2731f7b-8d28-4bd7-b1f4-a7dd261c65e3.png)


## 13. Debugging Multi-Threaded Applications

Applications that can execute different blocks of code in different threads

### Creating Threads

Creating threads are done by:
1. `CreateThread` --> creates thread within virtual address of calling process. Returns handle to thread
2. `CreateRemoteThread` --> creates thread inside virtual address of another process. Returns handle to thread
3. `CreateRemoteThreadEx` --> creates thread inside virtual address of another process. Returns handle to thread

Wrapper around `CreateThread`:
1. `_beginthread` --> should not be used for thread synchronization, as the handle generated might not be valid if it terminates very quickly. Other APIs are responsible for closing the handle, hence the return value is guaranteed to be valid
2. `_beginthreadex`

### Thread Synchronization

Threads can be synchronized with:
1. `WaitForSingleObject`
2. `WaitForMultipleObjects`

These puts the calling thread in a "wait" state until the specified "Objects" has finished running or terminated

The specified handles need to have `SYNCRHONIZE` access rights

### Thread Manipulation

Threads can be created to run immediately, or suspended (`CREATE_SUSPENDED`), until `ResumeThread` is called

`SuspendThread` suspends a thread, `TerminateThread` or `_endthreadex` (only if `_beginthreadex` was used) kills a thread

Threads can get information (CPU State) from other Threads using `GetThreadContext` with `THREAD_GET_CONTEXT` permissions enabled

Threads can perform changes to other Threads using `SetThreadContext` with `THREAD_SET_CONTEXT` permissions enabled

Usually both `THREAD_GET_CONTEXT` and `THREAD_SET_CONTEXT` are required

Context of the threads may have changed after accessing them, so we need to suspend the thread first before reading/modifying it by calling `THREAD_SUSPEND_RESUME`

### Debugging Multi-Threaded Applications

We can turn a multi-threaded application to a single threaded one

By replacing the `CreateThread` API call with `call <func>`, the function will be executed in the same thread again
