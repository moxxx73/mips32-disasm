# mips32-disasm
Just a small program demonstrating the disassembly of Mips32 instructions (Sample code provided)

As of now the disassembler can disassemble the main function of the provided sample code and most  
of the other instructions.  

This project was purely just something fun to do while researching the Mips architecture. Not sure  
whether i will update the disassembler with more instructions or develop it into something more complete.

## Compilation
To build the disassembler just run *gcc*:
```
gcc ./mips-disasm.c -Wall -Wextra -o ./mips-disasm
```
-and to build the sample target you will need the mips development tools (`mips-linux-gnu-*`):
```
mips-linux-gnu-gcc ./mips-target.c -Wall -Wextra -o ./mips-target
```
then you'll need to use *objcopy* to generate the machine code dump (-as theres no ELF parsing):
```
mips-linux-gnu-objcopy -O binary -j .text ./mips-target ./target.bin
```

## Running the disassembler
just call the binary:
```
./mips-disasm
```
the target binary's entry point address and file path to the machine code dump are hardcoded.
