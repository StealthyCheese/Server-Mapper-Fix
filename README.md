# Server-Mapper-Fix
ALL THIS IS DONE WITHOUT WRITING TO THE MODULE ITSELF OR FIXING IT STATICALLY | INJECTOR & BIN ARE INCLUDED!
take into consideration this example assumes
the target module has no extra protections besides iat + PE server mapped

Below is what this example looks like under IDA
 ![IDA](/WriteUp/imgs/IDA.png)

As you can see the entry refrences function addresses which are out of module.
as seen in the ida snip the memory address for LoadLibraryA = TargetBase + 0x1E000
& address for MessageBoxA = TargetBase + 0x1ED7A

To start fixing this we would need to get the imports called
you can get the imports used within a process by following an import call (ill look something like this)

 ![IAT](/WriteUp/imgs/IAT.png)

if your able, set breakpoints to get the list of imports
you can use the return addresses to get the address the import if refrenced example = ret - instr size;

to get the import addresses you can manually debug the module containing the import needed
for example with kernel32.dll you can get the exported function address (LoadLibraryA) minus it from the module base address

( THE IMPORT OFFSETS WILL CHANGE BETWEEN WINVERS!! I RECOMMEND USING GetProcAddress TO GET ADDRESSES AUTO AT RUNTIME )

LoadLibrary Export Address = 00007FFD3FEA92C0

Kernel32 BaseAddress 00007FFD3FE91000 - 1000 = 00007FFD3FE90000

Import Offset 00007FFD3FEA92C0 - 00007FFD3FE90000 = 0x192C0

kernel32 base address + 0x192C0 = LoadLibrary import address

 ![LoadLibraryA](/WriteUp/imgs/LoadLibraryA.png)
 
Same For MessageBoxA

MessageBoxA Export Address = 00007FFD3E1FA3B0

User32 Base Address 00007FFD3E181000 - 1000 = 00007FFD3E180000

Import Offset 00007FFD3E1FA3B0 - 00007FFD3E180000 = 0x7A3B0

User32 Base address + 0x7A3B0 = MessageBoxA import address
 ![MessageBoxA](/WriteUp/imgs/MessageBoxA.png)

 using this info we can write simple shell code at the call addresses 0x1E000 & 0x1ED7A or write a simple jmp instruction at the import address to our shellcode
 the shellcode ( wo using imports ) will call the addresses of the missing import
