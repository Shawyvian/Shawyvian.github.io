---
title: FSOP例题 buu houseoforange
date: 2026-09-27 23:01:49
tags: [CTF, PWN, IO_FILE]
---

题目：`E:\CTF\buu\Pwn\53_houseoforange`（本地路径）
有堆溢出


# 利用链：
## 堆溢出修改top_chunk的size 
## 申请大chunk，0x1000  --> 堆管理器重新mmap一块heap，原来的top_chunk进入unsorted bin
![](/images/posts/Pasted%20image%2020260923185459.png)
## 申请0x400 --> 泄露libc_addr(main_arena+0x58)和heap_addr(unsorted bin 扫描)
![](/images/posts/Pasted%20image%2020260923185710.png)
## 构造fake_FILE
![](/images/posts/Pasted%20image%2020260923185932.png)
![](/images/posts/Pasted%20image%2020260923190348.png)
## unsorted bin attack
会chunk->bk = main_arena + 0x58
而 `_IO_list_all` 指向第一个FILE,这里就是main_arena+0x58,此时我们希望跳转到下一个FILE为fake_FILE,所以要让 `_chain` (偏移0x68) 指向fake_FILE
```c
_IO_list_all(现在是 main_arena+0x58) + 0x68  ==  main_arena+0xC0
bin_at(av,6) + 0x18 = bins[10] - 0x10 + 0x18 = main_arena+0x68 + 0x50 + 0x08 = main_arena+0xC0
```
这验证了0x60大小的small bin(含prev_size, size) 正好就在main_arena + 0x58 + 0x68处,也就是 `_chain`了,这里刚好指向fake_FILE
## 报错触发 `abort()`  --> `_IO_flush_all_lockp(0)` --> 遍历 FILE 链
## 遍历到fake_FILE
fake_FILE里 `_IO_write_ptr` > `_IO_write_base`  --> `__overflow(fp)` (`vtable[3]`)

实际上  `vtable[3]` 处是 `system` ,而 `fp` 的 `_flags`(前8字节) 被改成了 `/bin/sh\x00`
相当于调用 `system('/bin/sh')`



# 后记
测试发现会有概率拿不到shell，发现进入到 `_IO_list_all` 指向的 `main_arena + 0x58` 处的fake_FILE时，里面的 `_IO_write_ptr` > `_IO_write_base` ，会触发 `_overflow` ，而不是通过 `_chain` 找到我们伪造的fake_FILE

这其实是是因为 `_mode` > `0` 了，导致处理时是宽字节模式
这里我举例为什么不行
当进入宽字节模式时，会去看 `fp->_wide_data` 这个结构，这个指针指向的区域存有待校验的 `_IO_write_ptr` 和 `_IO_write_base`

`fp->_wide_data` 偏移为0xA0,指向0x90
![](/images/posts/Pasted%20image%2020260927224343.png)
而`_IO_write_base` 在 `_IO_wide_data` 的偏移为0x18
`_IO_write_ptr` 为0x20
![](/images/posts/Pasted%20image%2020260927224657.png)
此时的 `_IO_write_ptr` > `_IO_write_base` 会触发 `_overflow`

而如果 `_mode` <=  `0` 就会走正常流程，中间步骤不会 `_overflow` 而是走 `_chain`


`_mode` 偏移为0xC0,且为32位，正负就跟 `libc_base` 相关了
fake_FILE起始位置为 `main_arena + 0x58` ,那么 `_mode` 就是 `main_arena + 0x118` 指向的值
因为是在 `small bins` 上的，值就是 `main_arena + 0x108`
由于取32位，所以 `_mode = (main_arena + 0x108) & 0xffffffff` <= `0` 就行了
