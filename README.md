# HikVisionAliceToolkit
A toolkit based on PoC of HikVision.  
## CN
### 36260Attacker  

这是一个针对CVE-2021-36260漏洞的PoC，使用dotnet8编写，采用NativeAoT生成。  
有如下五个命令：`test`，`shell`，`reboot`，`forceshell`和`rawcmd`。  

如果需要开启代理请在`UseProxy`选项输入大于0的数字，不需要则输入0或者负数。支持使用Uri形式的代理，例如：`http://127.0.0.1:543` 或者 `socks5://127.0.0.1:543`。  

1. **`test`命令**  
   `test`命令可以测试目标摄像头是否具有能被攻击的漏洞。  

2. **`reboot`命令**  
   `reboot`命令可以重启摄像头。  

3. **`shell`命令**  
   `shell`命令可以在摄像头的指定端口开启一个由Dropbear提供的SSH服务，但是目前因为命令长度限制只能选择4位数端口。  

4. **`forceshell`命令**  
   `forceshell`命令可以无视检查SSH是否已开启的操作，强制打开SSH，适合于`shell`命令返回成功但是却无法连接的情况。  

5. **`rawcmd`命令**  
   `rawcmd`命令可以直接通过漏洞执行Linux命令，但是长度限制22个ASCII字符，请在阅读源代码之后再使用。该命令输入`exit`退出。  

所有启动的SSH服务的账号是`usrx`，密码是`114514alice`。  
输入`exit`退出程序。  

### 其他项目  
目前正在开发中。

### 其他项目 
目前正在开发中

## EN
### 36260Attacker  

This is a Proof of Concept (PoC) for the CVE-2021-36260 vulnerability, written in dotnet8 and built with NativeAoT.  
It provides five commands: `test`, `shell`, `reboot`, `forceshell`, and `rawcmd`.  

If you need to enable a proxy, enter a number greater than 0 in the `UseProxy` option. Otherwise, enter 0 or a negative number. It supports proxy URIs, e.g., `http://127.0.0.1:543` or `socks5://127.0.0.1:543`.  

1. **`test` Command**  
   The `test` command tests whether the target camera is vulnerable to this exploit.  

2. **`reboot` Command**  
   The `reboot` command restarts the target camera.  

3. **`shell` Command**  
   The `shell` command enables an SSH service provided by Dropbear on the specified port of the target camera. Currently, due to command length limitations, only 4-digit ports are supported.  

4. **`forceshell` Command**  
   The `forceshell` command bypasses the check for an existing SSH service and forcibly enables SSH. This is useful when the `shell` command reports success but the connection fails.  

5. **`rawcmd` Command**  
   The `rawcmd` command allows direct execution of Linux commands via the vulnerability. However, it has a length limit of 22 ASCII characters. Use this command only after reviewing the source code. Enter `exit` to quit this command.  

For all SSH services started by the program, the username is `usrx` and the password is `114514alice`.  
Enter `exit` to quit the program.  

### Other Projects  
Currently under development.
