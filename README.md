# HikVisionAliceToolkit
A toolkit based on PoC of HikVision.  
## CN
## 36260Attacker  

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

## HikCameraScan

## 概述

HikCameraScan 是一个用于扫描 Hikvision 摄像头系统的工具，支持两种扫描模式：  
1. **/doc/page/**：扫描指定 IP 范围内的设备是否存在 `/doc/page/login.asp` 页面。  
2. **36260scan**：扫描指定 IP 范围内的设备是否存在 **CVE-2021-36260** 漏洞。  

该工具支持通过命令行参数或控制台交互方式来配置扫描，并且支持多线程加速扫描。

## 功能介绍

### 支持的扫描类型
- **/doc/page/**：此扫描模式检测设备是否存在 `/doc/page/login.asp` 页面。
- **36260scan**：此扫描模式检测设备是否存在 CVE-2021-36260 漏洞，该漏洞允许攻击者进行远程代码执行。

### 输入参数
程序支持两种方式读取输入参数：
1. **命令行参数**：通过命令行传入参数来指定扫描的类型和配置。
2. **控制台交互输入**：通过控制台交互输入配置（仅在命令行未使用 `-p` 参数时）。

### 命令行参数
支持以下命令行参数来配置扫描：
- `-f <folder>`：指定保存扫描结果的文件夹路径。
- `-p`：表示使用命令行参数（不通过控制台交互）。
- `--configtype=<config_type>`：指定配置类型（`/doc/page/` 或 `36260scan`）。
- `--startip=<start_ip>`：指定扫描的起始 IP 地址。
- `--endip=<end_ip>`：指定扫描的结束 IP 地址。
- `--threads=<threads>`：指定扫描时使用的线程数（默认为 4）。

### 扫描过程
1. 程序根据输入的配置类型（通过命令行参数或控制台交互）加载配置。
2. 根据配置，程序启动对指定 IP 范围的扫描。
3. 扫描结果会保存到指定的文件夹中，文件名格式如下：  
   `<ResultTypeInfo>+<StartIP>-<EndIP>.txt`。
4. 每一行结果包含设备信息，格式为：  
   `CamUrl||Port:<Port>||<AdditionalInfo>`。

## 示例

### 1. 通过命令行启动扫描
假设你要扫描 IP 范围为 `10.22.13.1` 到 `10.22.13.254`，并且将结果保存到 `C:\ScanResults\` 文件夹中，同时使用 16 个线程进行扫描，使用以下命令启动扫描：
```bash
HikCameraScan.exe -f C:\ScanResults\ -p --configtype=36260scan --startip=10.22.13.1 --endip=10.22.13.254 --threads=16
```

此命令将扫描 IP 范围内的设备是否存在 CVE-2021-36260 漏洞，并将结果保存在 `C:\ScanResults` 目录下，扫描使用 16 个线程进行。

### 2. 通过控制台输入配置
如果你不使用命令行参数，可以直接运行程序并通过控制台输入配置：
```bash
HikCameraScan.exe
```
程序会提示你输入配置类型，例如：
```
ConfigType:
```
你可以输入 `36260scan` 来开始扫描 CVE-2021-36260 漏洞。

随后，程序会要求你输入扫描的起始 IP 和结束 IP：
```
Start IP:
End IP:
```

### 3. 输出结果示例
扫描完成后，程序会在指定文件夹中生成一个文件，内容示例：
```
http://10.22.13.10||Port:80||Vulnerable
http://10.22.13.15||Port:8080||Not Vulnerable
```


### 注意事项
- **目录权限**：确保程序有足够的权限创建和写入指定的文件夹。
- **IP 范围**：扫描会按照 IP 范围逐个进行，因此扫描时间可能较长，具体时间取决于目标 IP 范围的大小。
- **多线程**：可根据需要调整线程数，以加速扫描过程。

## 问题与反馈
如果在使用过程中遇到任何问题，可以参考错误输出信息或联系开发者进行反馈。

## 依赖
- .NET 8.0 或更高版本

## EN
## 36260Attacker  

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

## HikCameraScan

## Overview

HikCameraScan is a tool used for scanning Hikvision camera systems, supporting two scanning modes:
1. **/doc/page/**: Scan a specified IP range to check if the `/doc/page/login.asp` page exists.
2. **36260scan**: Scan a specified IP range to check if the device is vulnerable to **CVE-2021-36260**.

The tool supports both command-line parameters and console interaction for configuration, and it supports multi-threaded scanning for faster performance.

## Features

### Supported Scan Types
- **/doc/page/**: This scan mode checks if the `/doc/page/login.asp` page exists on the device.
- **36260scan**: This scan mode checks if the device is vulnerable to CVE-2021-36260, a vulnerability that allows remote code execution.

### Input Parameters
The program supports two ways of reading input parameters:
1. **Command-Line Parameters**: Input parameters passed via the command line to specify the scan type and configuration.
2. **Console Interaction**: Input configuration through console prompts (only used when the `-p` parameter is not provided).

### Command-Line Parameters
The following command-line parameters are supported for configuration:
- `-f <folder>`: Specifies the folder path to save scan results.
- `-p`: Indicates that the program should use command-line parameters (not console interaction).
- `--configtype=<config_type>`: Specifies the configuration type (`/doc/page/` or `36260scan`).
- `--startip=<start_ip>`: Specifies the start IP address for the scan.
- `--endip=<end_ip>`: Specifies the end IP address for the scan.
- `--threads=<threads>`: Specifies the number of threads to use during scanning (default is 4).

### Scanning Process
1. The program loads the configuration based on the input configuration type (via command-line parameters or console interaction).
2. The program initiates the scan over the specified IP range according to the configuration.
3. Scan results are saved to the specified folder, with filenames in the following format:  
   `<ResultTypeInfo>+<StartIP>-<EndIP>.txt`.
4. Each result line contains device information in the format:  
   `CamUrl||Port:<Port>||<AdditionalInfo>`.

## Example

### 1. Start a Scan via Command-Line
To scan an IP range from `10.22.13.1` to `10.22.13.254` and save the results to `C:\ScanResults\`, using 16 threads, use the following command:
```bash
HikCameraScan.exe -f C:\ScanResults\ -p --configtype=36260scan --startip=10.22.13.1 --endip=10.22.13.254 --threads=16
```

This command will scan the specified IP range for the CVE-2021-36260 vulnerability and save the results in the `C:\ScanResults` directory, using 16 threads for the scan.

### 2. Start a Scan via Console Interaction
If you don't want to use command-line parameters, you can run the program and input configurations interactively via the console:
```bash
HikCameraScan.exe
```
The program will prompt you for the configuration type, for example:
```
ConfigType:
```
You can enter `36260scan` to start scanning for the CVE-2021-36260 vulnerability.

The program will then prompt you for the start and end IP addresses:
```
Start IP:
End IP:
```

### 3. Example of Scan Results Output
After the scan completes, the program generates a file in the specified folder with the following format:
```
http://10.22.13.10||Port:80||Vulnerable
http://10.22.13.15||Port:8080||Not Vulnerable
```


By parsing the command-line arguments, the program loads the corresponding scanning method based on the configuration type and starts the scan.

## Notes
- **Directory Permissions**: Ensure the program has the necessary permissions to create and write to the specified folder.
- **IP Range**: The scan will proceed IP-by-IP, so the scan duration may vary depending on the size of the target IP range.
- **Multi-threading**: You can adjust the number of threads to speed up the scanning process.

## Issues and Feedback
If you encounter any issues during use, refer to the error output for more information or contact the developer for support.

## Dependencies
- .NET 8.0 or higher
