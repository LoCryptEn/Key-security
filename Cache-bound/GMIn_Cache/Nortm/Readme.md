### 基本介绍
Nortm为支持SM2、SM3、SM4等国产密码算法安全实现的内核模块.

密钥受TSX和Cache保护，解密运算在Cache中实现，防止来自DRAM的攻击.

### 代码介绍
- 分为Kernel和User两个目录，其中Kernel下为Linux系统下的内核模块（一种内核驱动）；
	- tsx.h中包含开启TSX保护的宏定义，根据机器的具体支持情况，启用或关闭；
	- template_c.c为内核模块的主文件；
	- .S后缀的文件为使用寄存器的汇编实现；
- User目录下为用户态的应用程序，通过ioctl接口调用内核模块中的密码运算.
### 程序使用
1. 编译安装内核模块
	- 在Kernel下，执行make命令，编译内核模块；
	- 在Kernel目录下，执行sudo make install命令，安装内核模块；
	- 查看内核模块是否安装成功：lsmod |grep nortm
	- chmod 777 /dev/nortm (修改权限)
2. 编译用户态测试程序
	- 在User目录下，执行make命令，编译测试程序；
3. 运行
	- 查看测试项：sudo ./user
	- 内核模块初始化：sudo ./user 1 1 1 1 1
	- 依次进行功能测试：sudo ./user 1 1 1 X 1,将X换为具体的测试项
4. 卸载内核模块
   	- sudo rmmod nortm

上述命令在Ubuntu16.04环境中能运行成功

注：当前代码没有使用TSX特性，如果设备支持TSX，请在Kernel目录下的tsx.h文件中使用宏定义TSX：#define TSX_ENABLE
