### 基本介绍
Nortm为支持Dilithium后量子密码算法安全实现的内核模块.

密钥受TSX和Cache保护，密码运算在Cache中实现，防止来自DRAM的攻击.

### 代码介绍
- 分为Kernel和User两个目录，其中Kernel下为Linux系统下的内核模块（一种内核驱动）；
	- tsx.h中包含开启TSX保护的宏定义，根据机器的具体支持情况，启用或关闭；
- User目录下为用户态的应用程序，通过ioctl接口调用内核模块中的密码运算.

### 程序使用
1. 编译安装内核模块
	- 在Kernel目录下，执行make命令，编译内核模块；
	- 在Kernel目录下，执行make install命令；
		- sudo insmod nortm.ko，安装内核模块
		- chmod 777 /dev/nortm，修改权限
	- 查看内核模块是否安装成功：lsmod | grep nortm
2. 卸载内核模块
	- 在Kernel目录下，执行make uninstall命令
3. 编译用户态测试程序
	- 在User目录下，执行make命令，编译测试程序；
4. 用户态程序运行
	- 查看测试项：./user
	- 依次进行功能测试：./user X [options paramter],将X换为具体的测试项
		- -d 表示使用调试模式
		- -i 表示输入文件
		- -k 表示密钥文件
		- -o 表示输出文件(在Dilithium verify时表示签名文件)
		- -l 表示循环次数，0表示执行直到成功

上述命令在Ubuntu16.04环境中能运行成功

注1：CPU需要支持Intel Transactional Synchronization Extension (Intel TSX)，并确保在Kernel目录下的tsx.h文件中使用宏定义TSX：#define TSX_ENABLE

注2：若使用Safe KeyGen得到Dilithium公私钥文件，那么此文件只能使用在Safe模式下

源代码为科研实践中开发，仅供学习和研究用途。作者不对代码的质量、功能性、稳定性或适用性作出任何承诺和保障。代码可能包含潜在问题，使用者需自行承担由此产生的风险和后果。 代码仅供非商业用途使用，如需在其他场景下使用，请联系作者并获得明确授权。
