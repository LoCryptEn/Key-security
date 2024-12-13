### 基本介绍
Nortm为支持SM2、SM3、SM4等国产密码算法安全实现的内核模块.

密钥受TSX和Cache保护，解密运算在Cache中实现，防止来自DRAM的攻击.

### 代码介绍
- 分为Kernel和User两个目录，其中Kernel下为Linux系统下的内核模块（一种内核驱动）；
	- tsx.h中包含开启TSX保护的宏定义，根据机器的具体支持情况，启用或关闭；
- User目录下为用户态的应用程序，通过ioctl接口调用内核模块中的密码运算.
### 程序使用
1. 编译安装内核模块
	- 在Kernel下，执行make命令，编译内核模块；
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
		- -o 表示输出文件(在SM2 verify时表示签名文件)
		- -l 表示循环次数，0表示执行直到成功
5. 程序运行实例
	- 内核模块初始化：./user 1
		- 初始化CPU中的SM4密钥，以及PIN码。之后与内核模块交互时都需要此PIN码
		- 可以使用-d进入调试模式，此时将使用默认的密钥与PIN码，此后的每一步均需使用-d参数
	- SM2密钥初始化：./user [2|3] -o sm2.key
	- SM2签名：./user [4|5] -i file.msg -u yourname -k sm2.key -o sm2.sig
	- SM2验签：./user 9 -i file.msg -u yourname -k sm2.key -o sm2.sig
	- SM3摘要：./user 10 -i file.msg -o sm3.deg
    - SM4加密：./user 12 -i file.msg -o sm4.enc -k sm4.key
    - SM4解密：./user 13 -i sm4.enc -o sm4.dec -k sm4.key
    - SM3-HMAC：./user 14 -i file.msg -o sm3.hmac -k hmac.key
 			

上述命令在Ubuntu16.04环境中能运行成功

注1：如果设备支持TSX，请确保在Kernel目录下的tsx.h文件中使用宏定义TSX：#define TSX_ENABLE

注2：若使用Safe SM2 KeyGen得到SM2公私钥文件，那么此文件只能使用在Safe SM2模式下

注3：密钥与密文输出以16进制字符串的形式输出，解密的消息以字符形式输出

注4：对称密钥如sm4.key与hmac.key只需提供足够长的随机字符串即可，因为其先使用CPU的SM4密钥解密一次才使用，实际密钥会得到保密

  

源代码为科研实践中开发，仅供学习和研究用途。作者不对代码的质量、功能性、稳定性或适用性作出任何承诺和保障。代码可能包含潜在问题，使用者需自行承担由此产生的风险和后果。 代码仅供非商业用途使用，如需在其他场景下使用，请联系作者并获得明确授权。

