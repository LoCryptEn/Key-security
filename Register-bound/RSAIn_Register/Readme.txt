基本介绍：
Nortm为支持RSA解密的安全实现的内核模块；
RSA私钥受寄存器保护，解密运算在寄存器中实现，防止来自DRAM的攻击.

Kernel目录：
1、make (编译)
2、sudo make install（安装内核模块）
3、lsmod |grep nortm （查看内核模块是否安装成功）
chmod 777 /dev/nortm (修改权限)

User目录：
1、make （编译）
2、./user 1 1 1 1 (初始化)
3、./user 1 1 1 2 (功能测试)

上述命令在Ubuntu 20.04环境中能运行成功，CPU需要支持AVX-512