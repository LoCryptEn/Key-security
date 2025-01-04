### 基本介绍
Nortm为支持Dilithium后量子密码算法安全实现的内核模块.

密钥受TSX和Cache保护，密码运算在Cache中实现，防止来自DRAM的攻击.

### Kernel目录
1. make (编译)
2. make install（安装内核模块）
3. lsmod |grep nortm （查看内核模块是否安装成功）
4. chmod 777 /dev/nortm (修改权限)

### User目录
1. make （编译）
2. ./user

上述命令在Ubuntu16.04环境中能运行成功

注：当前代码没有使用TSX特性，如果设备支持TSX，请在Kernel目录下的tsx.h文件中使用宏定义TSX：#define TSX_ENABLE
