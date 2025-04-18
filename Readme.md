# 密钥安全开源密码软件


密钥安全是密码系统发挥作用的前提。密码系统在内存中运行时，需要对密钥进行额外的保护，从而防止多种内存信息泄露攻击，包括软件漏洞以及冷启动攻击等物理攻击。本开源库使用CPU SoC执行环境构建密码运算的安全执行环境，使得攻击者无法从内存中获得与密码运算有关的敏感数据。具体来说，本开源库的功能包括：

- Cache-bound 密码算法实现：在CPU Cache中进行安全的密码运算，并结合Intel TSX（Transactional Synchronization Extension）特性确保Cache中的数据不会被非法访问，共包括基于Cache实现的密码运算SM4加密/解密算法、基于SM3的HMAC算法、SM2签名算法、SM2解密算法、ECDSA签名算法和Dilithium签名算法。
- Register-bound密码算法实现：在CPU寄存器中进行安全的密码运算，防止明文数据出现在内存中，共包括2种基于寄存器实现的密码运算，分别为RSA解密和ECDSA签名。


## 目录描述
- Cache-bound/ 包含基于Cache的密码实现
  	- GMIn_Cache/ 基于Cache的国密算法SM2，SM3-HMAC，SM4；编译，运行以及软硬件环境请参考GMIn_Cache/Nortm/目录下的Readme文档。
  	- ECDSA_Cache/ 基于Cache的椭圆曲线签名算法ECDSA；编译，运行以及软硬件环境请参考ECDSA_Cache/Nortm/目录下的Readme文档。
  	- DilithiumIn_Cache/ 基于Cache的格签名算法Dilithium；编译，运行以及软硬件环境请参考DilithiumIn_Cache/Nortm/目录下的Readme文档。
	
- Register-bound/ 包含基于寄存器的密码实现
	- RSAIn_Register/ 基于寄存器的RSA解密算法；编译，运行以及软硬件环境请参考RSAIn_Register/目录下的Readme文档。
	- ECCIn_Register/ 基于寄存器的ECDSA签名算法；编译，运行以及软硬件环境请参考ECCIn_Register/目录下的Readme文档。


源代码为科研实践中开发，仅供学习和研究用途。作者不对代码的质量、功能性、稳定性或适用性作出任何承诺和保障。代码可能包含潜在问题，使用者需自行承担由此产生的风险和后果。 代码仅供非商业用途使用，如需在其他场景下使用，请联系作者并获得明确授权。

