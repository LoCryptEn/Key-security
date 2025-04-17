#!/bin/bash
#  unsigned long AES_Key[2]={0x0123456789ABCDEF, 0xFEDCBA9876543210};
#  low - > high ef cd ab 89 67 45 23 01 10 32 54 76 98 ba dc fe 
# vmovdqu     (%rsi),     %xmm0 
# 即xmm0 : fe dc ba 98 78 54 32 10 01 23 45 67 89 ab cd ef
#openssl -K efcdab89674523011032547698badcfe 
# 定义 16 进制数据 q
hex_data="ce3ace02ba41d151ed3d48e98204c5daa80346782c9c9451582ba059129700ce2d7e8d12ac11802dacc77f4da40e3353469e89b2947fe52436a0af2c7033b1fc00e9b65ae2baa4e9475ee6cd25c0ee8ad7762bf0289fbfaa165d325ef90b4e37375640cac798abb7e439ccac01c277433f1210635c1ef58761c2bfd9c239a729"

# 定义 16 进制数据 p
#hex_data="97f11f47fb793c58668fe46736687247370db111ba37639170ec26467384132a993c0e2feba7e326e9154611317238e66f7a8c48e80714c4fb45015b7b6e81f031b55553d04a17556f860d59f0e3d6c2655b5a1079ea6acb97e02238daa63df020e818e6a553cc216d27d2bb7e5eaad7cc33b3e673618c86fcbfeaabb5af91c9"

# 定义 16 进制数据 iqmp
#hex_data="4F1C25093AB75BF0C6BB527EB58E558399409A74C238F16582C428823C8DAF5D226D3472A2FCFFB9DE12B6CFA05AD0B0DAF11B3AFCCF1E37C6FE88D4E4F35C5269AA0AF927F1AD47D5493666BD112B979E291B809FCD4125F8F73994141C34A2B546B18C8636D20FF0349A23175D554FA262813EA438B9828E2D52EC259E0EBF"

#定义 16 进制数据 p0
#hex_data="51B08BE00DD0A787"

# 定义 16 进制数据 q0
#hex_data="30B922942B001AE7"


# 定义 16 进制数据 iqmp
#hex_data="3B77875466A3BA2C10E56D1A70364D64DB2FA973C10D663C955C3B60D7F7D0F7ABB5CC5731FCD0CFF96158D571C75F3AD553E8CA3DC9E3B32B8319A74D26A314111F8FBD39E32AA878B1CEB925D6281E96BCCCDB03D178E37F7E61238A7D72684FA2515A87E75ADD14CFA343BD937442B6F1BE85E23C279EA7CC614D5197C537"

length=${#hex_data}

if [ $(($length % 32 )) -eq 0 ]; then
padding_string=$hex_data
else
padding=$(((32 - length % 32)% 32))
padding_string=$(printf "%0${padding}d%s" 0 "$hex_data")
fi

split_string=$(echo "$padding_string" | awk '{for(i=1 ; i<=length ;i+=32)print substr($0 ,i ,32)}')

echo "########################################"
echo "$split_string"


hex_data=$(echo "$split_string" | awk '{
    hex = $0

    # 计算长度
    len = length(hex)

    # 初始化小端序字符串
    little_endian = ""

    # 将16进制字符串分成两个字符一组，并反转顺序
    for (i = len - 2; i >= 0; i -= 2) {
        little_endian = little_endian substr(hex, i + 1, 2)
    }

    # 输出小端序的16进制字符串

    # 存储转换后的行
    lines[NR] = little_endian
}
END {
    # 输出逆转后的所有行
    for (i = NR; i > 0; i--) {
        print lines[i]
    }



}' )

echo "########################################"
echo "$hex_data"

#hex_data="dac50482e9483ded51d141ba02ce3ace"




# 将 16 进制数据转换为二进制数据并写入文件
echo -n "$hex_data"  >  hexfile.txt
xxd -r -p hexfile.txt > test_cipher_plain.bin
echo "########################################"
xxd test_cipher_plain.bin
echo "########################################"
openssl enc -e -aes-128-ecb -in test_cipher_plain.bin -out test_cipher_to.bin -K efcdab89674523011032547698badcfe  -nopad 

res_temp=$(xxd  -p -c 8 test_cipher_to.bin) 
echo "########################################"
echo "$res_temp"
echo "########################################"
res=$(echo "$res_temp" | awk '{
   hex = $0

    # 计算长度
    len = length(hex)

    # 初始化小端序字符串
    little_endian = ""

    # 将16进制字符串分成两个字符一组，并反转顺序
    for (i = len - 2; i >= 0; i -= 2) {
        little_endian = little_endian substr(hex, i + 1, 2)
    }

    # 输出小端序的16进制字符串

    # 存储转换后的行
    # 存储转换后的行
    lines[NR] = little_endian
}
END {
    # 输出逆转后的所有行
    for (i = 1; i < 1+NR; ++i) {
        print "message[" i-1  "]=0x" lines[i] ";"
    }



}' )
#以下参数即可粘贴到对应的位置，实现自定义参数的受寄存器保护RSA-2048解密
echo "$res"
########################################
#如以下结果，即为经AES加密后的RSA p参数
#    message[0]=0xd17dc21c42760588;
#    message[1]=0xcf47ab0e698ffa1d;
#    message[2]=0x2cd2609ebe844674;
#    message[4]=0xf0a6d3d16eeb4ccf;
#    message[5]=0xa8d229f570c07090;
#    message[6]=0x446451e76acc42d9;
#    message[7]=0xa72983ec415a791d;
#    message[8]=0x41231c88dcd8100b;
#    message[9]=0x1cefc2a0efa05033;
#    message[10]=0x64ce55c4a3bc654b;
#    message[11]=0x5b8ca345b5ad8e04;
#    message[12]=0x15cf7213c53cb526;
#    message[13]=0xa11dce113e711dfa;
#    message[14]=0x4d3c000642903cfa;
#    message[15]=0x3c3b91e6f58ecdbd;

#可对应粘贴至user.c第87行处；其余参数的加密流程与上例相同