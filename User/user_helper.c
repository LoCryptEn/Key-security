#include "user_helper.h"
#include <stdlib.h>
int user_helper(){
    uint64_t*c;
    c=(uint64_t*)malloc(32*64);
    uint64_t *c_1;
    c_1=(uint64_t*)malloc(16*64);
    uint64_t *c_2;
    c_2=(uint64_t*)malloc(16*64);
    size_t e_len,d_len,n_len,m_len,c_1_len,c_2_len,ciphertext_len;
    char* e="0f31";
    //char* d="928ae599a94444bbf412b41c9791328de405ea74d7ef5a5f72c8e7cdfddb5fdb4d7e1cab9cdecdd634b7ed481550bc99864f6a71a4ffcc6b6b31b21bac8d21f46f5a6176cc7ad28bad388565e076d5e6eb0c577dddd9d7f55cd83330cb01677896ee37d598734eb10e95af997ddb08949d171a68629de9622a5bbcce01ccbfcda8ce93f779eb474362f917ed74eb1f823d81ec11f444a8773a071a632ea5efb4b0945680a6ad70f45c3d2612b7d090a79c282d81ebbd433ae01af0c96be73c846d8b00b8900875d92f31ee00614bc0a3be54ece2167b12128f8ea671e0fdc3c5868b6b4bdf314dc8e9c51350f35ac7a0d05d532340f8070fa8d41cc1b1f3b91";
    char* n="7a66ee12a844f4220cb0d502fd0f377a253910a5011e857e05358e279ab0e9be28b311ade9ae71c1b599d90d6b189ae44d7d9ad55b3f72632e27798d1bba482ec0a368d4c4a3120f9bd8d507f41090af8efe98e9f4f6032c569f404fa0c432698206a54a1b52ad3849d15f0b25e1035f8a784cfc3f750d8c8d0eb6f07827ff00b2c91451e2c4afd78fc32caec1f27d48394261489f8edb0859d61f0726a2ee0f349c8e663e373bcb5ba60f3bc63d1731ea9eb6b703e815bfecc14023d84a708856094ede6958568ad440bf66a2da6c171b4d21db2b4f6c4ddf00152c0f3c7dce416bdfe7b9fcf674a71d99d1fd198cb2775541de2f47c274afa6a3f868f97831";
    char* m="23418278266666766666665666666766666668666616666626666366666466666676666686666662366666666634666666666666666578666666666666666123666666666666238966666666746666666609a1";
    //char* m="2774182782666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666609a1";
    char m_user_input[1024];
    printf("以下是 受寄存器保护的RSA-2048解密DEMO:\n");
    printf("##############################################\n");
    printf("公钥(e,n)=\n(%s,%s)\n",e,n);
    printf("##############################################\n");
    printf("请输入明文m(小于n的16进制数),如略过(则为默认值 \"%s\")请输入回车键\n",  "123456789");
    printf("明文m: ");
    fgets(m_user_input, sizeof(m_user_input), stdin);
    // Remove newline character if present
    size_t len = strlen(m_user_input);
    if (len > 0 && m_user_input[len - 1] == '\n') {
        m_user_input[len - 1] = '\0';
    }
    if (len== 1) {
        strcpy(m_user_input, "123456789");
    } 

    printf("使用明文: %s\n", m_user_input);
    rsa_used_for_test_enc( e,n,m_user_input,&e_len,&n_len,&m_len,c_1,c_2,c_1_len,c_2_len,c,ciphertext_len);
    memcpy((void*)C_1_from_extern,(void*)c_1,16*64);
    memcpy((void*)C_2_from_extern,(void*)c_2,16*64);
    free(c);
    free(c_1);
    free(c_2);
    return 0;
    
}
