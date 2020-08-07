#include <iostream>


#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256

#include "pairing_3.h"
PFC pfc(AES_SECURITY);  // 初始化双线性对曲线
Big s; //私钥 
/*阶为素数p的乘法循环群*/
G1 S, R; 
G2 Q, V;  
Big X; 

//公私钥生成
void keygenBLS()
{
    // Create system-wide G2 constant
    pfc.random(Q);

    pfc.random(s);    // 私钥
    printf("privatekey: %d\n", s);
    V = pfc.mult(Q, s);  // 公钥
    printf("publickey: %d\n", V);
}

/*BLS签名*/
void signBLS(unsigned char* plain, int* lsb)
{
    //对消息求曲线哈希H(m)
    pfc.hash_and_map(R, (char*)plain); 
    S = pfc.mult(R, s); //消息的哈希结果乘以私钥就是签名

    *lsb = S.g.get(X);   // 签名结果是曲线上一个点

    cout << "Signature= " << lsb << " " << X << endl;
}

/*验证BLS签名*/
int vertifyBLS(int* lsb)
{

    if (!S.g.set(X, 1 - *lsb))
    {
        cout << "Signature is invalid" << endl;
        exit(0);
    }
   
    // Observe that Q is a constant
    // Interesting that this optimization doesn't work for the Tate pairing, only the Ate

    pfc.precomp_for_pairing(Q);

    G1* g1[2];
    G2* g2[2];
    g1[0] = &S; g1[1] = &R;
    g2[0] = &Q; g2[1] = &V;
     //验证公钥和消息的哈希值,与曲线生成点和签名,是否映射到同一个数
    if (pfc.multi_pairing(2, g2, g1) == 1)
        cout << "Signature verifies" << endl;
    else
        cout << "Signature is bad" << endl;
}

