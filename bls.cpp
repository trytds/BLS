#include <iostream>
#include <ctime>

#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256

#include "pairing_3.h"
PFC pfc(AES_SECURITY);  // 初始化双线性对曲线
Big s;
G1 S, R;
G2 Q, V;
Big X;

void keygenBLS()
{
    //G2 Q, V;
    //Big s;
    // Create system-wide G2 constant
    pfc.random(Q);

    pfc.random(s);    // private key
    cout << "privatekey: " << s << endl;
    V = pfc.mult(Q, s);  // public key
    printf("publickey: %d\n", V);
}

/*BLS签名*/
void signBLS(unsigned char* plain, int* lsb)
{
    //对待签名信息进行Hash计算 生成结果
    pfc.hash_and_map(R, (char*)plain); //对签名信息进行校验
    S = pfc.mult(R, s);

    *lsb = S.g.get(X);   // signature is lsb bit and X

    cout << "Signature= " << lsb << " " << X << endl;
}

/*验证BLS签名*/
int vertifyBLS(unsigned char* plain, int* lsb)
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
     //如果进行签名比较
    if (pfc.multi_pairing(2, g2, g1) == 1)
        cout << "Signature verifies" << endl;
    else
        cout << "Signature is bad" << endl;
}

int main()
{
    clock_t start, finish;
    double duration;

    unsigned char tx[5000] = "Be there or be square!"; //待签名明文
    int etx[4000]; //签名信息
    unsigned char mtx[5000] = "0"; //解密
    
    start = clock();
    keygenBLS();
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("KeyGen: %f seconds\n", duration);

    start = clock();
    signBLS(tx, etx);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("SignBLS: %f seconds\n", duration);

    start = clock();
    vertifyBLS(mtx, etx);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("VertifyBLS: %f seconds\n", duration); 

    return 0;
}