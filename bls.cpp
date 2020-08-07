#include <iostream>


#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256

#include "pairing_3.h"
PFC pfc(AES_SECURITY);  // ��ʼ��˫���Զ�����
Big s; //˽Կ 
/*��Ϊ����p�ĳ˷�ѭ��Ⱥ*/
G1 S, R; 
G2 Q, V;  
Big X; 

//��˽Կ����
void keygenBLS()
{
    // Create system-wide G2 constant
    pfc.random(Q);

    pfc.random(s);    // ˽Կ
    printf("privatekey: %d\n", s);
    V = pfc.mult(Q, s);  // ��Կ
    printf("publickey: %d\n", V);
}

/*BLSǩ��*/
void signBLS(unsigned char* plain, int* lsb)
{
    //����Ϣ�����߹�ϣH(m)
    pfc.hash_and_map(R, (char*)plain); 
    S = pfc.mult(R, s); //��Ϣ�Ĺ�ϣ�������˽Կ����ǩ��

    *lsb = S.g.get(X);   // ǩ�������������һ����

    cout << "Signature= " << lsb << " " << X << endl;
}

/*��֤BLSǩ��*/
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
     //��֤��Կ����Ϣ�Ĺ�ϣֵ,���������ɵ��ǩ��,�Ƿ�ӳ�䵽ͬһ����
    if (pfc.multi_pairing(2, g2, g1) == 1)
        cout << "Signature verifies" << endl;
    else
        cout << "Signature is bad" << endl;
}

