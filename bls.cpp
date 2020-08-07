#include <iostream>
#include <ctime>

#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256

#include "pairing_3.h"
PFC pfc(AES_SECURITY);  // ��ʼ��˫���Զ�����
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

/*BLSǩ��*/
void signBLS(unsigned char* plain, int* lsb)
{
    //�Դ�ǩ����Ϣ����Hash���� ���ɽ��
    pfc.hash_and_map(R, (char*)plain); //��ǩ����Ϣ����У��
    S = pfc.mult(R, s);

    *lsb = S.g.get(X);   // signature is lsb bit and X

    cout << "Signature= " << lsb << " " << X << endl;
}

/*��֤BLSǩ��*/
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
     //�������ǩ���Ƚ�
    if (pfc.multi_pairing(2, g2, g1) == 1)
        cout << "Signature verifies" << endl;
    else
        cout << "Signature is bad" << endl;
}

int main()
{
    clock_t start, finish;
    double duration;

    unsigned char tx[5000] = "Be there or be square!"; //��ǩ������
    int etx[4000]; //ǩ����Ϣ
    unsigned char mtx[5000] = "0"; //����
    
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