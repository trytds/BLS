/*
   Boneh-Lynn-Shacham short signature

   Compile with modules as specified in the selected header file

   For MR_PAIRING_CP curve
   cl /O2 /GX bls.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
   (Note this really doesn't make much sense as the signature will not be "short")

   For MR_PAIRING_MNT curve
   cl /O2 /GX bls.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BN curve
   cl /O2 /GX bls.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX bls.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX bls.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   Test program
*/

#include <iostream>
#include <ctime>

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security   
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

//#define MR_PAIRING_BN    // AES-128 or AES-192 security
//#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256
//*********************************************

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
	printf("privatekey: %d\n", s);
	V = pfc.mult(Q, s);  // public key
	printf("publickey: %d\n", V);

}

void signBLS(unsigned char *plain,int *lsb)
{
    //G1 S, R;
    //Big X;
    pfc.hash_and_map(R, (char*)plain);
    S = pfc.mult(R, s);

    *lsb = S.g.get(X);   // signature is lsb bit and X

    cout << "Signature= " << lsb << " " << X << endl;
}

void vertifyBLS(unsigned char *plain, int *lsb)
{
    if (!S.g.set(X, 1 - *lsb))
    {
        cout << "Signature is invalid" << endl;
        exit(0);
    }
    pfc.hash_and_map(R, (char*)plain);


    // Observe that Q is a constant
    // Interesting that this optimization doesn't work for the Tate pairing, only the Ate

    pfc.precomp_for_pairing(Q);

    G1* g1[2];
    G2* g2[2];
    g1[0] = &S; g1[1] = &R;
    g2[0] = &Q; g2[1] = &V;

    if (pfc.multi_pairing(2, g2, g1) == 1)
        cout << "Signature verifies" << endl;
    else
        cout << "Signature is bad" << endl;
}

int main()
{
    unsigned char tx[5000] = "Be there or be square!"; //待签名明文
    int etx[4000]; //签名信息
    unsigned char mtx[5000] = "0"; //解密
	keygenBLS();
    signBLS(tx,etx);
    vertifyBLS(mtx,etx);
	return 0;
}