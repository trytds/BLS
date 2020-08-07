#include <iostream>
#include <ctime>
#include "bls.h"

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
    vertifyBLS(etx);
    finish = clock();
    duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("VertifyBLS: %f seconds\n", duration);
}