#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>

#define RANDOM1 {0}
#define RANDOM2 {1}
#define RANDOM3 {2}
#define RANDOM4 {3}
#define RANDOM5 {4}
#define RANDOM6 {5}
#define RANDOM7 {6}
#define RANDOM8 {7}
#define RANDOM9 {8}
#define RANDOM10 {9}
#define RANDOM11 {10}
#define RANDOM12 {11}
#define RANDOM13 {12}
#define RANDOM14 {13}
#define RANDOM15 {14}
#define RANDOM16 {15}
#define RANDOM17 {16}
#define RANDOM18 {17}
#define RANDOM19 {18}
#define RANDOM20 {19}

char dummy[RANDOM1];
unsigned char payload[1000];
int g_len;
{20} char dummy2[800];

void a0(){{ mprotect(0, 0, 0); }}
{21} void a1(){{ mmap(0, 0, 0, 0, 0, 0); }}
{22} void a2(){{ getuid(); }}
{23} void a3(){{ geteuid(); }}
{24} void a4(){{ printf(""); }}
{25} void a5(){{ getpid(); }}
{26} void a6(){{ getppid(); }}
{27} void a7(){{ close(10); }}
{28} void a8(){{ time(0); }}
{29} void a9(){{ dup(10); }}
{30} void a10(){{ dup2(10, 10); }}
{31} void a11(){{ getgid(); }}
{32} void a12(){{ personality(0); }}
{33} void a13(){{ setreuid(9, 9, 9); }}
{34} void a14(){{ setuid(9); }}
{35} void a15(){{ setgid(9); }}
{36} void a16(){{ nice(0); }}

void b0(){{
    int buf[RANDOM4];
    memcpy((char*)buf, &payload[48], g_len-48);
}}

void b1(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM5 ) b0(); }}
void b2(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM6 ) b1(payload[45], payload[46], payload[47]); }}
void b3(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM7 ) b2(payload[42], payload[43], payload[44]); }}
void b4(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM8 ) b3(payload[39], payload[40], payload[41]); }}
void b5(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM9 ) b4(payload[36], payload[37], payload[38]); }}
void b6(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM10 ) b5(payload[33], payload[34], payload[35]); }}
void b7(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM11 ) b6(payload[30], payload[31], payload[32]); }}
void b8(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM12 ) b7(payload[27], payload[28], payload[29]); }}
void b9(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM13 ) b8(payload[24], payload[25], payload[26]); }}
void b10(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM14 ) b9(payload[21], payload[22], payload[23]); }}
void b11(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM15 ) b10(payload[18], payload[19], payload[20]); }}
void b12(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM16 ) b11(payload[15], payload[16], payload[17]); }}
void b13(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM17 ) b12(payload[12], payload[13], payload[14]); }}
void b14(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM18 ) b13(payload[9], payload[10], payload[11]); }}
void b15(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM19 ) b14(payload[6], payload[7], payload[8]); }}
void b16(unsigned char a, unsigned char b, unsigned char c){{ if( RANDOM20 ) b15(payload[3], payload[4], payload[5]); }}

int z(long int a, long int b, long int c, long int d, long int e, long int f){{
    int buf[RANDOM4];
    return 0;
}}
int zz(long int a, long int b, long int c, long int d, long int e, long int f){{
    int buf[RANDOM4];
    int r=z(a, c, b, e, f, d);
    return r;
}}

int main(int argc, char* argv[]){{
    if(argc!=2){{
        printf("usage : ./aeg [hex encoded payload]\n");
        return 0;
    }}

    srand(zz(1, 2, 3, 4, 5, 6));

    g_len = strlen(argv[1])/2;
    if(g_len>1000){{
        printf("payload length exceeds 1000byte\n");
        return 0;
    }}

    char tmp[3];
    int k, n;
    for(k=0, n=0; k<g_len*2; k+=2){{
        tmp[0]=argv[1][k];
        tmp[1]=argv[1][k+1];
        tmp[2]=0;
        sscanf(tmp, "%02x", &payload[n++]);
    }}

    int a, b, c;
    int i;
    for(i=0; i<g_len; i++){{
        {20} if(RANDOM9){{ b=a++; }}
        {21} if(RANDOM16){{ c=b++; }}
        {22} if(RANDOM7){{ a=c++; }}
        if((i%2)==0) payload[i] = payload[i] ^ RANDOM2;
        else payload[i] = payload[i] ^ RANDOM3;
        {23} if(RANDOM18){{ a=b+c; }}
        {24} if(RANDOM9){{ b=a-c; }}
        {25} if(RANDOM10){{ c=++a; }}
    }}

    printf("payload encoded. let's go!\n");

    b16(payload[0], payload[1], payload[2]);

    printf("end of program\n");
    return 0;
}}
