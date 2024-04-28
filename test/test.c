#include<stdio.h>


int test_func_call(unsigned char *buf){
    puts(buf);
    return 0;
}

int go(){
    char *buf = "Hello World!";
    test_func_call(buf)
    return 1;
}