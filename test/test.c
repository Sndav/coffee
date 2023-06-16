void println(char *buf);
void debugln(char *buf);
void hello_world();


int test_func_call(unsigned char *buf){
    println(buf);
    return 0;
}

int main(){
    char *buf = "Hello World!";
    debugln(buf);
    hello_world();
    return 1;
}