#include <stdio.h>
#include <stdlib.h>

unsigned char func(unsigned char a, unsigned char b){
    unsigned char c;
    c = a * b;    
    return c;
}


unsigned char start_func(unsigned char x) {
    unsigned char y[3];
    unsigned char x_shift;
    for (int i = 0; i < 3; i++) {
        x_shift = (x << i);
        y[i] = func(x_shift, 10);
    }

    return y;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <byte_value>\n", argv[0]);
        return 1;
    }

    unsigned char sec = (unsigned char)atoi(argv[1]);
    unsigned char y = start_func(sec);
    
    int c = func(sec, 14);
    printf("= %d\n", c);
    return 0;
}
