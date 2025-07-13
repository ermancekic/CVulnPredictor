#include <stdio.h>

void noParameterVariable() {
    // empty
}

void oneParameterVariable(int a) {
    printf("Parameter variable: %d\n", a);
}

void twoParameterVariables(int a, int b) {
    printf("Parameter variables: %d, %d\n", a, b);
}

void threeParameterVariables(int a, int b, int c) {
    printf("Parameter variables: %d, %d, %d\n", a, b, c);
}

void fourParameterVariables(int a, int b, int c, int d) {
    printf("Parameter variables: %d, %d, %d, %d\n", a, b, c, d);
}