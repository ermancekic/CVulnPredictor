#include <stdio.h>

void noControlStructure() {
    // empty
}

void oneIfControlStructure(int a) {
    if (a > 0) {
        printf("a is positive: %d\n", a);
    }
}

void threeTimeUse(int a){
    if(a > 0) {}
    if(a == 0) {}
    
    while (a > 0) {
        printf("a is positive: %d\n", a);
        a--;
    }
}

void manyVariables(int a, int b, int c) {
    if (a > 0) {
        printf("a is positive: %d\n", a);
    } else if (a < 0) {
        printf("a is negative: %d\n", a);
    } else {
        printf("a is zero\n");
    }

    for (int i = 0; i < b; i++) {
        printf("Loop iteration %d of %d\n", i, b);
    }

    while (c > 0) {
        c--;
    }

    if (a > b && b > c) {
        printf("a > b > c\n");
    } else if (a == b) {
        printf("a equals b: %d\n", a);
    }

    switch (a) {
        case 1:
            printf("a is 1\n");
            break;
        case 2:
            if (b > 0) {
                printf("a is 2 and b is positive\n");
            }
            break;
        default:
            printf("a is neither 1 nor 2\n");
    }

    for (int i = 0; i < a; i++) {
        if (i % b == 0) {
            printf("%d is divisible by %d\n", i, b);
        }
    }
}

