#include <stdio.h>

// No control flow
void noControl(void) {
    int x = 0;
    x += 1;
    printf("x=%d\n", x);
}

// do-while once
void doWhileOnce(int x) {
    do {
        x++;
    } while (x < 0);
}

// nested do-while
void doWhileNested(int x) {
    do {
        do {
            x--;
        } while (x > 0);
        x += 2;
    } while (x < 10);
}

// single ternary operator
int conditionalSimple(int a) {
    int y = (a > 0) ? 1 : 2;
    return y;
}

// nested ternary operator
int conditionalNested(int a, int b) {
    int y = a ? 1 : (b ? 2 : 3);
    return y;
}

// switch with fallthrough between two cases
int switchFallthrough(int x) {
    int y = 0;
    switch (x) {
        case 1:
        case 2:
            y = 1;
            break;
        default:
            y = 0;
            break;
    }
    return y;
}

// complex boolean condition does not add extra decisions
int ifComplexCond(int a, int b, int c) {
    int y = 0;
    if ((a && b) || c) {
        y = 1;
    }
    return y;
}

// else-if chain with three conditions
int elseIfChain3(int v) {
    if (v < 0) {
        return -1;
    } else if (v == 0) {
        return 0;
    } else if (v == 1) {
        return 1;
    } else {
        return 2;
    }
}

// Mixed constructs to exercise counting
int mixAll(int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) {           // +1
        acc += i;
    }
    int j = 0;
    while (j < n) {                          // +1
        j++;
    }
    int k = 0;
    do {                                     // +1
        k++;
    } while (k < 3);

    if (n % 2 == 0) {                        // +1
        acc += 10;
    }

    switch (n & 3) {                         // +2 (two case labels)
        case 0:
            acc += 1;
            break;
        case 1:
            acc += 2;
            break;
        default:
            break;
    }

    acc += (n > 5) ? 1 : 0;                  // +1
    return acc;
}

