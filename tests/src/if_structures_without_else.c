#include <stdio.h>

void ifWithoutElse(int x) {
    if (x > 0) {
        printf("x is positive\n");
    }
}

void ifElseWithoutElse(int x) {
    if (x > 0) {
        printf("x is positive\n");
    } else if (x < 0) {
        printf("x is negative\n");
    }
}

void ifWithElse() {
    int x = 10;
    if (x > 0) {
        printf("x is positive\n");
    } else {
        printf("x is not positive\n");
    }
}

void twoIfsWithoutElse(int x) {
    if (x > 0) {
        printf("x is positive\n");
    }
    if (x < 0) {
        printf("x is negative\n");
    }
}

void nestedIfsInIfElse(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            printf("x and y are positive\n");
        }
    } else {
        if (y < 0) {
            printf("x is not positive and y is negative\n");
        }
    }
}

void twoNestedIfsInIfElse(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            printf("x and y are positive\n");
        }
    } else {
        if (y < 0) {
            printf("x is not positive and y is negative\n");
        }
    }

    if (x > 0) {
        if (y > 0) {
            printf("x and y are positive\n");
        }
    } else {
        if (y < 0) {
            printf("x is not positive and y is negative\n");
        }
    }
}