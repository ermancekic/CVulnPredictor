#include <stdio.h>

void noControlStructure() {
    // empty
}

void ifControlStructure(int a) {
    if (a > 0) {
        printf("Positive number: %d\n", a);
    } else {
        printf("Non-positive number: %d\n", a);
    }
}

void switchControlStructure(int a) {
    switch (a) {
        case 1:
            printf("Case 1: %d\n", a);
            break;
        case 2:
            printf("Case 2: %d\n", a);
            break;
        default:
            printf("Default case: %d\n", a);
            break;
    }
}

void forControlStructure(int n) {
    for (int i = 0; i < n; i++) {
        printf("For loop iteration: %d\n", i);
    }
}

void whileControlStructure(int n) {
    int i = 0;
    while (i < n) {
        printf("While loop iteration: %d\n", i);
        i++;
    }
}

void doWhileControlStructure(int n) {
    int i = 0;
    do {
        printf("Do-while loop iteration: %d\n", i);
        i++;
    } while (i < n);
}

void doubleNestedForControlStructure(int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            printf("Double nested for loop iteration: i=%d, j=%d\n", i, j);
        }
    }
}

void tripleNestedMixedControlStructure(int n) {
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) {
            for (int j = 0; j < n; j++) {
                printf("Triple nested mixed control structure: i=%d, j=%d\n", i, j);
            }
        } else {
            while (i < n) {
                printf("Triple nested mixed control structure while: i=%d\n", i);
                i++;
            }
        }
    }
}

void twoNestedStructures(int n, int m) {
    for (int i = 0; i < n; i++) {
        while (i < m) {
            printf("Double nested mixed - for-while: i=%d\n", i);
            i++;
        }
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                for (int l = 0; l < n; l++) {
                    printf("Four-level nested loops: i=%d, j=%d, k=%d, l=%d\n", i, j, k, l);
                }
            }
        }
    }
}