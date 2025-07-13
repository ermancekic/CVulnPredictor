#include <stdio.h>

void emptyMethod() {
    // empty
}

void singleLoop() {
    for (int i = 0; i < 10; i++) {
        printf("Single loop iteration %d\n", i);
    }
}

void doubleNestedLoop() {
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 3; j++) {
            printf("Double nested: i=%d, j=%d\n", i, j);
        }
    }
}

void tripleNestedLoop() {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 2; k++) {
                printf("Triple nested: i=%d, j=%d, k=%d\n", i, j, k);
            }
        }
    }
}

void mixedNestedLoops() {
    for (int i = 0; i < 3; i++) {
        while (i < 2) {
            int j = 0;
            do {
                printf("Mixed loops: i=%d, j=%d\n", i, j);
                j++;
            } while (j < 2);
            break;
        }
    }
}

void whileNestedLoop() {
    int i = 0;
    while (i < 3) {
        int j = 0;
        while (j < 2) {
            printf("While nested: i=%d, j=%d\n", i, j);
            j++;
        }
        i++;
    }
}

void doWhileNestedLoop() {
    int i = 0;
    do {
        int j = 0;
        do {
            printf("Do-while nested: i=%d, j=%d\n", i, j);
            j++;
        } while (j < 2);
        i++;
    } while (i < 3);
}

void sequentialNestedLoops() {
    // First nested section
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            printf("First nested section: i=%d, j=%d\n", i, j);
        }
    }
    
    // Second nested section
    for (int x = 0; x < 3; x++) {
        for (int y = 0; y < 2; y++) {
            for (int z = 0; z < 2; z++) {
                printf("Second nested section: x=%d, y=%d, z=%d\n", x, y, z);
            }
        }
    }
    
    // Third nested section
    int a = 0;
    while (a < 2) {
        int b = 0;
        do {
            printf("Third nested section: a=%d, b=%d\n", a, b);
            b++;
        } while (b < 2);
        a++;
    }
}

void deeplyNestedSequential() {
    // First deep nesting
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 2; k++) {
                for (int l = 0; l < 2; l++) {
                    printf("Deep nest 1: i=%d, j=%d, k=%d, l=%d\n", i, j, k, l);
                }
            }
        }
    }
    
    // Second deep nesting
    for (int a = 0; a < 2; a++) {
        while (a < 1) {
            for (int b = 0; b < 2; b++) {
                int c = 0;
                do {
                    printf("Deep nest 2: a=%d, b=%d, c=%d\n", a, b, c);
                    c++;
                } while (c < 2);
            }
            break;
        }
    }
}