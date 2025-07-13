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

void thirteenNestedLoops() {
    for (int i = 0; i < 2; i++) {
        int j = 0;
        while (j < 2) {
            int k = 0;
            do {
                for (int l = 0; l < 2; l++) {
                    int m = 0;
                    while (m < 2) {
                        for (int n = 0; n < 2; n++) {
                            int o = 0;
                            do {
                                for (int p = 0; p < 2; p++) {
                                    int q = 0;
                                    while (q < 2) {
                                        for (int r = 0; r < 2; r++) {
                                            int s = 0;
                                            do {
                                                for (int t = 0; t < 2; t++) {
                                                    int u = 0;
                                                    while (u < 2) {
                                                        printf("13 nested loops: i=%d, j=%d, k=%d, l=%d, m=%d, n=%d, o=%d, p=%d, q=%d, r=%d, s=%d, t=%d, u=%d\n", 
                                                               i, j, k, l, m, n, o, p, q, r, s, t, u);
                                                        u++;
                                                    }
                                                }
                                                s++;
                                            } while (s < 2);
                                        }
                                        q++;
                                    }
                                }
                                o++;
                            } while (o < 2);
                        }
                        m++;
                    }
                }
                k++;
            } while (k < 2);
            j++;
        }
    }
}