#include <stdio.h>

void oneVariableInControlPredicate(int x) {
    if (x > 0) {
        printf("x is positive\n");
    }
}

void twoVariablesInControlPredicate(int x, int y) {
    if (x > 0 && y > 0) {
        printf("x and y are positive\n");
    }
}

void threeVariablesInControlPredicate(int x, int y, int z) {
    if (x > 0 && y > 0 && z > 0) {
        printf("x, y, and z are positive\n");
    }
}

void fourVariablesInControlPredicate(int x, int y, int z, int w) {
    if (x > 0 && y > 0 && z > 0 && w > 0) {
        printf("x, y, z, and w are positive\n");
    }
}

void threeVariablesSeparateIfs(int x, int y, int z) {
    if (x > 0) {
        if (y > 0) {
            if (z > 0) {
                printf("x, y, and z are positive\n");
            }
        }
    }
}

void fourVariablesSeparateIfs(int x, int y, int z, int w) {
    if (x > 0) {
        if (y > 0) {
            if (z > 0) {
                if (w > 0) {
                    printf("x, y, z, and w are positive\n");
                }
            }
        }
    }
}

void twoVariablesSeparateIfs(int x, int y) {
    if (x > 0) {

    }

    if (y > 0) {
        printf("x and y are positive\n");
    }
}

void fourVariablesSeparateIfs(int x, int y, int z, int w) {
    if (x > 0) {
        if (y > 0) {

        }
    }

    if (z > 0) {
        if (w > 0) {
            printf("x, y, z, and w are positive\n");
        }
    }
}