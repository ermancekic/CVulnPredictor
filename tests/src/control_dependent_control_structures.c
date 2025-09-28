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

void nestedControlStructure(int a) {
    if (a > 0) {
        printf("Positive number: %d\n", a);
        if (a > 10) {
            printf("And greater than 10: %d\n", a);
        }
    } else {
        printf("Non-positive number: %d\n", a);
    }
}

void manyNestedControlStructure(int a) {
    if (a > 0) {
        if (a > 10) {
            if (a > 20) {
                printf("Number is greater than 20: %d\n", a);
            } else {
                printf("Number is between 11 and 20: %d\n", a);
            }
        }
    }

    if (a > 0) {
        if (a > 10) {
            if (a > 20) {
                for (int i = 0; i < a; i++) {
                    printf("Looping with i: %d\n", i);
                }
            }
        }
    }
}

void manyNestedLoopControlStructure(int a) {
    if (a > 0) {
        for (int i = 0; i < a; i++) {
            printf("Outer loop iteration: %d\n", i);
            for (int j = 0; j < a; j++) {
                printf("Inner loop iteration: %d, %d\n", i, j);
                if (j % 2 == 0) {
                    printf("Even inner index: %d\n", j);
                }
            }
        }
    }

    while(a > 0) {
        if (a > 10) {
            printf("While loop with condition met: %d\n", a);
        } else {
            printf("While loop with condition not met: %d\n", a);
        }

        for (int i = 0; i < a; i++) {
            if (i % 2 == 0) {
                printf("For loop with even index: %d\n", i);
            } else {
                printf("For loop with odd index: %d\n", i);
            }
        }

        if (a > 5) {
            printf("Decrementing a: %d\n", a);
            a--;
        } else {
            printf("Breaking out of while loop: %d\n", a);
            break;
        }
    }
}

void manyIfStatements(){
    if (1) {

    }

    if (1){
        if (2){

        }
    }

    if (1) {
        if (2) {
            if (3) {

            }
        }
    }

    if (1) {
        if (2) {
            if (3) {
                if (4) {

                }
            }
        }
    }

    if (1) {
        if (2) {
            if (3) {
                if (4) {
                    if (5) {

                    }
                }
            }
        }

        if (2) {
            if (3) {
                if (4) {
                    if (5) {

                    }
                }
            }
        }
    }
}

void ifElseControlStructure(int a) {
    if (a > 0) {
        if (a % 2 == 0) {
            printf("Positive even number: %d\n", a);
        } else {
            printf("Positive odd number: %d\n", a);
        }
    } else {
        if (a < 0) {
            printf("Negative number: %d\n", a);
        } else {
            printf("Zero: %d\n", a);
        }
    }
}

// Added cases to cover SWITCH_STMT and DO_STMT for the
// maximum of control-dependent control structures metric
void switchOnly(int a) {
    switch (a) {
        case 0:
            printf("zero\n");
            break;
        case 1:
            printf("one\n");
            break;
        default:
            printf("other\n");
            break;
    }
}

void switchWithIf(int a) {
    switch (a) {
        case 0:
            if (a >= 0) {
                printf("non-negative\n");
            }
            break;
        default:
            break;
    }
}

void doWhileWithIf(int a) {
    do {
        if (a > 0) {
            a--;
        }
    } while (a > 0);
}
