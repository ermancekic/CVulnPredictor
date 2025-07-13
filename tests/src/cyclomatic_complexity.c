#include <stdio.h>

// Method with for loop
void forLoopMethod() {
    for (int i = 0; i < 10; i++) {
        printf("For loop iteration: %d\n", i);
    }
}

// Method with while loop
void whileLoopMethod() {
    int count = 0;
    while (count < 5) {
        printf("While loop count: %d\n", count);
        count++;
    }
}

// Method with if cases
void ifCasesMethod(int value) {
    if (value > 0) {
        printf("Value is positive\n");
    } else if (value < 0) {
        printf("Value is negative\n");
    } else {
        printf("Value is zero\n");
    }
}

// Method with switch cases
void switchCasesMethod(int option) {
    switch (option) {
        case 1:
            printf("Option 1 selected\n");
            break;
        case 2:
            printf("Option 2 selected\n");
            break;
        case 3:
            printf("Option 3 selected\n");
            break;
        default:
            printf("Invalid option\n");
            break;
    }
}

// Method with nested loops
void nestedLoopsMethod() {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            printf("Nested loop: i=%d, j=%d\n", i, j);
        }
    }
}

// Method with nested if statements
void nestedIfMethod(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            printf("Both x and y are positive\n");
        } else {
            printf("x is positive, y is not\n");
        }
    } else {
        if (y > 0) {
            printf("y is positive, x is not\n");
        } else {
            printf("Both x and y are non-positive\n");
        }
    }
}

// Method with nested switch in if
void nestedSwitchInIfMethod(int condition, int option) {
    if (condition > 0) {
        switch (option) {
            case 1:
                printf("Condition true, option 1\n");
                break;
            case 2:
                printf("Condition true, option 2\n");
                break;
            default:
                printf("Condition true, invalid option\n");
                break;
        }
    } else {
        printf("Condition false\n");
    }
}

// Method with loop containing if statements
void loopWithIfMethod(int limit) {
    for (int i = 0; i < limit; i++) {
        if (i % 2 == 0) {
            printf("Even number: %d\n", i);
        } else if (i % 3 == 0) {
            printf("Odd multiple of 3: %d\n", i);
        } else {
            printf("Other odd number: %d\n", i);
        }
    }
}

// Method with sequential control structures
void sequentialControlMethod(int value, int limit) {
    // First: if-else chain
    if (value < 0) {
        printf("Value is negative\n");
    } else if (value == 0) {
        printf("Value is zero\n");
    } else {
        printf("Value is positive\n");
    }
    
    // Then: for loop
    for (int i = 0; i < limit; i++) {
        printf("Sequential for loop: %d\n", i);
    }
    
    // Then: while loop
    int counter = 0;
    while (counter < 3) {
        printf("Sequential while loop: %d\n", counter);
        counter++;
    }
    
    // Finally: switch statement
    switch (value % 4) {
        case 0:
            printf("Remainder 0\n");
            break;
        case 1:
            printf("Remainder 1\n");
            break;
        case 2:
            printf("Remainder 2\n");
            break;
        default:
            printf("Remainder 3\n");
            break;
    }
}