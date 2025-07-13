#include <stdio.h>

void emptyMethod() {
    // empty
}

// Method with for loop
void forLoopExample() {
    for (int i = 0; i < 10; i++) {
        printf("For loop iteration: %d\n", i);
    }
}

// Method with while loop
void whileLoopExample() {
    int i = 0;
    while (i < 10) {
        printf("While loop iteration: %d\n", i);
        i++;
    }
}

// Method with do-while loop
void doWhileLoopExample() {
    int i = 0;
    do {
        printf("Do-while loop iteration: %d\n", i);
        i++;
    } while (i < 10);
}

// Method with range-based for loop
void rangeBasedForLoopExample() {
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    for (int element : arr) {
        printf("Range-based for loop element: %d\n", element);
    }
}

// Method with nested for loops
void nestedForLoopExample() {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            printf("Nested for loop: i=%d, j=%d\n", i, j);
        }
    }
}

// Method with nested while loops
void nestedWhileLoopExample() {
    int i = 0;
    while (i < 3) {
        int j = 0;
        while (j < 3) {
            printf("Nested while loop: i=%d, j=%d\n", i, j);
            j++;
        }
        i++;
    }
}

// Method with mixed nested loops (for inside while)
void mixedNestedLoopExample1() {
    int i = 0;
    while (i < 3) {
        for (int j = 0; j < 3; j++) {
            printf("Mixed nested (while-for): i=%d, j=%d\n", i, j);
        }
        i++;
    }
}

// Method with mixed nested loops (while inside for)
void mixedNestedLoopExample2() {
    for (int i = 0; i < 3; i++) {
        int j = 0;
        while (j < 3) {
            printf("Mixed nested (for-while): i=%d, j=%d\n", i, j);
            j++;
        }
    }
}

// Method with deeply nested loops (3 levels)
void deeplyNestedLoopExample() {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 2; k++) {
                printf("Deeply nested: i=%d, j=%d, k=%d\n", i, j, k);
            }
        }
    }
}

// Method with sequential loops (one after another)
void sequentialLoopsExample() {
    // First for loop
    for (int i = 0; i < 3; i++) {
        printf("First for loop: %d\n", i);
    }
    
    // Second while loop
    int j = 0;
    while (j < 3) {
        printf("Second while loop: %d\n", j);
        j++;
    }
    
    // Third do-while loop
    int k = 0;
    do {
        printf("Third do-while loop: %d\n", k);
        k++;
    } while (k < 3);
}
