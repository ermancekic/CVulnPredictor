#include <stddef.h>

// Binary pointer arithmetic operations
void binaryPlus() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ptr = ptr + 2;  // 1 operation
    ptr = ptr + 1;  // 1 operation
    ptr = 3 + ptr;  // 1 operation
}

void binaryMinus() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ptr = ptr - 2;  // 1 operation
    ptr = ptr - 1;  // 1 operation
}

void compoundAssignment() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ptr += 2;  // 1 operation
    ptr -= 1;  // 1 operation
}

void unaryIncrement() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ++ptr;  // 1 operation
    ptr++;  // 1 operation
}

void unaryDecrement() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    --ptr;  // 1 operation
    ptr--;  // 1 operation
}

void noPointerOps() {
    int a = 5;
    int b = 10;
    int c = a + b;  // not a pointer operation
}

void nestedOperations() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ptr = (ptr + 1);  // 1 operation
}

void pointerArithmeticInLoop() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    for (int i = 0; i < 3; i++) {
        ptr++;  // 1 operation
    }
}

void doubleNestedPointerArithmetic() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    ptr = (ptr + 1) + 1;  // 1 operation
}

void pointerDifference() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr1 = arr;
    int *ptr2 = arr + 4;
    
    ptrdiff_t diff = ptr2 - ptr1;  // 1 operation
}