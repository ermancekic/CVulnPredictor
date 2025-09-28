#include <stddef.h>

typedef struct { int m; } S;

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

void pointerAssignmentNoArith() {
    int arr[] = {1, 2, 3, 4, 5};
    int *p = arr;        // assignment without arithmetic
    int *q = p;          // pointer copy
}

void pointerComparisonNoArith() {
    int arr[] = {1, 2, 3, 4, 5};
    int *p = arr;
    int *q = p;           // no arithmetic here
    if (p == q) {}
    if (p != q) {}
    if (p < q) {}
}

void addressOfNoArith() {
    int a = 42;
    int *p = &a;         // taking address is not arithmetic
}

void dereferenceNoArith() {
    int a = 0;
    int *p = &a;
    *p = 5;              // dereference store, no arithmetic
}

void arrayIndexingNoArith() {
    int arr[] = {1, 2, 3, 4, 5};
    int *p = arr;
    int x = arr[2];      // indexing is not counted as arithmetic here
    p[1] = 7;            // likewise
}

void pointerCastNoArith() {
    int arr[] = {1, 2, 3};
    int *p = arr;
    char *cp = (char *)p;  // cast only, no arithmetic
    (void)cp;
}

// Member access via pointer (should be counted)
void pointerMemberAccess() {
    S s; S *p = &s;
    int x = p->m;  // 1 operation (->)
    p->m = x;      // 1 operation (->)
}

// Member access with dot (not via pointer) should NOT be counted
void structMemberDotNoArith() {
    S s;
    int x = s.m;   // not pointer arithmetic
    s.m = x;       // not pointer arithmetic
}
