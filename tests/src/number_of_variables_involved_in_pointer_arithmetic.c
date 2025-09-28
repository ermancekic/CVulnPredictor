#include <stddef.h>

typedef struct { int m; } S;

void oneUnaryPointer(int *ptr) {
    ptr++;
}

void twoUnaryPointers(int *ptr1, int *ptr2) {
    ptr1++;
    ptr2++;
}

void threeUnaryPointers(int *ptr1, int *ptr2, int *ptr3) {
    ptr1++;
    ptr2++;
    ++ptr3;
}

void oneBinaryPointer(int *ptr1) {
    ptr1 = ptr1 + 1;
}

void twoBinaryPointers(int *ptr1, int *ptr2) {
    ptr1 = ptr1 + 1;
    ptr2 = ptr2 + 1;
}

void threeBinaryPointers(int *ptr1, int *ptr2, int *ptr3) {
    ptr1 = ptr1 + 1;
    ptr2 = ptr2 + 1;
    ptr3 = ptr3 + 1;
}

void mixedUnaryBinary(int *ptr1, int *ptr2) {
    ptr1++;
    ptr2 = ptr2 + 2;
}

void pointerWithOffset(int *base, int offset) {
    int *result = base + offset;
}

void pointerCompoundAssignment(int *ptr) {
    ptr += 5;
}

void pointerDecrement(int *ptr) {
    ptr--;
}

void pointerDifference() {
    int arr[] = {1, 2, 3, 4, 5};
    int *ptr1 = arr;
    int *ptr2 = arr + 4;
    
    ptrdiff_t diff = ptr2 - ptr1;  // 1 operation
}

void pointerAssignment_no_arith(int *p, int *q) {
    // Simple pointer-to-pointer assignment is not arithmetic
    p = q;
}

void pointerCast_no_arith(int *p) {
    // Casting a pointer type is not arithmetic
    void *v = (void*)p;
    (void)v;
}

void pointerAddressOf_no_arith() {
    // Taking the address of a variable is not pointer arithmetic
    int x = 0;
    int *p = &x;
    (void)p;
}

void pointerDereference_no_arith(int *p) {
    // Dereferencing a pointer is not arithmetic
    int x = *p;
    (void)x;
}

void pointerCompare_no_arith(int *p, int *q) {
    // Comparing pointers is not arithmetic
    if (p == q) {
        // no-op
    }
}

void notPointerTypes_no_arith() {
    // Integer arithmetic should not be counted for pointer metrics
    int a = 1, b = 2;
    int c = a + b;
    (void)c;
}

// Member access via pointer: only the base pointer variable should be counted
void pointerMemberAccess_vars() {
    S s; S *p = &s;
    int x = p->m;  // involves pointer variable p
    p->m = x;      // involves pointer variable p
}

// Dot access (non-pointer) should not contribute
void structMemberDotNoArith_vars() {
    S s;
    int x = s.m;
    s.m = x;
}
