#include <stdio.h>

void oneUnaryPointer(int *ptr) {
    ptr++;
}

void twoUnaryPointers(int *ptr1, int *ptr2) {
    ptr1++;
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
    ptr1 = ptr1 + 1;
    ptr2 = ptr2 + 1;
}

void threeBinaryPointers(int *ptr1, int *ptr2, int *ptr3) {
    ptr1 = ptr1 + 1;
    ptr2 = ptr2 + 2;
    ptr3 = ptr3 + 3;
}

void mixedPointerOperations(int *ptr1, int *ptr2) {
    ptr1++;
    ptr2 = ptr2 + 2;
    ++ptr1;
    ptr2 += 3;
}

void pointerArithmetic(int *base, int offset) {
    int *result = base + offset;
    *result = 42;
    result -= 2;
}

