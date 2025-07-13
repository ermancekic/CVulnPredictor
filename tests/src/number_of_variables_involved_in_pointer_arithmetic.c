#include <stdio.h>
#include <stddef.h>

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