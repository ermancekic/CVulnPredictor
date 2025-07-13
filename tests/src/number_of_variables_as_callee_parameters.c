#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef struct {
    int  a;
    float b;
    char *name;
} MyStruct;

void callee_no_args(void) {
    // nichts
}

void callee_one_arg(int x) {
    printf("x = %d\n", x);
}

void callee_two_args(int x, const char *s) {
    printf("x = %d, s = %s\n", x, s);
}

void callee_struct_field(int *p, float f) {
    *p += (int)f;
}

int  callee_returning(int x) {
    return x * 2;
}

void test_simple(int v) {
    callee_one_arg(v);
}

void test_repeated(int v1, int v2) {
    callee_two_args(v1, "Hello");
    callee_two_args(v2, "World");
    callee_two_args(v1, "Again");
}

void test_locals(void) {
    int lv = 42;
    callee_two_args(lv, "Test");
    callee_one_arg(100);
}

void test_struct_field(MyStruct *structParam) {
    callee_struct_field(&structParam->a, structParam->b);
    callee_two_args(structParam->a, structParam->name);
}

void test_nested_calls(int v1, int v2) {
    int result = callee_returning(v1) + v2;
    callee_one_arg(result);
}

void test_complex(MyStruct *structParam, int v) {
    int tmp = callee_returning(callee_returning(v));
    callee_struct_field(&structParam->a, (float) tmp);
    callee_one_arg(v);
    callee_struct_field(&structParam->a, structParam->b);
}

int main(void) {
    MyStruct s = { .a = 5, .b = 3.14f, .name = "TestStruct" };
    test_simple(10);
    test_repeated(1, 2);
    test_locals();
    test_struct_field(&s);
    test_nested_calls(4, 6);
    test_complex(&s, 7);
    return 0;
}