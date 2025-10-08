#include <assert.h>

// Function using <stdio.h>
void test_stdio() {
    if (1) {
        assert(1 && "This should always be true");  
    }

    if (0) {
        assert(0 && "This should not trigger");
    }
}