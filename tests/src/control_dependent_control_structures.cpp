// Minimal C++ fixture to cover CXX_FOR_RANGE_STMT cases

void rangeForOnly() {
    int arr[3] = {1, 2, 3};
    for (int x : arr) {
        (void)x; // no inner control
    }
}

void rangeForWithIf() {
    int arr[3] = {1, 2, 3};
    for (int x : arr) {
        if (x > 0) {
            // no-op
        }
    }
}

