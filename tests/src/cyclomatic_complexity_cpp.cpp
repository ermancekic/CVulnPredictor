// Minimal C++ cases to validate catch counting and mixed constructs

void tryOneCatch() {
    try {
        int x = 0; (void)x;
    } catch (...) {
        // handle
    }
}

void tryTwoCatches() {
    try {
        // work
    } catch (int) {
        // handle int
    } catch (...) {
        // fallback
    }
}

void tryCatchWithIf(int a) {
    try {
        // work
    } catch (...) {
        if (a > 0) { // adds +1
            a--;
        }
    }
}

