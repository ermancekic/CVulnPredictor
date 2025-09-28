// Crafted functions to exercise maximum nesting level of control structures

int no_control(void) {
    int x = 0;
    x++;
    return x;
}

int one_if(int a) {
    if (a > 0) {
        a--;
    }
    return a;
}

int nested_if(int a, int b) {
    if (a > 0) {
        if (b > 0) {
            a--;
        }
    }
    return a + b;
}

int if_in_loop(int n) {
    for (int i = 0; i < n; i++) {
        if (i % 2) {
            while (n > 0) {
                n--;
                break;
            }
        }
    }
    return n;
}

int switch_with_if(int x) {
    switch (x) {
        case 1:
            if (x > 0) {
                x--;
            }
            break;
        default:
            break;
    }
    return x;
}

int else_if_chain(int x) {
    if (x == 0) {
        x = 1;
    } else if (x == 1) {
        x = 2;
    } else if (x == 2) {
        x = 3;
    } else {
        x = 4;
    }
    return x;
}

int loop_switch_if_nested(int n) {
    for (int i = 0; i < n; i++) {
        switch (i % 3) {
            case 0:
                if (n > 10) {
                    n--;
                }
                break;
            default:
                break;
        }
    }
    return n;
}

int triple_nested_loops_with_if(int n) {
    for (int i = 0; i < n; i++) {
        while (n > 0) {
            do {
                if (i % 2 == 0) {
                    n--;
                }
            } while (n > 0 && i < n);
            break;
        }
    }
    return n;
}

int nested_else_if(int n) {
    if (n > 0) {
        n = 12;
    } else if (n < 0) {
        if (n < -10) {
            n = 0;
        } else if (n < -5) {
            n = -1;
        } else {
            for (int i = 0; i < 3; i++) {
                n++;
            }
        }
    }
    return n;
}