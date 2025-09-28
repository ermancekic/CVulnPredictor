// Fixture for lines-of-code metric tests

void empty(void) {}

int simple()
{
    // single-line comment
    int a = 1;   // trailing comment
    /* block comment on its own */

    a += 2;
    return a; // another trailing comment
}

#define M(a) a = (a) + 1

int with_macro(int x)
{
    M(x);
    return x;
}

void empty_block_lines(void)
{
}

int comments_and_blanks(void)
{
    /* multi-line
       block comment */

    // single-line comment
    return 0;
}

#define INC2(x) do { \
    (x)++;           \
    (x)++;           \
} while(0)

int with_multiline_macro(int x)
{
    INC2(x);
    return x;
}

int only_semicolons(void)
{
    ;
    ;
    ;
    return 0;
}
