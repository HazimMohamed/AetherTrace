#include <stdio.h>

// Function to compute the nth Fibonacci number
int fibonacci(int n) {
    if (n <= 1)
        return n;

    int a = 0, b = 1, temp;
    for (int i = 2; i <= n; i++) {
        temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

// Provide your own main
int main() {
    // This is a stub — since we can't print or return anything without includes,
    // you’d normally call this in a debugger or check the return value
    int result = fibonacci(10);

    // Return it as exit code (0–255 range)
    printf("%d\n", result);
}
