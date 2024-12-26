#include <stdio.h>
#include <windows.h>

void close() {
    // User-defined close
}

int main() {
    close();              // User-defined function
    MessageBox(NULL, "Hello", "Title", MB_OK); // OS-specific
    printf("Hello, World!"); // Standard library
    return 0;
}
