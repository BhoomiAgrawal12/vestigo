
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[256];
    int result = 0;
    
    // Simulate waiting for network data
    printf("Waiting for data...\n");
    
    // This would normally block on recv()
    // In harness, this will be injected
    
    // Simulate processing
    for (int i = 0; i < 10; i++) {
        result += i;
    }
    
    printf("Processing complete: %d\n", result);
    return 0;
}
