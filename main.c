#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIGNATURE_LENGTH 8

// Function to search for a signature in a file
void searchSignature(const char *filename, const char *signature, int signatureLength) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Get file size for better efficiency
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read the entire file into a buffer
    char *buffer = (char *)malloc(fileSize);
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation error");
        return;
    }

    fread(buffer, sizeof(char), fileSize, file);
    fclose(file);

    // Search for the signature in the hexadecimal representation
    char *hexBuffer = (char *)malloc(2 * fileSize + 1); // Each byte represented by 2 characters, plus null terminator
    if (hexBuffer == NULL) {
        free(buffer);
        perror("Memory allocation error");
        return;
    }

    // Convert binary buffer to hexadecimal representation
    for (int i = 0; i < fileSize; i++) {
        sprintf(hexBuffer + 2 * i, "%02X", buffer[i]);
    }
    hexBuffer[2 * fileSize] = '\0'; // Null terminator

    // Search for the signature in the hexadecimal buffer
    char *pos = strstr(hexBuffer, signature);
    if (pos != NULL) {
        printf("Signature found in file: %s\n", filename);
        printf("Offset in hexadecimal: %s\n", pos - hexBuffer);
    } else {
        printf("Signature not found in file: %s\n", filename);
    }

    // Free allocated memory
    free(buffer);
    free(hexBuffer);
}

int main() {
    char filename[100];
    char signature[MAX_SIGNATURE_LENGTH * 3]; // Allow for spaces between bytes

    // Input filename and signature from the user
    printf("Enter filename: ");
    scanf(" %[^\n]%*c", filename); // Read the entire line including spaces

    printf("Enter signature (up to 8 bytes in hexadecimal, separated by spaces): ");
    scanf(" %[^\n]%*c", signature); // Read the entire line including spaces

    // Remove any spaces from the signature
    char *ptr = signature;
    while (*ptr) {
        if (*ptr == ' ') {
            strcpy(ptr, ptr + 1);
        } else {
            ptr++;
        }
    }

    // Calculate signature length
    int signatureLength = strlen(signature) / 2; // Each byte represented by 2 characters

    // Search for the signature in the file
    searchSignature(filename, signature, signatureLength);

    return 0;
}
