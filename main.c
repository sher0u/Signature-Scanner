#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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
    char *buffer = (char *)malloc(fileSize); // Allocate fileSize bytes
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation error");
        return;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Allocate memory for hexadecimal representation (twice the file size + 1 for null terminator)
    char *hexBuffer = (char *)malloc(2 * fileSize + 1); // Each byte represented by 2 characters, plus null terminator
    if (hexBuffer == NULL) {
        free(buffer);
        perror("Memory allocation error");
        return;
    }

    // Convert binary buffer to hexadecimal representation
    for (int i = 0; i < fileSize; i++) {
        sprintf(hexBuffer + 2 * i, "%02X", (unsigned char)buffer[i]); // Ensure correct interpretation of bytes
    }
    hexBuffer[2 * fileSize] = '\0'; // Null terminator

    // Make a copy of the signature to modify
    char *signatureCopy = strdup(signature);
    if (signatureCopy == NULL) {
        perror("Memory allocation error");
        free(buffer);
        free(hexBuffer);
        return;
    }

    // Convert input signature copy to uppercase
    for (int i = 0; i < signatureLength; i++) {
        signatureCopy[i] = toupper(signatureCopy[i]);
    }

    // Search for the signature in the hexadecimal buffer
    char *pos = strstr(hexBuffer, signatureCopy);
    if (pos != NULL) {
        printf("Signature found in file: %s\n", filename);
    } else {
        printf("Signature not found in file: %s\n", filename);
    }

    // Free allocated memory
    free(buffer);
    free(hexBuffer);
    free(signatureCopy);
}

int main() {
    char filename[100];
    char signature[MAX_SIGNATURE_LENGTH * 2 + 1]; // Each byte represented by 2 characters, plus null terminator

    // Input filename and signature from the user
    printf("Enter filename: ");
    if (scanf("%99s", filename) != 1) {
        printf("Invalid filename\n");
        return 1;
    }

    printf("Enter signature (up to 8 bytes in hexadecimal, without spaces): ");
    if (scanf("%16s", signature) != 1) {
        printf("Invalid signature\n");
        return 1;
    }

    // Calculate signature length
    int signatureLength = strlen(signature);

    // Search for the signature in the file
    searchSignature(filename, signature, signatureLength);

    return 0;
}
