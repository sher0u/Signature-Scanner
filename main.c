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

    // Check if the file size is smaller than the required size for signature check
    if (fileSize < signatureLength) {
        printf("Error: File size is smaller than signature length + offset\n");
        fclose(file);
        return;
    }

    // Read the entire file into a buffer
    unsigned char *buffer = (unsigned char *)malloc(fileSize);
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation error");
        return;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Check for MZ header in the first two bytes of the file
    if (buffer[0] == 0x4D && buffer[1] == 0x5A) {
        printf("The file has an MZ header, indicating a PE format executable.\n");
    } else {
        printf("The file does not have an MZ header, possibly not a Windows executable.\n");
    }

    // Allocate memory for hexadecimal representation (twice the file size + 1 for null terminator)
    char *hexBuffer = (char *)malloc(2 * fileSize + 1);
    if (hexBuffer == NULL) {
        free(buffer);
        perror("Memory allocation error");
        return;
    }

    // Convert binary buffer to hexadecimal representation
    for (int i = 0; i < fileSize; i++) {
        sprintf(hexBuffer + 2 * i, "%02X", buffer[i]);
    }
    hexBuffer[2 * fileSize] = '\0';

    // Convert input signature to uppercase
    char *signatureCopy = strdup(signature);
    if (signatureCopy == NULL) {
        perror("Memory allocation error");
        free(buffer);
        free(hexBuffer);
        return;
    }

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

long getFileSize(const char *filename) {
    FILE *file;
    long size;

    // Open the file in binary mode
    file = fopen(filename, "rb");

    // Check if file opened successfully
    if (file == NULL) {
        printf("Error opening file.\n");
        return -1; // Return -1 to indicate error
    }

    // Move file pointer to the end of the file
    fseek(file, 0, SEEK_END);

    // Get the current position of the file pointer
    size = ftell(file);

    // Close the file
    fclose(file);

    return size;
}

int checkFileSize(int fileSize, int offset, int signatureSize) {
    if (fileSize < 0) {
        printf("ERROR: Invalid file size\n");
        return 1;
    }
    if (offset < 0) {
        printf("ERROR: Invalid offset\n");
        return 2;
    }
    if (signatureSize <= 0) {
        printf("ERROR: Invalid signature size\n");
        return 3;
    }
    if (fileSize < offset + signatureSize) {
        printf("ERROR: File size too small for signature\n");
        return 4;
    }
    return 0;
}



int main() {
    FILE *file;
    char signature[MAX_SIGNATURE_LENGTH + 1]; // +1 for null terminator
    size_t bytes_read;
    char filepath[100]; // Assuming the maximum length of the file path is 100 characters
    char filepathToScan[100];

    // Prompt the user to input the file path
    printf("Please enter the path of the file containing the hexadecimal signature: ");
    fgets(filepath, sizeof(filepath), stdin);
    filepath[strcspn(filepath, "\n")] = 0; // Remove trailing newline

    printf("Please enter the path of the Program: ");
    fgets(filepathToScan, sizeof(filepathToScan), stdin);
    filepathToScan[strcspn(filepathToScan, "\n")] = 0; // Remove trailing newline


    // Open the file in binary mode
    file = fopen(filepath, "rb");
    if (file == NULL) {
        printf("Error: Unable to open file at path '%s'\n", filepath);
        return 1;
    }



    // Read the signature from the file
    bytes_read = fread(signature, 1, MAX_SIGNATURE_LENGTH, file);
    if (bytes_read == 0) {
        printf("Error: Unable to read signature from file\n");
        fclose(file);
        return 1;
    }
    
    signature[bytes_read] = '\0'; // Null-terminate the signature

    // Close the file
    fclose(file);

    // Print the signature as it is
    printf("\nSignature read from file: %s\n", signature);

    // Get file size for the program file
    file = fopen(filepathToScan, "rb");
    if (file == NULL) {
        printf("Error: Unable to open file at path '%s'\n", filepathToScan);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long programFileSize = ftell(file);
    fclose(file);



    // Print program file size
    printf("Program file size: %ld bytes\n", programFileSize);
    // Print signature size
    printf("Signature size: %zu bytes\n", bytes_read);

    searchSignature(filepathToScan, signature, strlen(signature));

    return 0;
}
