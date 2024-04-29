#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIGNATURE_LENGTH 8
#define MAX_LENGTH 100  // Maximum length of each line in the file
// reading the signature from the exe

void read_file_at_offset(const char* file_path, long offset) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("Unable to open file '%s'.\n", file_path);
        return;
    }

    // Seek to the specified offset
    if (fseek(file, offset, SEEK_SET) != 0) {
        printf("Error seeking to offset.\n");
        fclose(file);
        return;
    }

    // Read 4 bytes (32 bits) from the file
    unsigned char data[4];
    size_t bytes_read = fread(data, 1, sizeof(data), file);
    if (bytes_read != sizeof(data)) {
        printf("Error reading signature from file.\n");
        fclose(file);
        return;
    }

    // Print the signature
    printf("Signature at offset 0x%lx: ", offset);
    for (int i = 0; i < sizeof(data); ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");

    // Clean up
    fclose(file);
}

//function to read the offset and the signature from the text file
int read_signature_and_offset(const char *file_name, char *signature, char *offset) {
    FILE *file = fopen(file_name, "r");
    if (file == NULL) {
        printf("Error opening file.\n");
        return 1;
    }

    // Read the first line (signature)
    if (fgets(signature, MAX_LENGTH, file) == NULL) {
        printf("Error reading signature.\n");
        fclose(file);
        return 1;
    }
    // Remove newline character if present
    if (signature[strlen(signature) - 1] == '\n')
        signature[strlen(signature) - 1] = '\0';

    // Read the second line (offset)
    if (fgets(offset, MAX_LENGTH, file) == NULL) {
        printf("Error reading offset.\n");
        fclose(file);
        return 1;
    }
    // Remove newline character if present
    if (offset[strlen(offset) - 1] == '\n')
        offset[strlen(offset) - 1] = '\0';

    fclose(file);
    return 0;
}

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

int main() {
    FILE *file;
    char signature[MAX_SIGNATURE_LENGTH + 1]; // +1 for null terminator
    size_t bytes_read;
    char filepath[100]; // Assuming the maximum length of the file path is 100 characters
    char filepathToScan[100];
    char offset[MAX_LENGTH];
    char offsetFake[MAX_LENGTH];

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

    // Read the signature and offset  from the file
    read_signature_and_offset(filepath,signature,offset);


    // Print the signature as it is
    printf("\nSignature read from file: %s\n", signature);
    // Print the signature as it is
    printf("Signature read from file: %s\n", offset);
    //printf the offset from the exe file

    // Prompt the user to input the offset to read from
    long offsetValue;
    printf("Please enter the offset (in hexadecimal) to read from: ");
    scanf("%lx", &offsetValue);

    // Read data from the file at the specified offset
    read_file_at_offset(filepathToScan, offsetValue);


    searchSignature(filepathToScan, signature, strlen(signature));

    return 0;
}
