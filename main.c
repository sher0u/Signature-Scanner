#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIGNATURE_LENGTH 8
#define MAX_LENGTH 100  // Maximum length of each line in the file
#define SIGNATURE_SIZE 4

// Function to check for the presence of an MZ header in a file
int checkMZHeader(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(-1) ; // Return -1 to indicate error
    }

    // Read the first two bytes of the file
    unsigned char header[2];
    if (fread(header, 1, 2, file) != 2) {
        printf("Error reading file.\n");
        fclose(file);
        exit(-1); // Return -1 to indicate error
    }

    // Close the file
    fclose(file);

    // Check for MZ header (ASCII characters 'M' (0x4D) followed by 'Z' (0x5A))
    if (header[0] == 0x4D && header[1] == 0x5A) {
        return 0;
    } else {
        printf("\nThe file '%s' does not have an MZ header, possibly not a Windows executable.\n", filename);
        exit(-1); // Return 0 to indicate MZ header not found
    }
}

//function to read the offset and the signature and the name from the text file
int read_signature_and_offset(const char *file_name, char *signature, char *offset, char *name) {
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

    // Read the third line (offset)
    if (fgets(name, MAX_LENGTH, file) == NULL) {
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

// Function to calculate the size of the executable file
long calculateExeSize(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("Error opening file '%s'.\n", file_path);
        return -1; // Return -1 to indicate error
    }

    // Seek to the end of the file to get its size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    // Close the file
    fclose(file);

    return file_size;

}

// Function to calculate the size of the offset
size_t calculateOffsetSize(unsigned long long int offset) {
    size_t size = 0;
    while (offset != 0) {
        offset /= 16; // Assuming hexadecimal offset, divide by 16
        size++;
    }
    return size;
}

// Function to calculate the size of the signature
size_t calculateSignatureSize(const char *signature) {
    size_t size = 0;
    // Iterate through the signature until a null terminator is encountered
    while (signature[size] != '\0') {
        size++;
    }
    return size;
}

//function of cheacking with the file size
int check_file_size(int exe_file_size, int offset, int signature_size) {
    if (exe_file_size < 0) {
        printf("ERROR: Invalid executable file size.\n");
        return 1;
    }
    if (offset < 0) {
        printf("ERROR: Invalid offset.\n");
        return 2;
    }
    if (signature_size <= 0) {
        printf("ERROR: Invalid signature size.\n");
        return 3;
    }
    if (exe_file_size < offset + signature_size) {
        printf("ERROR: Offset and signature size exceed file size.\n");
        return 4;
    }
    return 0;
}

// reading the signature from the exe
unsigned int read_file_at_offset(const char *file_path, long offset) {
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("Unable to open file '%s'.\n", file_path);
        return 0;  // Return 0 if file cannot be opened
    }

    // Seek to the specified offset
    if (fseek(file, offset, SEEK_SET) != 0) {
        printf("Error seeking to offset.\n");
        fclose(file);
        return 0;  // Return 0 if seeking fails
    }

    // Read 4 bytes (32 bits) from the file
    unsigned char data[SIGNATURE_SIZE];
    size_t bytes_read = fread(data, 1, SIGNATURE_SIZE, file);
    if (bytes_read != SIGNATURE_SIZE) {
        printf("Error reading signature from file.\n");
        fclose(file);
        return 0;  // Return 0 if reading fails
    }

    // Convert the signature bytes to an unsigned integer value
    unsigned int signature = 0;
    for (int i = 0; i < SIGNATURE_SIZE; ++i) {
        signature = (signature << 8) | data[i];
    }

    // Clean up
    fclose(file);

    return signature;
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
    unsigned char *buffer = (unsigned char *) malloc(fileSize);
    if (buffer == NULL) {
        fclose(file);
        perror("Memory allocation error");
        return;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Allocate memory for hexadecimal representation (twice the file size + 1 for null terminator)
    char *hexBuffer = (char *) malloc(2 * fileSize + 1);
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

    // Free allocated memory
    free(buffer);
    free(hexBuffer);
    free(signatureCopy);
}


//comparing signature
bool compareSignatures(const char *signature1, const char *signature2) {
    // Get the lengths of the signatures
    size_t len1 = strlen(signature1);
    size_t len2 = strlen(signature2);

    // If the lengths are different, signatures cannot match
    if (len1 != len2) {
        return false;
    }

    // Compare the signatures character by character
    for (size_t i = 0; i < len1; ++i) {
        if (signature1[i] != signature2[i]) {
            // Signatures do not match
            return false;
        }
    }

    // Signatures match
    return true;
}

// Function to prepare for signature verification by calculating sizes and checking file integrity
int prepareSignatureVerification(const char *filepathToScan, const char *offset, const char *signature) {
    long offsetValue = strtol(offset, NULL, 16);
    long exe_size = calculateExeSize(filepathToScan);
    unsigned long long int offsetSize = offsetValue;
    size_t offset_size = calculateOffsetSize(offsetSize);
    size_t signature_size = calculateSignatureSize(signature);
    int result = check_file_size(exe_size, offset_size, signature_size);
    return result;
}

int main() {
    FILE *file;
    char signature[MAX_SIGNATURE_LENGTH + 1]; // +1 for null terminator
    char filepath[100]; // Assuming the maximum length of the file path is 100 characters
    char filepathToScan[100];
    char NameFile[100];
    char offset[MAX_LENGTH];
    unsigned int Signature;
    char hexSignature[MAX_SIGNATURE_LENGTH + 1]; // +1 for null terminator
    const char *filename = filepathToScan; // Replace with the actual file name
    int Result ;



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
    read_signature_and_offset(filepath, signature, offset, NameFile);

    // MZ CHeacker
    checkMZHeader(filename);


    // Assign offset from the variable
    long offsetValue = strtol(offset, NULL, 16);
    // Read the signature and offset from the file
    read_signature_and_offset(filepath, signature, offset, NameFile);

    // Check file integrity and prepare for signature verification
    Result = prepareSignatureVerification(filepathToScan, offset, signature);
    if (Result != 0) {
        exit(-1);
    }

    // Read data from the file at the specified offset
    Signature = read_file_at_offset(filepathToScan, offsetValue);
    searchSignature(filepathToScan, signature, strlen(signature));

    // Convert the unsigned int signature to a string representation
    sprintf(hexSignature, "%X", Signature);

// Now you can call the compareSignatures function with the string representations
    if (compareSignatures(hexSignature, signature)) {
        printf("\nSignatures found in:%s\n", NameFile);
    } else {
        printf("Signatures do not match!\n");
    }


    return 0;
}
