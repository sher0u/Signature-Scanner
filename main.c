#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIGNATURE_LENGTH 8
#define MAX_LENGTH 100  // Maximum length of each line in the file
#define SIGNATURE_SIZE 4


//function to read the offset and the signature and the name from the text file
int read_signature_and_offset(const char *file_name, char *signature, char *offset, char *name) {

    if (file_name == NULL){
        return 1;
    }
    if(signature== NULL){
        return 2;
    }
    if (name == NULL){
        return 3;
    } else{
        FILE *file = fopen(file_name, "r");
        if (file == NULL) {

            int CheackPrint = printf("Error opening file.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -1;
            }

        }

        // Read the first line (signature)
        if (fgets(signature, MAX_LENGTH, file) == NULL) {

            int CheackPrint = printf("Error reading signature.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -1;
            }
            fclose(file);
            int Cheack1 = fclose(file);
            if ( Cheack1!= 0) {
                return -1;
            }
            return 1;
        }
        // Remove newline character if present
        if (signature[strlen(signature) - 1] == '\n')
            signature[strlen(signature) - 1] = '\0';

        // Read the second line (offset)
        if (fgets(offset, MAX_LENGTH, file) == NULL) {

            int CheackPrint = printf("Error reading offset.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -1;
            }

            fclose(file);
            int Cheack1 = fclose(file);
            if ( Cheack1!= 0) {
                return -1;
            }
            return 1;
        }
        // Remove newline character if present
        if (offset[strlen(offset) - 1] == '\n')
            offset[strlen(offset) - 1] = '\0';

        // Read the third line (offset)
        if (fgets(name, MAX_LENGTH, file) == NULL) {

            int CheackPrint =printf("Error reading offset.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -1;
            }

            fclose(file);
            int Cheack1 = fclose(file);
            if ( Cheack1!= 0) {
                return -1;
            }
            return 1;
        }
        // Remove newline character if present
        if (offset[strlen(offset) - 1] == '\n')
            offset[strlen(offset) - 1] = '\0';

        fclose(file);
        int Cheack1 = fclose(file);
        if ( Cheack1!= 0) {
            return -1;
        }
        return 1;
    }

}


// Function to calculate the size of the executable file
long calculateExeSize(const char *file_path) {
    if (file_path == NULL){
        return 1;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        int CheackPrint = printf("Error opening file '%s'.\n", file_path);
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
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
    if (signature == NULL){
        return 1;
    } else {
        size_t size = 0;
        // Iterate through the signature until a null terminator is encountered
        while (signature[size] != '\0') {
            size++;
        }
        return size;
    }
}

//function of cheacking with the file size
int check_file_size(int exe_file_size, int offset, int signature_size) {
    if (exe_file_size < 0) {
        int CheackPrint = printf("ERROR: Invalid executable file size.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
        return 1;
    }
    if (offset < 0) {

        int CheackPrint = printf("ERROR: Invalid offset.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
        return 2;
    }
    if (signature_size <= 0) {

        int CheackPrint = printf("ERROR: Invalid signature size.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
        return 3;
    }
    if (exe_file_size < offset + signature_size) {

        int CheackPrint = printf("ERROR: Offset and signature size exceed file size.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
        return 4;
    }
    return 0;
}

// reading the signature from the exe
unsigned int read_file_at_offset(const char *file_path, long offset) {
    if(file_path == NULL) {
        return 1;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        int CheackPrint =printf("Unable to open file '%s'.\n", file_path);
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }
        return 0;
    }

    // Seek to the specified offset
    if (fseek(file, offset, SEEK_SET) != 0) {

        int CheackPrint =printf("Error seeking to offset.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }

        fclose(file);
        int Cheack1 = fclose(file);
        if ( Cheack1!= 0) {
            return -1;
        }
        return 0;  // Return 0 if seeking fails
    }

    // Read 4 bytes (32 bits) from the file
    unsigned char data[SIGNATURE_SIZE];
    size_t bytes_read = fread(data, 1, SIGNATURE_SIZE, file);
    if (bytes_read != SIGNATURE_SIZE) {

        int CheackPrint =printf("Error reading signature from file.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -1;
        }

        fclose(file);
        int Cheack1 = fclose(file);
        if ( Cheack1!= 0) {
            return -1;
        }
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


// Function to check for the presence of an MZ header in a file
int checkMZHeader(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1; // Return -1 to indicate error
    }

    // Read the first two bytes of the file
    unsigned char header[2];
    if (fread(header, 1, 2, file) != 2) {
        printf("Error reading file.\n");
        fclose(file);
        return -1; // Return -1 to indicate error
    }

    // Close the file
    fclose(file);

    // Check for MZ header (ASCII characters 'M' (0x4D) followed by 'Z' (0x5A))
    if (header[0] == 0x4D && header[1] == 0x5A) {
        return 1; // Return 1 to indicate MZ header found
    } else {
        printf("\nThe file '%s' does not have an MZ header, possibly not a Windows executable.\n", filename);
        exit(0); // Return 0 to indicate MZ header not found
    }
}


// Function to search for a signature in a file
int searchSignature(const char *filename, const char *signature, int signatureLength) {
    if (filename == NULL){
        return 1;
    }
    if (signature == NULL){
        return 2;
    }
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
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
        return -2;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    // Allocate memory for hexadecimal representation (twice the file size + 1 for null terminator)
    char *hexBuffer = (char *) malloc(2 * fileSize + 1);
    if (hexBuffer == NULL) {
        free(buffer);
        perror("Memory allocation error");
        return -2;
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
        return -2;
    }

    for (int i = 0; i < signatureLength; i++) {
        signatureCopy[i] = toupper(signatureCopy[i]);
    }

    // Free allocated memory
    free(buffer);
    free(hexBuffer);
    free(signatureCopy);
    return 0;
}


//comparing signature
bool compareSignatures(const char *signature1, const char *signature2) {

    if(signature1 == NULL){
        return 1;
    }
    if(signature2 == NULL){
        return 2;
    } else {
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
}



// Function to prepare for signature verification by calculating sizes and checking file integrity
int prepareSignatureVerification(const char *filepathToScan, const char *offset, const char *signature) {

    if (filepathToScan == NULL){
        return 1;
    }
    if ( offset == NULL){
        return 2;
    }
    if ( signature == NULL){
        return 3;
    }
    long offsetValue = strtol(offset, NULL, 16);
    long exe_size = calculateExeSize(filepathToScan);
    unsigned long long int offsetSize = offsetValue;
    size_t offset_size = calculateOffsetSize(offsetSize);
    size_t signature_size = calculateSignatureSize(signature);
    long result = check_file_size(exe_size, offset_size, signature_size);
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
    int Result ;
    int PrintCheck;
    char *ScanCheck;



    // Prompt the user to input the file path
    PrintCheck = printf("Please enter the path of the file containing the hexadecimal signature: ");
    if (PrintCheck < 0) {
        printf("Error: Unable to prompt user for input.\n");
        return -1;
    }
    // Read the user input
    ScanCheck = fgets(filepath, sizeof(filepath), stdin);
    if (ScanCheck == NULL) {
        printf("Error: Unable to read user input.\n");
        return -1;
    }
    filepath[strcspn(filepath, "\n")] = 0; // Remove trailing newline


    PrintCheck =     printf("Please enter the path of the Program: ");

    if (PrintCheck < 0) {
        printf("Error: Unable to prompt user for input.\n");
        return -1;
    }
    // Read the user input
    ScanCheck = fgets(filepathToScan, sizeof(filepathToScan), stdin);

    if (ScanCheck == NULL) {
        PrintCheck = printf("Please enter the path of the file containing the hexadecimal signature: ");
        if (PrintCheck < 0) {
            printf("Error: Unable to prompt user for input.\n");
            return -1;
        }
        return -1;
    }
    filepathToScan[strcspn(filepathToScan, "\n")] = 0; // Remove trailing newline

    // Open the file in binary mode
    file = fopen(filepath, "rb");
    if (file == NULL) {
        PrintCheck =printf("Error: Unable to open file at path '%s'\n", filepath);
        if (PrintCheck < 0) {
            printf("Error: Unable to prompt user for input.\n");
            return -1;
        }
        return 1;
    }

    // Read the signature and offset from the file
    if (read_signature_and_offset(filepath, signature, offset, NameFile) == 0) {
        printf("Error reading signature or offset.\n");
        return -1;
    }

    // Check for MZ header
    if (checkMZHeader(filepathToScan) != 1) {
        printf("Error: Not a valid Windows executable.\n");
        return -1;
    }


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
        PrintCheck =printf("\nSignatures found in:%s\n", NameFile);
        if (PrintCheck < 0) {
            printf("Error: Unable to prompt user for input.\n");
            return -1;
        }

    } else {

        PrintCheck =printf("Signatures do not match!\n");
        if (PrintCheck < 0) {
            printf("Error: Unable to prompt user for input.\n");
            return -1;
        }

    }
    return 0;
}

/*_______________________________
Yousfi abdelakder / GitHub :@sher0u /mail : abdelkader.yousfi.pr@mail.ru
_______________________________-
 * Tested to work.
 */
