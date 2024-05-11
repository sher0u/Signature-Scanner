#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    }
        FILE *file = fopen(file_name, "r");
        if (file == NULL) {

            int CheackPrint = printf("Error opening file.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -1;
            }
            return 4;
        }

        // Read the first line (signature)
        if (fgets(signature, MAX_LENGTH, file) == NULL) {

            int CheackPrint = printf("Error reading signature.\n");
            if (CheackPrint<0)
            {
                printf("error of printing\n");
                return -2;
            }
            if (fclose(file) != 0) { // Attempt to close the file
                printf("Error closing the file.\n");
                return -3;
            }
            return 5;
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
                return -5;
            }

            if (fclose(file) != 0) { // Attempt to close the file
                printf("Error closing the file.\n");
                return -6;
            }
            return 6;
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
                return -7;
            }

            if (fclose(file) != 0) { // Attempt to close the file
                printf("Error closing the file.\n");
                return -8;
            }
            return 7;
        }
        // Remove newline character if present
        if (offset[strlen(offset) - 1] == '\n')
            offset[strlen(offset) - 1] = '\0';

        if (fclose(file) != 0) { // Attempt to close the file
            printf("Error closing the file.\n");
            return -9;
        }
        return 0;
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
    if (fclose(file) != 0) { // Attempt to close the file
        printf("Error closing the file.\n");
        return -2;
    }
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
        exit(1) ;
    }
    if (offset < 0) {

        int CheackPrint = printf("\nERROR: Invalid offset.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            exit(-2);
        }
        return 2;
    }
    if (signature_size <= 0) {

        int CheackPrint = printf("\nERROR: Invalid signature size.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -3;
        }
        exit(3) ;
    }
    if (exe_file_size < offset + signature_size) {

        int CheackPrint = printf("\nERROR: Offset and signature size exceed file size.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -4;
        }
        exit(4) ;
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
            return -2;
        }

        if (fclose(file) != 0) {
            printf("Error closing the file.\n");
            return -3;
        }
        return 0;
    }

    // Read 4 bytes (32 bits) from the file
    unsigned char data[SIGNATURE_SIZE];
    size_t bytes_read = fread(data, 1, SIGNATURE_SIZE, file);
    if (bytes_read != SIGNATURE_SIZE) {

        int CheackPrint =printf("Error reading signature from file.\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return -4;
        }

        if (fclose(file) != 0) { // Attempt to close the file
            printf("Error closing the file.\n");
            return -5;
        }
        return 0;
    }

    // Convert the signature bytes to an unsigned integer value
    unsigned int signature = 0;
    for (int i = 0; i < SIGNATURE_SIZE; ++i) {
        signature = (signature << 8) | data[i];
    }

    if (fclose(file) != 0) { // Attempt to close the file
        printf("Error closing the file.\n");
        return -6;
    }
    return signature;
}


// Function to check for the presence of an MZ header in a file
int checkMZHeader(const char *filename) {
    if(filename == NULL) {
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    // Read the first two bytes of the file
    unsigned char header[2];
    if (fread(header, 1, 2, file) != 2) {
        printf("Error reading file.\n");
        fclose(file);
        return -2;
    }

    if (fclose(file) != 0) { // Attempt to close the file
        printf("Error closing the file.\n");
        return -3;
    }

    // Check for MZ header (ASCII characters 'M' (0x4D) followed by 'Z' (0x5A))
    if (header[0] == 0x4D && header[1] == 0x5A) {
        return 1; // Return 1 to indicate MZ header found
    } else {
        printf("\nThe file '%s' does not have an MZ header, possibly not a Windows executable.\n", filename);
        exit(0); // Return 0 to indicate MZ header not found
    }
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
    if (offset == NULL){
        return 2;
    }
    if (signature == NULL){
        return 3;
    }

    // Convert offset to numeric value
    long offsetValue = strtol(offset, NULL, 16);
    if (offsetValue == 0 && errno != 0) {
        return 4; // Error converting offset to numeric value
    }

    // Calculate sizes
    long exe_size = calculateExeSize(filepathToScan);
    if (exe_size < 0) {
        return 5; // Error calculating exe size
    }

    unsigned long long int offsetSize = offsetValue;
    size_t offset_size = calculateOffsetSize(offsetSize);
    if (offset_size == 0) {
        return 6; // Error calculating offset size
    }

    size_t signature_size = calculateSignatureSize(signature);
    if (signature_size == 0) {
        return 7; // Error calculating signature size
    }

    // Check file integrity
    long result = check_file_size(exe_size, offset_size, signature_size);
    if (result != 0) {
        return 8; // File integrity check failed
    }

    return 0; // Success
}



int main() {
    char SignatureTxt[MAX_SIGNATURE_LENGTH + 1];//signture from text file
    char filepath[MAX_LENGTH]; // Adjusted buffer size
    char filepathToScan[MAX_LENGTH]; // Adjusted buffer size
    char NameFile[MAX_LENGTH]; // Adjusted buffer size // from the text file
    char offset[MAX_LENGTH]; //offset from text file
    unsigned int SignatureExe;
    char hexSignature[MAX_SIGNATURE_LENGTH + 1];
    char *ScanCheck;
    int CheackPrint;


    // Prompt the user to input the file path for the signature file
    CheackPrint = printf("Please enter the path of the file containing the hexadecimal signature: ");
    if (CheackPrint<0)
    {
        printf("error of printing\n");
        return 1;
    }
    ScanCheck = fgets(filepath, sizeof(filepath), stdin);
    if (ScanCheck == NULL) {
        printf("Error: Unable to read user input.\n");
        return 2;
    }
    filepath[strcspn(filepath, "\n")] = 0; // Remove trailing newline


    // Prompt the user to input the file path for the executable
     CheackPrint = printf("Please enter the path of the Program: ");
    if (CheackPrint<0)
    {
        printf("error of printing\n");
        return 3;
    }

    ScanCheck = fgets(filepathToScan, sizeof(filepathToScan), stdin);
    if (ScanCheck == NULL) {
        printf("Error: Unable to read user input.\n");
        return -1;
    }
    filepathToScan[strcspn(filepathToScan, "\n")] = 0; // Remove trailing newline

    // Call the function to read the signature and offset from the file
    if (read_signature_and_offset(filepath,  SignatureTxt, offset, NameFile) != 0) {
        return -2;
    }

    // Check for MZ header in the executable file
    if (checkMZHeader(filepathToScan) != 1) {
        return -3;
    }

    // Convert the hexadecimal offset to a long value
    long offsetValue = strtol(offset, NULL, 16);

    // size cheacking
    if (prepareSignatureVerification(filepathToScan, offset, SignatureTxt) != 0) {
        return -3;
    }

    // Read data from the file at the specified offset
    SignatureExe = read_file_at_offset(filepathToScan, offsetValue);

    // Convert the unsigned int signature to a string representation
    sprintf(hexSignature, "%X", SignatureExe);

    // Compare the signatures
    if (compareSignatures(hexSignature, SignatureTxt)) {
        CheackPrint =printf("\nSignatures found in: %s\n", NameFile);
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return 4;
        }

    } else {
        CheackPrint =printf("Signatures do not match!\n");
        if (CheackPrint<0)
        {
            printf("error of printing\n");
            return 4;
        }
    }
    return 0;
}
