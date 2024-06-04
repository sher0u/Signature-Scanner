#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Virus {
    char NameVirus[100];
    int OffseTPosition;
    char sign[6];
    char VirusSignature[6];
    char MZ[2];
    char MZexpected[2];
} vir;


int DataRead(char *textfilepath) {
    FILE *f;
    int ResultforChecking;

    if(textfilepath == NULL){
        return 1;
    }

    f = fopen(textfilepath, "r");
    if (f == NULL)
        return 2;

    if (fgets(vir.NameVirus, sizeof(vir.NameVirus), f) == NULL)
        return 3;
    vir.NameVirus[strcspn(vir.NameVirus, "\n")] = 0;

    if (fscanf(f, "%d", &vir.OffseTPosition) != 1)
        return 3;

    for (int i = 0; i < 6; i++) {
        if (fscanf(f, "%hhx", &vir.sign[i]) != 1)
            return 3;
    }

    ResultforChecking = fclose(f);
    if (ResultforChecking != 0) return 4;

    return 0;
}


int SeekBegan(FILE *f) {
    if(f==NULL){
        return 1;
    }
    int ResultCheckingSeekBegan;
    ResultCheckingSeekBegan = fseek(f, 0, SEEK_SET);
    if (ResultCheckingSeekBegan != 0) return 2;
    return 0;
}

int SeekEnd(FILE *f) {
    if(f==NULL){
        return 1;
    }
    int ResultCheckingSeekEnd;
    ResultCheckingSeekEnd = fseek(f, 0, SEEK_END);
    if (ResultCheckingSeekEnd != 0) return 2;
    return 0;
}

int GoToSignatureOffset(FILE *f) {
    if(f==NULL){
        return 1;
    }
    int ResultCheckingGotoSignature;
    ResultCheckingGotoSignature = fseek(f, vir.OffseTPosition, SEEK_SET);
    if (ResultCheckingGotoSignature != 0) return 2;
    return 0;
}

int ScanForMZSignature(FILE *f) {
    if(f==NULL){
        return 1;
    }
    int result;
    vir.MZexpected[0] = 'M';
    vir.MZexpected[1] = 'Z';
    for (int i = 0; i < 2; i++) {
        result = fread(&vir.MZ[i], sizeof(char), 1, f);
        if (result != 1) return 2;
    }
    return 0;
}

int CloseFile(FILE *f) {
    if(f==NULL){
        return 1;
    }
    int ResultcheckingforCLosingfile;
    ResultcheckingforCLosingfile = fclose(f);
    if (ResultcheckingforCLosingfile != 0) return 2;
    return 0;
}

int main() {
    FILE *f;
    char FileName[100];
    char SignatureTxt[100];
    int Result, Length;
    int CHecking;
    char *ScanCheck;


    Result = printf("\n\t** Hello,Welcome to the signature scaner ** \n \t\t*** Guide of use *** \n "
                    "* Prepare the text file as this examples * \n "
                    "The first line : Name of Program. \n "
                    "Second line:offset in Decimal \n "
                    "Third line:Signature in HexDecimal and in 6 bytes with Spaces. \n"
                    "\n******Examples of text file ******\nNotepad\n"
                     "242835\n"
                     "8A 67 25 CA 82 5F\n\n");
    if (Result < 0) {
        printf("Error printf!");
        return 1;
    }

    Result = printf("Enter the path of the text file: \n");
    if (Result < 0) {
        printf("Error printf!");
        return 2;
    }

    ScanCheck = fgets(SignatureTxt, sizeof(SignatureTxt), stdin);
    if (ScanCheck == NULL) {
        printf("Error: Unable to read user input.\n");
        return 3;
    }

    int index = 0;
    while (SignatureTxt[index] != '\0') {
        if (SignatureTxt[index] == '\n') {
            SignatureTxt[index] = '\0';
            break;
        }
        index++;
    }

    Result = DataRead(SignatureTxt);
    switch (Result) {
        case 1:
            printf("The argument is Null");
            return 1;
        case 2:
            printf("Error of opening the file!\n");
            return 2;
        case 3:
            printf("Error of reading the  database\n");
            return 3;
        case 4:
            printf("Error of  closing the file!\n");
            return 2;
    }

    Result = printf("Enter the path to the  file That You want To scan it : \n");
    if (Result < 0) {
        printf("Error printf!");
        return 4;
    }

    Result = scanf("%99s",FileName);
    if (Result !=1 ) {
        printf("Error: Unable to read user input.\n");
        return 5;
    }

    f = fopen(FileName, "rb");
    if (f == NULL) {
        printf("Error open file!");
        return 2;
    }

    Result = SeekBegan(f);
    if (Result == 1) {
        printf("Error moving to the beginning of the file!");
        return 1;
    }

    Result = ScanForMZSignature(f);
    if (Result == 1) {
        printf("Error of fread!");
        return 2;
    }

    if (vir.MZ[0] != vir.MZexpected[0] || vir.MZ[1] != vir.MZexpected[1]) {
        Result = printf("\nThis is Safe program\n");
        if (Result < 0) {
            printf("Error printf!");
            return 3;
        }
        Result = CloseFile(f);
        if (Result == 1) {
            printf("Error close file!");
            return 3;
        }
        return 0;
    }

    Result = SeekEnd(f);
    if (Result == 1) {
        printf("Error when moving to the end of the file!");
        return 4;
    }
    Length = ftell(f);
    if (Length == -1) {
        printf("Error of ftell!");
        return 5;
    }
    if (Length < vir.OffseTPosition) {
        Result = printf("\nThis  is Safe program\n");
        if (Result < 0) {
            printf("Error printf!");
            return 6;
        }
        Result = CloseFile(f);
        if (Result == 1) {
            printf("Error close file!");
            return 3;
        }
        return 0;
    }

    Result = GoToSignatureOffset(f);
    if (Result == 1) {
        printf("Error when moving to the beginning of the signature!");
        return 7;
    }

    CHecking = 0;
    for (int i = 0; i < 6; i++) {
        Result = fread(&vir.VirusSignature[i], sizeof(vir.VirusSignature[0]), 1, f);
        if (Result != 1) {
            printf("Error fread :(");
            return 8;
        }
        if (vir.VirusSignature[i] == vir.sign[i]) {
            CHecking += 1;
        }
    }

    if (CHecking == 6) {
        Result = printf("\nThis is a Virus ! \nVirus name: %s \nLocation file: %s\n", vir.NameVirus, FileName);
        if (Result < 0) {
            printf("Error printf!");
            return 9;
        }
        Result = CloseFile(f);
        if (Result == 1) {
            printf("Error close file!");
            return 3;
        }
        return 0;
    } else {
        Result = printf("\nThis is Safe :)\n");
        if (Result < 0) {
            printf("Error printf!");
            return 10;
        }
        Result = CloseFile(f);
        if (Result == 1) {
            printf("Error close file!");
            return 3;
        }
        return 0;
    }
}

