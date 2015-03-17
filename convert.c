#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_DATE_SIZE 720

int main(int argc, char* argv[]) {
    char date[MAX_DATE_SIZE]="";
    double btc=0;
    double rate=0;
    FILE * pFile;
    char line[18];

    if (argc == 3 && strlen(argv[1]) < MAX_DATE_SIZE) {
        btc=strtod(argv[1], NULL);
        strcpy(date, argv[2]);
    } else {
        fprintf(stderr, "Bitcoin to US Dollar converter.\n");
        fprintf(stderr, "Usage: %s <#bitcoins> <YYYY-MM-DD>\n", argv[0]);
        fprintf(stderr, "Date range: \"2010-07-17\" to \"2014-01-21\".\n");
        return -1;
    }

    pFile = fopen ("/home/superuser/bitcoin.txt" , "r");
    if (pFile == NULL) perror ("Error opening file");
    else {
       while ( fgets (line , sizeof(line), pFile) != NULL )
           if (strcmp(strndup(line + 0, 10), date) == 0)
               rate=strtod(strndup(line + 11, sizeof(line)-11), NULL);
    }
    fclose (pFile);

    printf("%.5f BTC were worth %.5f USD on %s\n", btc, (btc * rate), date);

    return 0;
}

