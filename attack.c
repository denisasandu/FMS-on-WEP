#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define N 256

int mod(int a, int b) {
    while ((a < 0) || (a >= b) ) {
        if(a < 0)
            a += b;
        if(a >= b)
            a -= b;
    }
    return a;
}

void swap(unsigned char *a, unsigned char *b) {
    unsigned char aux = *a;
    *a = *b;
    *b = aux; 
}

int KSA(unsigned char* s, unsigned char *ivkey, int steps) {
    int j = 0;
    for(int i = 0; i < N; i++) {
        s[i] = i;
    }
    for(int i = 0; i < steps; i++) {
        j = mod(j + s[i] + (int) ivkey[mod((unsigned int) i, 8)], N);
        swap(&s[i], &s[j]);
    }
    return j;
}

int simResolve(unsigned char *buffer, unsigned char *key, int keyByte) {
    unsigned char iv[3];
    unsigned char ivkey[8];
    unsigned char s[N];
    int sInverse;

    for(int i = 0; i < 3; i++) {
        iv[i] = buffer[i];
        ivkey[i] = iv[i];
    }

    for (int i = 0; i < 4; i++) {
        ivkey[i + 3] = key[i];
    }

    // Apply keyByte + 3 steps of KSA
    int j = KSA(s, ivkey, keyByte + 3);

    sInverse = 0;
    for(int c = 0; c < N; c++) {
        if(s[c] == (buffer[4] ^ 'a') )
            sInverse = c;
    }

    int guess = mod((sInverse - j - s[keyByte + 3]), N);
    return guess;
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./attack input_file.\n");
        exit(1);
    }

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("Error opening file %s.\n", argv[1]);
        exit(1);
    }

    int counts[N];
    unsigned char buffer[5], key[5] = {0};
    int bestGuess, maxGuess;

    for (int keyByte = 0; keyByte < 5; keyByte++) {
        memset(counts, 0, N * sizeof(int));

        while (fread(buffer, sizeof(unsigned char), 5, fp) != 0) {
            if ((buffer[0] == keyByte + 3) && (buffer[1] == 0xFF))
                counts[simResolve(&buffer[0], &key[0], keyByte)]++;
        }

        maxGuess = bestGuess = 0;
        for(int i = 0; i < N; i++) {
            if(counts[i] > maxGuess) {
                maxGuess = counts[i];
                bestGuess = i;
            }
        }
        key[keyByte] = bestGuess;
        printf("Best guess for key[%d] is 0x%.2x = %d = %c\n", keyByte, bestGuess, bestGuess, bestGuess);

        fseek(fp, 0, SEEK_SET);
    }

    printf("\nRC4 Key: ");
    for (int i = 0; i < 5; i++) {
        printf("%c", key[i]);
    }
    printf("\n");

    fclose(fp);
    return 0;
}