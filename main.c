#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include "aes.h"

static uint8_t state[4][4];
uint8_t s[16];
char inputfile;

uint8_t key[16] = {(uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16,
                   (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6,
                   (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88,
                   (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c};

uint8_t output[16];
uint8_t IV[16] = {0xfc, 0x4e, 0x53, 0x29, 0xbf, 0xd4, 0x4c, 0x4c, 0x34, 0x76, 0x14, 0x7b, 0xb7, 0xfd, 0xc6, 0xe8};

void encrypt(unsigned char *s, uint8_t roundkey[176])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[i][j] = s[4 * i + j];
        }
    }
    printstate(state);

    cipher(state, roundkey);

    printstate(state);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            s[4 * i + j] = state[i][j];
        }
    }
}
uint8_t unpad(uint8_t *s)
{
    uint8_t pv = s[15];
    if ((pv > 0) && (pv <= 16))
    {
        for (uint8_t i = 0; i < pv; ++i)
        {
            if (s[15 - i] != pv)
            {
                fprintf(stderr, "invalid padding");
                exit(EXIT_FAILURE);
            }
        }
        return pv;
    }
    else
    {
        fprintf(stderr, "invalid padding");
        exit(EXIT_FAILURE);
    }
}

void decrypt(unsigned char *s, uint8_t roundkey[176])
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            state[i][j] = s[4 * i + j];
        }
    }
    printstate(state);

    decipher(state, roundkey);

    printstate(state);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            output[4 * i + j] = state[i][j];
        }
    }
}

void ecbencrypt(FILE *pt, FILE *ct)
{
    key_scheudling(roundkey, key);

    if (pt == NULL)
    {
        printf("file not opened\n");
    }
    uint8_t j;

    while ((j = fread(s, 1, 16, pt)) == 16)
    {

        encrypt(s, roundkey);
        printf("written on output");
        for (int i = 0; i < 4; i++)
        {
            printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
        }

        int k = fwrite(s, 1, 16, ct);

        printf("%d\n", k);
    }

    uint8_t pad = 16 - j;
    for (uint8_t i = j; i < 16; i++)
    {
        s[i] = pad;
    }

    encrypt(s, roundkey);

    printf("written on output");
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
    }

    int k = fwrite(s, 1, 16, ct);

    printf("%d\n", k);

    fclose(pt);
    fclose(ct);
    printf("end of cipher\n");
}

void ecbdecrypt(FILE *ct, FILE *pt)
{
    key_scheudling(roundkey, key);
    uint8_t j = fread(s, 1, 16, ct);
    while (j > 0)
    {

        decrypt(s, roundkey);
        printf("written on output\n");
        for (int i = 0; i < 4; i++)
        {
            printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
        }
        if (fread(s, 1, 16, ct) == 0)
        {
            break;
        }

        int k = fwrite(output, 1, 16, pt);

        // printf("%d\n", k);
        // j = read(fd_c, s, 16);
    }
    uint8_t pad_len = unpad(output);
    int k = fwrite(output, 1, 16 - pad_len, pt);

    fclose(ct);
    fclose(pt);
    printf("end of decipher\n");
}

void cbcencrypt(FILE *pt, FILE *ct, uint8_t *roundkey)
{
    uint8_t plain[16];
    uint8_t byt;
    fwrite(IV, 1, 16, ct);

    while ((byt = fread(plain, 1, 16, pt)) == 16)
    {
        for (uint8_t i = 0; i < 16; ++i)
        {
            IV[i] ^= plain[i];
        }
        encrypt(IV, roundkey);
        int m = fwrite(IV, 1, 16, ct);
        printf("\n%d\n", m);
    }
    uint8_t padval = 16 - byt;

    for (uint8_t i = byt; i < 16; ++i)
    {
        plain[i] = padval;
    }

    for (uint8_t i = 0; i < 16; ++i)
    {
        IV[i] ^= plain[i];
    }
    encrypt(IV, roundkey);
    int m = fwrite(IV, 1, 16, ct);
    printf("\n%d\n", m);
    fclose(pt);
    fclose(ct);
    printf("end of cipher\n");
}

void cbcdecrypt(FILE *ct, FILE *pt)
{
    uint8_t c[16], temp[16];
    uint8_t byt;
    fread(IV, 1, 16, ct);

    uint8_t j = fread(c, 1, 16, ct);
    while (j > 0)
    {
        for (uint8_t i = 0; i < 16; i++)
        {
            temp[i] = c[i];
        }

        decrypt(c, roundkey);

        for (uint8_t i = 0; i < 16; i++)
        {
            output[i] = output[i] ^ IV[i];
        }

        for (uint8_t i = 0; i < 16; i++)
        {
            IV[i] = temp[i];
        }

        if ((j = fread(c, 1, 16, ct)) == 0)
        {
            break;
        }
        fwrite(output, 1, 16, pt);
    }

    uint8_t pad_len = unpad(output);
    fwrite(output, 1, 16 - pad_len, pt);
}

void main()
{
    FILE *pt = fopen("input.txt", "r");

    FILE *ct = fopen("cipher.txt", "w");

    cbcencrypt(pt, ct, roundkey);

    FILE *ct1 = fopen("cipher.txt", "rb");
    FILE *pt1 = fopen("decipher.txt", "w");

    cbcdecrypt(ct1, pt1);
}