#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include "aes.h"
// declaring the state
static uint8_t state[4][4];
// declaring the array to take input in modes
uint8_t s[16];
char inputfile;
// the key in use
uint8_t key[16] = {(uint8_t)0x2b, (uint8_t)0x7e, (uint8_t)0x15, (uint8_t)0x16,
                   (uint8_t)0x28, (uint8_t)0xae, (uint8_t)0xd2, (uint8_t)0xa6,
                   (uint8_t)0xab, (uint8_t)0xf7, (uint8_t)0x15, (uint8_t)0x88,
                   (uint8_t)0x09, (uint8_t)0xcf, (uint8_t)0x4f, (uint8_t)0x3c};
// array to store the output
uint8_t output[16];
// Static IV i  use
uint8_t IV[16] = {0xfc, 0x4e, 0x53, 0x29, 0xbf, 0xd4, 0x4c, 0x4c, 0x34, 0x76, 0x14, 0x7b, 0xb7, 0xfd, 0xc6, 0xe8};
// Convering the encrypt funtion from 2d input to 1d
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

// function to find the length of thepadding
uint8_t unpad(uint8_t *s)
{
    uint8_t pv = s[15]; // taking the last entry of the lst block
    if ((pv > 0) && (pv <= 16))
    {
        for (uint8_t i = 0; i < pv; ++i)
        {
            if (s[15 - i] != pv) // checking if there are pv many blocks with pv in it or not?
            {
                fprintf(stderr, "invalid padding");
                exit(EXIT_FAILURE);
            }
        }
        return pv; // pad value
    }
    else
    {
        fprintf(stderr, "invalid padding");
        exit(EXIT_FAILURE);
    }
}
// making the decryption function from 2d input to 1d
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

// encryption function for ECB mode
void ecbencrypt(FILE *pt, FILE *ct)
{

    key_scheudling(roundkey, key); // initializing the round key

    if (pt == NULL)
    {
        printf("file not opened\n");
    }
    uint8_t j; // to see how many bytes are getting read or write

    while ((j = fread(s, 1, 16, pt)) == 16) // reading untill full blocks
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

    uint8_t pad = 16 - j; // determining the pad value
    for (uint8_t i = j; i < 16; i++)
    {
        s[i] = pad; // adding the pad
    }

    encrypt(s, roundkey); // encrypting the last block

    printf("written on output");
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
    }

    int k = fwrite(s, 1, 16, ct);

    printf("%d\n", k);

    fclose(pt); // closing the files
    fclose(ct);
    printf("end of cipher\n");
}

// decryption function for ECB
void ecbdecrypt(FILE *ct, FILE *pt)
{
    key_scheudling(roundkey, key);   // initializing the round key
    uint8_t j = fread(s, 1, 16, ct); // counting how many we read
    while (j > 0)
    {

        decrypt(s, roundkey); // applying decryption
        printf("written on output\n");
        for (int i = 0; i < 4; i++)
        {
            printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
        }
        if (fread(s, 1, 16, ct) == 0) // we execute the loop in this way such that the input for nest round is collected in this round
        {
            break; // we can take the decesion based on that wether it is the last block or not
        }

        int k = fwrite(output, 1, 16, pt);

        // printf("%d\n", k);
        // j = read(fd_c, s, 16);
    }
    uint8_t pad_len = unpad(output);             // finding out the pad length
    int k = fwrite(output, 1, 16 - pad_len, pt); // out putting shy before the pad

    fclose(ct);
    fclose(pt);
    printf("end of decipher\n");
}

// encryption function for CBC
void cbcencrypt(FILE *pt, FILE *ct, uint8_t *roundkey)
{
    uint8_t plain[16]; // array to store the input
    uint8_t byt;       // no of bytes read
    fwrite(IV, 1, 16, ct);

    while ((byt = fread(plain, 1, 16, pt)) == 16)
    {
        for (uint8_t i = 0; i < 16; ++i)
        {
            IV[i] ^= plain[i]; // xor IV with the input
        }
        encrypt(IV, roundkey); // encrypting IV+input
        int m = fwrite(IV, 1, 16, ct);
        printf("\n%d\n", m);
    }
    uint8_t padval = 16 - byt; // determining the pad value

    for (uint8_t i = byt; i < 16; ++i)
    {
        plain[i] = padval; // assining the pad
    }

    for (uint8_t i = 0; i < 16; ++i)
    {
        IV[i] ^= plain[i]; // setting up IV
    }
    encrypt(IV, roundkey);
    int m = fwrite(IV, 1, 16, ct);
    printf("\n%d\n", m);
    fclose(pt);
    fclose(ct);
    printf("end of cipher\n");
}
// Decryption function for cbc decrypt
void cbcdecrypt(FILE *ct, FILE *pt)
{
    uint8_t c[16], temp[16]; // declaring intermidiate array and message array
    uint8_t byt;
    fread(IV, 1, 16, ct);

    uint8_t j = fread(c, 1, 16, ct);
    while (j > 0)
    {
        for (uint8_t i = 0; i < 16; i++)
        {
            temp[i] = c[i]; // store the input in temp
        }

        decrypt(c, roundkey);

        for (uint8_t i = 0; i < 16; i++)
        {
            output[i] = output[i] ^ IV[i]; // store the decrypted message in output
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

void ctrencrypt(FILE *pt, FILE *ct)
{
    int j = fwrite(IV, 1, 16, ct);
    printf("\n%d\n", j);
    IV[0] = IV[1] = IV[2] = IV[3] = 0x00;

    uint8_t m[16], input[16];
    uint8_t byt;
    while ((byt = fread(m, 1, 16, pt)) > 0)
    {
        for (uint8_t i = 0; i < 16; i++)
        {
            input[i] = IV[i];
        }
        encrypt(input, roundkey);
        for (uint8_t i = 0; i < 16; i++)
        {
            m[i] = m[i] ^ input[i];
        }
        int j = fwrite(m, 1, 16, ct);
        printf("\n%d\n", j);

        for (uint8_t i = 0; i < 4; i++)
        {
            if (++IV[i] != 0)
            {
                break;
            }
        }
    }
    fclose(pt);
    fclose(ct);
    printf("end of cipher");
}

void ctrdecrypt(FILE *ct, FILE *pt)
{
    int j = fread(IV, 1, 16, ct);
    printf("\n%d\n", j);
    IV[0] = IV[1] = IV[2] = IV[3] = 0x00;

    uint8_t m[16], input[16];
    uint8_t byt;
    while ((byt = fread(m, 1, 16, ct)) > 0)
    {
        for (uint8_t i = 0; i < 16; i++)
        {
            input[i] = IV[i];
        }
        encrypt(input, roundkey);
        for (uint8_t i = 0; i < 16; i++)
        {
            m[i] = m[i] ^ input[i];
        }
        int j = fwrite(m, 1, 16, pt);
        printf("\n%d\n", j);

        for (uint8_t i = 0; i < 4; i++)
        {
            if (++IV[i] != 0)
            {
                break;
            }
        }
    }
    fclose(ct);
    fclose(pt);
    printf("end of decipher");
}
// function for OFB encryption
void ofbencrypt(FILE *pt, FILE *ct)
{
    uint8_t m[16]; // message array
    uint8_t byt;   // no of bytes read
    int j = fwrite(IV, 1, 16, ct);
    printf("\n%d\n", j);

    while ((byt = fread(m, 1, 16, pt)) > 0)
    {
        encrypt(IV, roundkey); // encrypt the round key to generate the msak
        for (int i = 0; i < 16; i++)
        {
            m[i] = m[i] ^ IV[i]; // making the message by IV
        }

        int j = fwrite(m, 1, byt, ct);
        printf("\n%d\n", j);
    }
    fclose(pt);
    fclose(ct);
    printf("end of cipher");
}
// Decryption function for OFB
void ofbdecrypt(FILE *ct, FILE *pt)
{
    uint8_t m[16]; // message array
    uint8_t byt;   // no of bytes read
    int j = fread(IV, 1, 16, ct);
    printf("\n%d\n", j);

    while ((byt = fread(m, 1, 16, ct)) > 0)
    {
        encrypt(IV, roundkey); // generaring the necryption mask
        for (int i = 0; i < 16; i++)
        {
            m[i] = m[i] ^ IV[i]; // xoring mask to get palin text
        }

        int j = fwrite(m, 1, byt, pt);
        printf("\n%d\n", j);
    }
    fclose(ct);
    fclose(pt);
    printf("end of decrypt");
}
// encryption function For CFB mode
void cfbencrypt(FILE *pt, FILE *ct)
{
    uint8_t m[16];                 // array to hold incoming bytes
    uint8_t byt;                   // how many bytes we read
    int j = fwrite(IV, 1, 16, ct); // write the IV
    printf("\n%d\n", j);

    while ((byt = fread(m, 1, 16, pt)) > 0)
    {
        encrypt(IV, roundkey); // encrypt the IV

        for (int i = 0; i < 16; i++)
        {
            IV[i] = IV[i] ^ m[i]; // mask m with E_k(iv) i.e previous round cipher key
        }
        int j = fwrite(IV, 1, byt, ct);
        printf("\n%d\n", j);
    }
    fclose(pt);
    fclose(ct);
    printf("end of cipher");
}

void cfbdecrypt(FILE *ct, FILE *pt)
{
    uint8_t m[16];
    uint8_t byt;

    int j = fread(IV, 1, 16, ct);
    printf("\n%d\n", j);

    while ((byt = fread(m, 1, 16, ct)) > 0)
    {
        encrypt(IV, roundkey); // generaring the otp mask
        for (int i = 0; i < 16; i++)
        {
            IV[i] = IV[i] ^ m[i]; // decrypting the message
        }

        int j = fwrite(IV, 1, 16, pt);
        printf("\n%d\n", j);

        for (uint8_t i = 0; i < 16; i++)
        {
            IV[i] = m[i];
        }
    }
    fclose(ct);
    fclose(pt);
    printf("end of decryption");
}

void main()

{
    key_scheudling(roundkey, key);
    FILE *pt = fopen("input.txt", "r"); // opening the input message file in  read  mode

    FILE *ct = fopen("cipher.txt", "w"); // opening the cipher text message file in write

    cbcencrypt(pt, ct, roundkey); // cbc encrypt

    FILE *ct1 = fopen("cipher.txt", "rb");  // opening the previously written cipher tect in read byte mode as it was written in bin encoding
    FILE *pt1 = fopen("decipher.txt", "w"); // opening the file to store decipher ed text

    cbcdecrypt(ct1, pt1); // cbc decrypt
}