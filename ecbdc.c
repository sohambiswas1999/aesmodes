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

int main()
{
    key_scheudling(roundkey, key);

    int fd = open("cipher.txt", O_RDWR);
    int dc = open("decipher.txt", O_RDWR);

    while (1)
    {

        size_t l = read(fd, s, 16);

        printf("%d\n", l);

        if (l <= 0)
        {
            printf("end of file\n");
            break;
        }

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
                s[4 * i + j] = state[i][j];
            }
        }

        int k = write(dc, s, 16);
    }
    close(dc);
    close(fd);
}