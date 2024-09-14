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
    int fd = open("input.txt", O_RDONLY);

    int fdcipher = open("cipher.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

    if (fd == -1)
    {
        printf("file not opened\n");
    }

    int j = read(fd, s, 16);
    while (j > 0)
    {

        // j = read(fd, s, 16);

        printf("%d\n", j);

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
        printf("written on output");
        for (int i = 0; i < 4; i++)
        {
            printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
        }

        int k = write(fdcipher, s, 16);

        printf("%d\n", k);
        j = read(fd, s, 16);
    }
    close(fdcipher);
    close(fd);
    printf("end of cipher\n");

    int fd_r = open("cipher.txt", O_RDONLY);
    int dc = open("decipher.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);

    size_t l = read(fd_r, s, 16);
    while (l > 0)
    {

        printf("%d", l);

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
        l = read(fd_r, s, 16);
    }
    close(dc);
    close(fd_r);
}