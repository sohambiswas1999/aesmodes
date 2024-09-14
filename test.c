#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <fcntl.h>
#include "aes.h"

unsigned char s[16];
unsigned char s1[16];
unsigned char s2[16];
unsigned char s3[16];

void main()
{
    unsigned char s[16] = {0x72, 0x14, 0x70, 0x81, 0xbb, 0xac, 0x1a, 0xc9, 0x45, 0x25, 0xe0, 0x91, 0x25, 0x96, 0xb0, 0xc8};
    int fd = open("test.txt", O_WRONLY | O_TRUNC | O_CREAT, 0600);
    int k = write(fd, s, 16);

    printf("%d", k);
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s[4 * i + 0], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3]);
    }

    unsigned char s1[16] = {0x72, 0x14, 0x72, 0x81, 0xbb, 0xad, 0x1a, 0xc9, 0x45, 0x26, 0xe0, 0x91, 0x25, 0x96, 0xb0, 0xc8};
    int j = write(fd, s1, 16);
    printf("%d", j);
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s1[4 * i + 0], s1[4 * i + 1], s1[4 * i + 2], s1[4 * i + 3]);
    }
    close(fd);

    int fd1 = open("test.txt", O_RDONLY);

    int k1 = read(fd1, s2, 16);

    printf("%d", k1);
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s2[4 * i + 0], s2[4 * i + 1], s2[4 * i + 2], s2[4 * i + 3]);
    }

    int j1 = read(fd1, s1, 16);
    printf("%d", j1);
    for (int i = 0; i < 4; i++)
    {
        printf("%x,%x,%x,%x\n", s3[4 * i + 0], s3[4 * i + 1], s3[4 * i + 2], s3[4 * i + 3]);
    }
    close(fd1);
}