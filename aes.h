#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

#define Nb 4
#define Nr 10
#define Nk 4

static uint8_t roundkey[176];

uint8_t input[16];

static uint8_t state[4][4];
uint8_t key[16];
void printstate(uint8_t state[4][4]);

void key_scheudling(uint8_t *roundkey, uint8_t *key);

void decipher(uint8_t state[4][4], uint8_t roundkey[176]);

void cipher(uint8_t state[4][4], uint8_t roundkey[176]);

#endif