#include <stdio.h>      //printf
#include <stdlib.h>     //random functions
#include <time.h>       //random seed generator

/**
Keygen
================================================================
Program creates key file of specified length from 27 characters (26 Capital + Space).
Last character keygen output will be newline.asm
Error text output to be 'stderr'


gcc --std=gnu99 -o enc_server enc_server.c
gcc --std=gnu99 -o enc_client enc_client.c
gcc --std=gnu99 -o dec_server dec_server.c
gcc --std=gnu99 -o dec_client dec_client.c
gcc --std=gnu99 -o keygen keygen.c
================================================================

source 1: Wikipedia One-Time Pads: https://en.wikipedia.org/wiki/One-time_pad
source 2: GeeksforGeeks: https://www.geeksforgeeks.org/random-password-generator-in-c/ (keygen)
*/

const char randLetters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "; // 26 capital char + space

int main(int argc, char *argv[]){
    //if input is not 2 args (./keygen and "256" - length of chars to run), return error
    if (argc != 2) {
        fprintf(stderr, "Error: number of key characters specified is invalid.\n");
        exit(1);
    }

    int charLength = atoi(argv[1]); //convert string to integer
    srand(time(NULL));  //seed random number generator with cur_time

    for (int i=0; i<charLength; i++){
        printf("%c", randLetters[rand() % 27]);
    }
    printf("\n");   //end with newline
    return 0;
}