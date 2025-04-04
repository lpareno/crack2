#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *in = fopen(hashFilename, "r");
    if(!in){       
        printf("Can't open hash file\n");
        exit(1);
    }
    // Loop through the hash file, one line at a time.
    char line[HASH_LEN];
    while( fgets(line, HASH_LEN, in) != NULL){

        // Trim newline
        char *newLine = strchr(line, '\n');
        if (newLine) *newLine = '\0';

    // Check if hash of plaintext is the same as the line
        if(strcmp(line, hash) == 0){
            fclose(in);
            return hash;
        }
    }

    fclose(in);
    free(hash);
    return NULL;
}


int main(int argc, char *argv[])
{
    // Checks if all files were given
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    FILE *dict = fopen(argv[2], "r");
    if(!dict){       
        printf("Can't open dictionary file\n");
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char word[PASS_LEN];
    int cracked = 0;
    while( fgets(word, PASS_LEN, dict) != NULL){
    
        // Trim newline
        char *newLine = strchr(word, '\n');
        if (newLine) *newLine = '\0';

        // If we got a match, display the hash and the word
        char *found = tryWord(word, argv[1]);
        if(found != NULL){
            printf("%s %s\n", found, word);
            cracked++;
            free(found);
        }
    }
    // Close the dictionary file.
    fclose(dict);
    // Display the number of hashes that were cracked.
    printf("Number of Cracked Passwords: %d\n", cracked);
}

