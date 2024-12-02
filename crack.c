#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"
#include "fileutil.h"

#define PASS_LEN 50     // Maximum length any password will be.
#define HASH_LEN 33     // Length of hash plus one for null.

// Comparison function for qsort and bsearch
int compare(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s hash_file dictionary_file\n", argv[0]);
        exit(1);
    }

    // Load the hashes into memory
    int hashCount;
    char **hashes = loadFileAA(argv[1], &hashCount);
    if (!hashes) {
        fprintf(stderr, "Failed to load hash file.\n");
        exit(1);
    }

    // Sort the hashes for binary search
    qsort(hashes, hashCount, sizeof(char *), compare);

    // Open the dictionary file
    FILE *dictFile = fopen(argv[2], "r");
    if (!dictFile) {
        fprintf(stderr, "Failed to open dictionary file.\n");

        // Free each string in the hash array and the array itself
        for (int i = 0; i < hashCount; i++) {
            free(hashes[i]);
        }
        free(hashes);
        exit(1);
    }

    char buffer[PASS_LEN];
    int foundCount = 0;

    // Process each word in the dictionary
    while (fgets(buffer, sizeof(buffer), dictFile)) {
        // Trim newline
        char *nl = strchr(buffer, '\n');
        if(nl) *nl = '\0';

        // Hash the password
        char *hashedPassword = md5(buffer, strlen(buffer));
        if (!hashedPassword) {
            fprintf(stderr, "Failed to hash password: %s\n", buffer);
            continue;
        }

        // Perform binary search for the hash
        char **found = bsearch(&hashedPassword, hashes, hashCount, sizeof(char *), compare);
        if (found) {
            printf("Found: %s %s\n", *found, buffer);
            foundCount++;
        }

        // Free the hashed password
        free(hashedPassword);
    }

    // Cleanup
    fclose(dictFile);

    // Free memory allocated for hashes
    for (int i = 0; i < hashCount; i++) {
        free(hashes[i]); // Free each string
    }
    free(hashes); // Free the array itself

    printf("Number of hashes cracked: %d\n", foundCount);

    return 0;
}
