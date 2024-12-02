#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fileutil.h"

// DIRECTIONS
// Choose whether you are doing the 2D array or
// the array of arrays.
// For the 2D array,
//    implement loadFile2D, substringSearch2D, and free2D.
// For the array of arrays, 
//    implement loadFileAA, substringSearchAA, and freeAA.


// Load the text file from the given filename.
// Return a pointer to the array of strings.
// Sets the value of size to be the number of valid
// entries in the array (not the total array length).
char ** loadFileAA(char *filename, int *size)
{
	FILE *in = fopen(filename, "r");
	if (!in)
	{
	    perror("Can't open file");
	    exit(1);
	}
	
	char **arr = NULL; // Array of strings
    int capacity = 0;  // Current allocated capacity
    *size = 0;         // Number of valid entries

    char buffer[1024]; // Buffer for reading each line

    while (fgets(buffer, sizeof(buffer), in)) {

        // Trim newline
        char *nl = strchr(fileName, '\n');
        if(nl) *nl = '\0';

        // Expand array if necessary
        if (*size >= capacity) {
            capacity = capacity == 0 ? 10 : capacity * 2; // Increase capacity
            arr = realloc(arr, capacity * sizeof(char *));
            if (!arr) {
                perror("Realloc failed");
                exit(1);
            }
        }

        // Allocate memory for the string and copy the buffer into it
        arr[*size] = malloc(strlen(buffer) + 1); // +1 for null terminator
        if (!arr[*size]) {
            perror("Malloc failed");
            exit(1);
        }
        strcpy(arr[*size], buffer);
        (*size)++;
    }

    fclose(in);
    return arr;

}

char *substringSearchAA(char *target, char **arr, int size) {
    for (int i = 0; i < size; i++) {
        if (strstr(arr[i], target)) {
            return arr[i]; // Return the first matching string
        }
    }
    return NULL; // Not found
}

char (*loadFile2D(char *filename, int *size))[COLS] {
    FILE *in = fopen(filename, "r");
    if (!in) {
        perror("Can't open file");
        exit(1);
    }

    char (*arr)[COLS] = NULL; // 2D array
    int capacity = 0;         // Current allocated capacity
    *size = 0;                // Number of valid entries

    char buffer[COLS];        // Buffer for reading each line

    while (fgets(buffer, sizeof(buffer), in)) {
        // Trim newline
        char *nl = strchr(fileName, '\n');
        if(nl) *nl = '\0';

        // Expand array if necessary
        if (*size >= capacity) {
            capacity = capacity == 0 ? 10 : capacity * 2; // Increase capacity
            arr = realloc(arr, capacity * sizeof(*arr));
            if (!arr) {
                perror("Realloc failed");
                exit(1);
            }
        }

        // Copy the buffer into the array
        strcpy(arr[*size], buffer);
        (*size)++;
    }

    fclose(in);
    return arr;
}

// Search the array for the target string.
// Return the found string or NULL if not found.
char *substringSearch2D(char *target, char (*arr)[COLS], int size) {
    for (int i = 0; i < size; i++) {
        if (strstr(arr[i], target)) {
            return arr[i]; // Return the first matching line
        }
    }
    return NULL; // Not found
}

// Free the memory used by the array
void freeAA(char **arr, int size) {
    for (int i = 0; i < size; i++) {
        free(arr[i]); // Free each string
    }
    free(arr); // Free the array itself
}


void free2D(char (*arr)[COLS]) {
    free(arr); // Free the entire 2D array
}
