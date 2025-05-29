////////////////////////////////////////////////////////////////////////////////
// COMP1521 25T1 --- Assignment 2: `cursed', a file encryption tool
// <https://www.cse.unsw.edu.au/~cs1521/25T1/assignments/ass2/index.html>
//
// 2025-04-02   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>
//
// This program was written by William Chhour (z5585071) on 06/04/2025.

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "cursed.h"

// Add any extra #defines here.

// Add any extra function signatures here.
void print_permissions(mode_t mode);
void search_by_filename_recursive(const char *base, const char *str, char *results[], int *cnt);
int count_matches_in_file(const char *filepath, const char *pattern, int size);
void search_by_content_recursive(const char *base, const char *pattern, int size, content_result *results[], int *cnt);


// Some provided strings which you may find useful. Do not modify.
const char *const MSG_ERROR_FILE_STAT = "Could not stat file.\n";
const char *const MSG_ERROR_FILE_OPEN = "Could not open file.\n";
const char *const MSG_ERROR_CHANGE_DIR = "Could not change directory.\n";
const char *const MSG_ERROR_DIRECTORY =
    "cursed does not support directories.\n";
const char *const MSG_ERROR_READ =
    "group does not have permission to read this file.\n";
const char *const MSG_ERROR_WRITE =
    "group does not have permission to write here.\n";
const char *const MSG_ERROR_RESERVED =
    "'.' and '..' are reserved filenames. Please search for something else.\n";

/////////////////////////////////// SUBSET 0 ///////////////////////////////////

// Print the name of the current directory.
void print_current_directory(void) {
    // Create char array to hold path name
    char pathname[MAX_PATH_LEN];
    // Run getcwd and if it fails print error message
    if (getcwd(pathname, sizeof(pathname)) == NULL) {
        printf("print_current_directory failed");
        return;
    }
    // Print directory
    printf("The current directory is: %s\n", pathname);
}

// Change the current directory to the given pathname.
void change_current_directory(char *directory) {
    // Handle '~' as home directory
    if (strcmp(directory, "~") == 0) {
        directory = getenv("HOME");
        if (directory == NULL) {
            printf("HOME environment variable not set.\n");
            return;
        }
    }
    // Run chdir and if it fails print error message
    if (chdir(directory) != 0) {
        printf(MSG_ERROR_CHANGE_DIR);
        return;
    }
    // Print moving message
    printf("Moving to %s\n", directory);
}

// Print file permissions using a files mode field from the stat struct
void print_permissions(mode_t mode) {
    // Use byte masks to extract the bit in mode which indicates permissions
    printf(S_ISDIR(mode) ? "d" : "-");

    printf((mode & S_IRUSR) ? "r" : "-");
    printf((mode & S_IWUSR) ? "w" : "-");
    printf((mode & S_IXUSR) ? "x" : "-");

    printf((mode & S_IRGRP) ? "r" : "-");
    printf((mode & S_IWGRP) ? "w" : "-");
    printf((mode & S_IXGRP) ? "x" : "-");

    printf((mode & S_IROTH) ? "r" : "-");
    printf((mode & S_IWOTH) ? "w" : "-");
    printf((mode & S_IXOTH) ? "x" : "-");
}

// List the contents of the current directory.
void list_current_directory(void) {
    // Open current directory
    DIR *dir = opendir(".");
    // If fails print error message
    if (dir == NULL) {
        printf(MSG_ERROR_FILE_OPEN);
        return;
    }
    
    // Array of string for filenames
    char *filenames[MAX_LISTINGS];
    int count = 0;
    
    // Make a directory entry struct pointer
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && count < MAX_LISTINGS) {
        // Add to filenames array, using strdup and extracting the entry's name field
        filenames[count] = strdup(entry->d_name);
        if (filenames[count] == NULL) {
            printf("No files in directory");
            closedir(dir);
            return;
        }
        count++;
    }

    closedir(dir);
    // Helper function to sort an array of strings
    sort_strings(filenames, count);

    for (int i = 0; i < count; i++) {
        struct stat sb;
        int result = stat(filenames[i], &sb);
    
        if (result == -1) {
            printf("Error\n");
            free(filenames[i]);
            continue;
        }

        // Call the print permission helper function to print the files permissions
        print_permissions(sb.st_mode);
        // Print the tab space and then the actual filename
        printf("\t%s\n", filenames[i]);
    
        free(filenames[i]); 
    }
}

/////////////////////////////////// SUBSET 1 ///////////////////////////////////

// Check whether the file meets the criteria to be encrypted.
bool is_encryptable(char *filename) {
    // The criteria is:
    // 1.File exists and is stattable 
    // 2.File is a regular file and not a directory
    // 3.File is readable by the group
    // 4.File is writable by the group

    struct stat file_stat;
    // Check if the file exists and can be statted
    if (stat(filename, &file_stat) != 0) {
        printf("%s", MSG_ERROR_FILE_STAT);
        return false;
    }

    // Check if the file is a regular file
    if (!S_ISREG(file_stat.st_mode)) {
        printf("%s", MSG_ERROR_DIRECTORY);
        return false;
    }

    // Check if the group has read permission
    if (!(file_stat.st_mode & S_IRGRP)) {
        printf("%s", MSG_ERROR_READ);
        return false;
    }

    // Determine the target directory as we currently have full file path e.g (a/b/c/file.txt)
    char dir_path[MAX_PATH_LEN];
    // Get last slash
    char *last_slash = strrchr(filename, '/');
    // If last_slash is not NULL extract the directory
    if (last_slash != NULL) {
        // Pointer subtraction to find how much chars the directory is
        size_t dir_len = last_slash - filename;
        if (dir_len == 0) {
            // If file is in root directory
            strcpy(dir_path, "/");
        } else {
            // String copy with the dir_len to fill in the dir_path array with the directory
            strncpy(dir_path, filename, dir_len); 
            // Add null terminator to last index of the array
            dir_path[dir_len] = '\0';
        }
    } else {
        // If no slash, assume current directory (.)
        strcpy(dir_path, ".");
    }

    // Check if the group has write permission to the target directory
    struct stat dir_stat;
    if (stat(dir_path, &dir_stat) != 0) {
        printf("%s", MSG_ERROR_WRITE);
        return false;
    }

    if (!(dir_stat.st_mode & S_IWGRP)) {
        printf("%s", MSG_ERROR_WRITE);
        return false;
    }
    // If all checks pass return true
    return true;
}

// XOR the contents of the given file with a set key, and write the result to
// a new file.
void xor_file_contents(char *src_filename, char *dest_filename) {
    FILE *src = fopen(src_filename, "rb");
    if (src == NULL) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        return;
    }
    
    FILE *dest = fopen(dest_filename, "wb");
    if (dest == NULL) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        fclose(src);
        return;
    }
    // Loop through file by 1024 chars ( 1 kilobyte 1kB)
    unsigned char buffer[1024];
    // fread return size_t similar to int but unsigned and larger (used because fread returns size_t)
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        // Iterate through source file
        for (size_t i = 0; i < bytes_read; i++) {
            // Use key to XOR encrypt the file
            buffer[i] = buffer[i] ^ XOR_BYTE_VALUE;
        }
        // Write to destination file (1024 bytes)
        fwrite(buffer, 1, bytes_read, dest);
    }
    
    fclose(src);
    fclose(dest);
}
/////////////////////////////////// SUBSET 2 ///////////////////////////////////

// Recursively search through all files and folders using the current directory and the string we 
// are searching for then update the results array with the paths to the directories/files
// that contain our string
void search_by_filename_recursive(const char *base, const char *str, char *results[], int *cnt) {
    DIR *d = opendir(base);
    if (d == NULL) {
        return;
    }
    // Initialise a directory entry variable
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        // Skip these 2 as they are to leave
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) {
            continue;
        }

        // String of the path
        char path[MAX_PATH_LEN];
        // . represents current directory 
        if (!strcmp(base, ".")) {
            // If base == "." we are in current directory and the file is ./file.txt
            snprintf(path, MAX_PATH_LEN, "./%s", ent->d_name);
        } else {
            // If base != "." add the entry to the base
            snprintf(path, MAX_PATH_LEN, "%s/%s", base, ent->d_name);
        }
        // strstr checks if the string we are searching for is in the string ent->d_name
        if (strstr(ent->d_name, str) != NULL) {
            if (*cnt < MAX_LISTINGS) {
                // If it is and our counter is less than MAX_LISTINGS add it to the results array
                results[*cnt] = strdup(path);
                (*cnt)++;
            }
        }

        // Initialise stat struct
        struct stat st;
        // Recursively call stat with our file path ensuring it is a directory
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            search_by_filename_recursive(path, str, results, cnt);
        }
    }

    closedir(d);
}

// Search the current directory and its subdirectories for filenames containing
// the search string.
void search_by_filename(char *search_string) {
    // Can't search for . or .. are they have special meanings (current dir) and (parent dir)
    if (!strcmp(search_string, ".") || !strcmp(search_string, "..")) {
        printf("%s", MSG_ERROR_RESERVED);
        return;
    }
    // Initialise the results array
    char *results[MAX_LISTINGS];
    int count = 0;
    // Call our recursive function with our current directory, search string, array and counter
    search_by_filename_recursive(".", search_string, results, &count);
    // Sort the strings using provided helper function
    sort_strings(results, count);
    // Use our counter to print the amount of strings found
    printf("Found in %d filenames.\n", count);
    // For loop that stats each match ground and prints it
    for (int i = 0; i < count; i++) {
        struct stat st;
        if (stat(results[i], &st) == 0) {
            print_permissions(st.st_mode);
            printf("\t%s\n", results[i]);
        }
        // Free our results array preparing it for another search
        free(results[i]);
    }
}

// Search the given file for occurrences of the pattern and return the count
int count_matches_in_file(const char *filepath, const char *pattern, int size) {
    // Open the file in binary mode
    FILE *fp = fopen(filepath, "rb");
    if (fp == NULL) {
        return 0;
    }

    // Initialise a match counter
    int matches = 0;

    // Allocate buffer to hold the sliding window of bytes
    char *buf = malloc(size);
    if (buf == NULL) {
        fclose(fp);
        return 0;
    }

    // Read the first chunk of bytes (equal to the pattern size)
    int bytes = fread(buf, 1, size, fp);
    if (bytes < size) {
        free(buf);
        fclose(fp);
        return 0;
    }

    // Compare the first window of bytes
    if (memcmp(buf, pattern, size) == 0) {
        matches++;
    }

    // Read the file one byte at a time and slide the buffer
    int c;
    while ((c = fgetc(fp)) != EOF) {
        // Shift the buffer left by 1 byte
        memmove(buf, buf + 1, size - 1);
        buf[size - 1] = c;

        // Compare buffer to pattern
        if (memcmp(buf, pattern, size) == 0) {
            matches++;
        }
    }

    free(buf);
    fclose(fp);
    return matches;
}

// Recursively search through base directory and its subdirectories,
// checking each file for the pattern and adding matches to the results array
void search_by_content_recursive(const char *base, const char *pattern, int size, content_result *results[], int *cnt) {
    // Open the directory at the given base path
    DIR *d = opendir(base);
    if (d == NULL) {
        return;
    }

    // Directory entry struct
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        // Skip current and parent directory entries
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        // Create full path to current entry
        char path[MAX_PATH_LEN];
        if (strcmp(base, ".") == 0) {
            snprintf(path, MAX_PATH_LEN, "./%s", ent->d_name);
        } else {
            snprintf(path, MAX_PATH_LEN, "%s/%s", base, ent->d_name);
        }

        // Get information about the file/directory
        struct stat st;
        if (stat(path, &st) != 0) {
            continue;
        }

        // If it's a directory, recurse into it
        if (S_ISDIR(st.st_mode)) {
            search_by_content_recursive(path, pattern, size, results, cnt);
        }

        // If it's a regular file, check for pattern matches
        else if (S_ISREG(st.st_mode)) {
            int m = count_matches_in_file(path, pattern, size);
            if (m > 0 && *cnt < MAX_LISTINGS) {
                content_result *res = malloc(sizeof(content_result));
                res->filename = strdup(path);
                res->matches = m;
                results[(*cnt)++] = res;
            }
        }
    }

    closedir(d);
}

// Search the current directory and its subdirectories for files containing the
// provided search bytes.
void search_by_content(char *search_bytes, int size) {
    content_result *results[MAX_LISTINGS];
    int count = 0;
    search_by_content_recursive(".", search_bytes, size, results, &count);
    sort_content_results(results, count);
    if (count == 1)
        printf("Found in 1 file.\n");
    else
        printf("Found in %d files.\n", count);
    for (int i = 0; i < count; i++) {
        printf("%d: %s\n", results[i]->matches, results[i]->filename);
        free(results[i]->filename);
        free(results[i]);
    }
}

/////////////////////////////////// SUBSET 3 ///////////////////////////////////

// Encrypt a block of plaintext using shift-based ECB encryption and password
char *shift_encrypt(char *plaintext, char password[CIPHER_BLOCK_SIZE]) {
    // Allocate memory to hold ciphertext block
    char *ciphertext = malloc(CIPHER_BLOCK_SIZE);
    // Loop through each byte in the block
    for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
        unsigned char pt = plaintext[i];
        unsigned char pw = password[i] % 8;
        // Left rotate the byte by pw bits
        ciphertext[i] = (pt << pw) | (pt >> (8 - pw));
    }
    return ciphertext;
}

// Decrypt a block of ciphertext using shift-based ECB decryption and password
char *shift_decrypt(char *ciphertext, char password[CIPHER_BLOCK_SIZE]) {
    // Allocate memory to hold plaintext block
    char *plaintext = malloc(CIPHER_BLOCK_SIZE);
    // Loop through each byte in the block
    for (int i = 0; i < CIPHER_BLOCK_SIZE; i++) {
        unsigned char ct = ciphertext[i];
        unsigned char pw = password[i] % 8;   
        // Right rotate the byte by pw bits
        plaintext[i] = (ct >> pw) | (ct << (8 - pw));
    }
    return plaintext;
}

// ECB encryption: take input file, break into blocks, encrypt each with shift_encrypt
void ecb_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    FILE *src = fopen(filename, "rb");
    if (!src) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        return;
    }

    // Create output file name by adding ".ecb" extension
    char output_filename[MAX_PATH_LEN];
    snprintf(output_filename, sizeof(output_filename), "%s.ecb", filename);

    FILE *dest = fopen(output_filename, "wb");
    if (!dest) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        fclose(src);
        return;
    }

    // Get original file size to calculate padding
    fseek(src, 0, SEEK_END);
    long original_size = ftell(src);
    rewind(src);

    // Round file size up to nearest multiple of block size
    long padded_size = ((original_size + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;

    // Buffer to hold each block
    char buffer[CIPHER_BLOCK_SIZE];
    for (long i = 0; i < padded_size; i += CIPHER_BLOCK_SIZE) {
        // Read up to block size bytes from file
        int read_bytes = fread(buffer, 1, CIPHER_BLOCK_SIZE, src);
        // If read less than a full block, pad with null bytes
        for (int j = read_bytes; j < CIPHER_BLOCK_SIZE; j++) {
            buffer[j] = '\0';
        }
        // Encrypt block using shift_encrypt
        char *encrypted = shift_encrypt(buffer, password);
        // Write encrypted block to output file
        fwrite(encrypted, 1, CIPHER_BLOCK_SIZE, dest);
        free(encrypted);
    }

    fclose(src);
    fclose(dest);
}

// ECB decryption: read input file in blocks, decrypt each one, write result to .dec file
void ecb_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    FILE *src = fopen(filename, "rb");
    if (!src) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        return;
    }

    // Create output file name by adding ".dec" extension
    char output_filename[MAX_PATH_LEN];
    snprintf(output_filename, sizeof(output_filename), "%s.dec", filename);

    FILE *dest = fopen(output_filename, "wb");
    if (!dest) {
        printf("%s", MSG_ERROR_FILE_OPEN);
        fclose(src);
        return;
    }

    // Buffer to hold each encrypted block
    char buffer[CIPHER_BLOCK_SIZE];
    // Read exactly one block at a time
    while (fread(buffer, 1, CIPHER_BLOCK_SIZE, src) == CIPHER_BLOCK_SIZE) {
        // Decrypt the block
        char *decrypted = shift_decrypt(buffer, password);
        // Write decrypted block to output file
        fwrite(decrypted, 1, CIPHER_BLOCK_SIZE, dest);
        free(decrypted);
    }

    fclose(src);
    fclose(dest);
}

/////////////////////////////////// SUBSET 4 ///////////////////////////////////

void cbc_encryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    printf("TODO: COMPLETE ME");
}

void cbc_decryption(char *filename, char password[CIPHER_BLOCK_SIZE]) {
    printf("TODO: COMPLETE ME");
}

/////////////////////////////////// PROVIDED ///////////////////////////////////
// Some useful provided functions. Do NOT modify.

// Sort an array of strings in alphabetical order.
// strings:  the array of strings to sort
// count:    the number of strings in the array
// This function is to be provided to students.
void sort_strings(char *strings[], int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            if (strcmp(strings[i], strings[j]) < 0) {
                char *temp = strings[i];
                strings[i] = strings[j];
                strings[j] = temp;
            }
        }
    }
}

// Sort an array of content_result_t in descending order of matches.
// results:  the array of pointers to content_result_t to sort
// count:    the number of pointers to content_result_t in the array
// This function is to be provided to students.
void sort_content_results(content_result *results[], int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < count; j++) {
            if (results[i]->matches > results[j]->matches) {
                content_result *temp = results[i];
                results[i] = results[j];
                results[j] = temp;
            } else if (results[i]->matches == results[j]->matches) {
                // If the matches are equal, sort alphabetically.
                if (strcmp(results[i]->filename, results[j]->filename) < 0) {
                    content_result *temp = results[i];
                    results[i] = results[j];
                    results[j] = temp;
                }
            }
        }
    }
}

// Generate a random string of length RAND_STR_LEN.
// Requires a seed for the random number generator.
// The same seed will always generate the same string.
// The string contains only lowercase + uppercase letters,
// and digits 0 through 9.
// The string is returned in heap-allocated memory,
// and must be freed by the caller.
char *generate_random_string(int seed) {
    if (seed != 0) {
        srand(seed);
    }
    char *alpha_num_str =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    char *random_str = malloc(RAND_STR_LEN);

    for (int i = 0; i < RAND_STR_LEN; i++) {
        random_str[i] = alpha_num_str[rand() % (strlen(alpha_num_str) - 1)];
    }

    return random_str;
}
