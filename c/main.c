/***********************************************************************************************************************
 *  Date:        07 October 2019
 *
 *  Author:      Martin Siddons
 *
 *  Description: C-Language interpretation of a simple Encryption algorithm to be used to better understand what is
 *               required for an ARM Assembly language version of the same code, known as cw1.
 *
 *  History:    07 Oct 2019: v1.00 - Initial layout put together, keyCheck function complete, arguments assigned.
 *              09 Oct 2019: v1.01 - Stripper function wrote.
 *              11 Oct 2019: v1.02 - Encryption function completed.
 *              12 Oct 2019: v1.03 - Decryption complete and all modules are working in Windows + Linux.
 **********************************************************************************************************************/

#include <stdio.h>
#include <string.h>

// Notes for running on Linux:
// gcc main.c -o cw1
// cat textfile.txt | ./cw1 0 lock key | ./cw1 1 lock key
// Run on Windows with PowerShell:
// type .\textfile.txt | .\ARM_C_Code.exe 0 lock key | ./ARM_C_Code.exe 1 lock key | Write-Host

int gcd(int a, int b){ // Function to find the GCD of two numbers, to test if keys lengths are co-prime.
    if (a == b){
        return a; // Return the value of 'a' once GCD has been found.
    }
    if (a > b){
        gcd((a - b), b); // Recursive call - Reduce the value of a and go again.
    }
    else{
        gcd(a, (b - a)); // Recursive call - Reduce the value of b and go again.
    }
    return 0;
}

char stripper(char c){
    if (c > 64 && c < 91){
        return (c + 32); // If the character is upper-case, turn it lower.
    }
    if (c > 122 || c < 97){
        return(0); // If the character isn't lower case, return 0.
    }
    return c; // Return the character as-is if it is lower-case.
}

void encryption(char c, char key1, char key2){
    // we need to compute each key separately as there are not enough bits in a signed byte to hold a-z-z (-147).
    c = c - key1 + 98; // (c - key1) computes the difference between the two letters as a number, +96 turns that
                       // number back into it's letter representation, +2 offsets that letter by 2 (due to the algo).
    if (c < 97){ // wrap the letters back round if they're too low.
        c = c + 26;
    }
    else if (c == 123){ // Special case for 'z' - 'a' = '{'. Reset c to 'a'.
        c = 97;
    }

    c = c - key2 + 98;
    if (c < 97){ // check if letter is less than the value of 'a'.
        putchar(c + 26); // if so, loop it back round and output.
    }
    else if (c == 123) { // Again, special case for 'z' - 'a' = '{'. Output 'a'.
        putchar(97);
    }
    else {
        putchar(c);
    }
}

void decryption(char c, char key1, char key2){
    c = (c - 96) + (key2 - 28); // Values of c greater than 128 cause c to underrun to -127, this stops that by
                                // decreasing the value of c by 96 and key2 by 28. This also saves us having to do -98
                                // after computing the difference between c and key2 to bring c's value back to
                                // it's character value (+2).
    if (c == 70) { // Special case where c = 'a' - 1.
        c = 122;
    }
    if (c < 97){ // If c doesn't loop past z, add 26.
        c = c + 26;
    }

    c = (c - 96) + (key1 - 28); // As above but with key1 instead of key2.
    if (c == 70){
        putchar(122);
    }
    else if (c < 97) {
        putchar(c + 26);
    }
    else {
        putchar(c);
    }
}

int main(int argc, const char *argv[]) {
    //freopen("textfile.txt","r", stdin); // redirect getchar to textfile.txt for debugging.

    const char *mode = argv[1], // Set mode from argument to encryption(0) or decryption(1).
                *key1str = argv[2], // Pointers to refer to command line arguments.
                *key2str = argv[3];

    int key1Len = strlen(key1str); // Assign the length of keys to variables.
    int key2Len = strlen(key2str);
    if (gcd(key1Len, key2Len) != 1){ // Check to see if the key lengths are co-prime. This is the case only when the
                                     // output here is equal to 1. If keys are not co-prime, message is printed.
        printf("Key lengths are not co-prime. \n");
        return 0;
    }

    int charCount = 0; // Set up counters to track which letter of the keys we're using.
    char currentChar, key1Char, key2Char; // Character to check and which characters to pass for en/decryption.

    if (*mode == '0') { // Encryption Mode.
        char stripped; // char to store modified character.
        do{
            currentChar = getchar(); // Pipe in the first character of the message to the program.
            stripped = stripper(currentChar); // Strip out all non-letters and convert caps to lower case.
            key1Char = key1str[charCount % key1Len]; // Set the current key1 and key2 character for the encryption to
            key2Char = key2str[charCount % key2Len]; // 'counter mod keylength', ensuring the correct letter is used.
            if (stripped != 0) { // if the current character can be encrypted, do so otherwise pass.
                encryption(stripped, key1Char, key2Char);
                charCount++; // Increase the counter to drive the next key character settings.
            }
        }
        while (currentChar != 255 && currentChar != -1); // Keep looping in characters until we hit the end of the file
        // character '\xff'. This has two different designations depending on if you're on Unix or Windows, as Unix
        // treats char as unsigned, and Windows treats it as signed.
    }

    else { // Decryption mode.
        do {
            currentChar = getchar();
            if (currentChar != 10 && currentChar != 255 && currentChar != -1) { // Checking for '/n' (added by cat) or '\xff'.
                key1Char = key1str[charCount % key1Len]; // Set the current key1 and key2 character for the decryption
                key2Char = key2str[charCount % key2Len]; // to 'counter mod keylength', ensuring correct letter is used.
                decryption(currentChar, key1Char, key2Char);
                charCount++; // Increase the counter for the next loop's decryption keys.
            }
        }
        while (currentChar != 255 && currentChar != -1); // As before, we're looking for '\xff'.
    }
    putchar('\n'); // add a new line to the output stream to make it clearer to read.
    //fclose(stdin); // close the debug stream.
    return 0;
}