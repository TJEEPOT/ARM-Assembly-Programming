@-----------------------------------------------------------------
@ File:		cw1.s
@
@ Date:		12 October 2019
@
@ Author:	Martin Siddons
@
@ Desc:		A simple Encryption and decryption algorithm
@ 			written in ARMv7 Assembly based off of prototype
@ 			code written in C.
@
@ History:	12 Oct 19: v1.0 - Initial setup.
@			19 Oct 19: v1.1 - Finally worked out loading ARGVs.
@			21 Oct 19: v1.2 - Length of strings found.
@			24 Oct 19: v1.3 - GCD function implemented w/success.
@			26 Oct 19: v1.4 - Stripper function implemented.
@			27 Oct 19: v1.5 - Encryption completed successfully.
@			28 Oct 19: v1.6 - Decryption and testing completed.
@			01 Nov 19: v1.7 - Replaced most comments with C-code.
@
@ Note:		Run with argument -T4 for correct tab formatting.
@-----------------------------------------------------------------
@
.text @ code start
.balign 4 @ word alignment set
.global main
.func main
main:
@ // int main(int argc, const char *argv[]){
@ // This initial block pulls the argvs from r1 and puts them into
@ // registers ready to be used later in en/decryption.
@ // r0 - *mode, r6 - charCount, r7 - *key1str,
@ // r8 - *key2str, r11 - mode value.
	PUSH {r4, lr}		@ //(store the value of lr (padded w/r4))
	LDR r0, [r1, #4]!	@ const char *mode = argv[1]; // (IMM pre-in w/up)
	LDRB r11, [r0]		@ const char mode = *mode; // (pre-in w/reg off)
	LDR r7, [r1, #4]!   @ const char *key1str = argv[2];
	LDR r8, [r1, #4]!	@ const char *key2str = argv[3];
    MOV r6, #0          @ int charCount = 0;

@ // We now need to find the lengths of these keys.
@ // r0 - curKeyChar, r1 - curKey, r2 - i, r9 - key1Len,
@ // r10 - key2Len. r7,r8,r11 as previous.
	MOV r1, r7			@ char* curKey = key1str;
	MOV r9, #0			@ int key1Len = 0;
charprep:				@ do{
	MOV r2, #0			@ int i = 0;
   	LDRB r0, [r1]		@ curKeyChar = curKey[i];
	charloop:				@ do{
		LDRB r0, [r1, #1]!	@ curKeyChar = curKey[i];
		ADD r2, #1			@ i++;
		CMP r0, #0			@ while (curKeyChar =! 0)}
		BNE charloop		@
	CMP r9, #0			@ if (key1Len =! 0){
	MOVNE r10, r2       @ int key2Len = i;
	BNE charlengthcheck	@ }
	MOV r9, r2			@ else {key1Len = i;
	MOV r1, r8			@ curKey = key2str;}
	BEQ charprep		@ while (key1Len != 0)}

charlengthcheck:
@ // Here we branch to a function to work out the gcd of the the
@ // string lengths above and if they're not co-prime, we print
@ // an error message and exit.
@ // r0 - k1Tmp, r1 - k2Tmp, r9,r10 as previous.
	MOV r0, r9			@ k1Tmp = key1Len;
	MOV r1, r10			@ k2Tmp = key2Len;
	BL _gcd				@ int_gcd = gcd(k1Tmp, k2Tmp);
	CMP r0, #1			@ if (gcd == 1){
	BEQ selectmode		@ goto selectmode;} // don't do this in C!
	LDR r0, =notcoprime @ else{ char* msg = "Numbers are not
						@ 					co-prime.\n";
	BL printf			@	 printf("%s", msg);
	B _exit				@	 _exit();}

selectmode:
@ // This section branches to the setup areas for either encryption
@ // or decryption functions depending on value set in r11 earlier.
@ // r11 - mode
	CMP r11, #48		@ if (mode == '0'){
	BEQ encryptsetup	@ 	goto encryptsetup;} // Naughty C!
	CMP r11, #49		@ if (mode == '1'){
	BEQ decryptsetup	@ 	goto decryptsetup;} // Never do in C!
	B _exit				@ else {exit();}

encryptsetup:
@ // For encryption, we need to first strip all unwanted chars
@ // from our input stream and convert those we do want to lower
@ // case, then encrypt the resulting characters using the keys.
@ // This whole process will be performed character by character until
@ // we reach EOF.
@ // r0 - currentChar/ charCntTmp, r1 - keyLenTmp / key1char,
@ // r2 - keystrTmp / key2char, r4 - key1CharTmp, r5 - strippedChar.
@ // r6,r7,r8,r9,r10 as previous.
	BL getchar		@ do { currentChar = getchar();
	CMN r0, #1		@ if (currentChar == 255){
	BEQ _exit		@ 	exit();}
	BL _stripper	@ else { currentChar = stripper(currentChar); }
	CMP r0, #0		@ while (currentChar == 0)
	BEQ encryptsetup@ }
	MOV r5, r0		@ char strippedChar = currentChar;
	MOV r0, r6		@ int charCntTmp = charCount;
	MOV r1, r9		@ int keyLenTmp = key1Len;
	MOV r2, r7		@ char* keystrTmp = *key1str;
	BL _countermodkey @ int tmp = _countermodkey(charCntTmp,
					@				 keyLenTmp, keystrTmp);
	MOV r4, r0		@ char key1CharTmp = tmp;
	MOV r0, r6		@ charCntTmp = charCount;
	MOV r1, r10		@ keyLenTmp = key2Len;
	MOV r2, r8		@ keystrTmp = key2Len;
	BL _countermodkey @ tmp = _countermodkey(charCntTmp,
                    @                keyLenTmp, keystrTmp);
	MOV r2, r0		@ key2char = tmp;
	MOV r1, r4		@ key1char = key1CharTmp;
	MOV r0, r5		@ currentChar = strippedChar;
	BL _encryption	@ _encryption(currentChar, key1char, key2char);
	ADD r6, r6, #1	@ charCount++;
	B encryptsetup	@ while (currentChar != 255)}

decryptsetup:
@ // For decryption, we only need to find the correct key character and
@ // pass the resulting characters along with the current char to be
@ // decrypted to the decryption function.
@ // r0 - currentChar/ charCntTmp, r1 - keyLenTmp / key1char,
@ // r2 - keystrTmp / key2char, r4 - key1CharTmp, r5 - strippedChar.
@ // r6,r7,r8,r9,r10 as previous.
	BL getchar		@ do { currentChar = getchar();
	CMN r0, #1      @ if (currentChar == 255){
    BEQ _exit       @   exit();}
	CMP r0, #97		@ if (currentChar < 97){ // (value of 'a')
	BLT decryptsetup@	goto decryptsetup;} // (catching spare new-lines)
	MOV r5, r0		@ char strippedChar = currentChar;
	MOV r0, r6		@ int charCntTmp = charCount;
	MOV r1, r9		@ int keyLenTmp = key1Len;
	MOV r2, r7		@ char* keystrTmp = *key1str;
	BL _countermodkey @ int tmp = _countermodkey(charCntTmp,
                    @                keyLenTmp, keystrTmp);
    MOV r4, r0      @ char key1CharTmp = tmp;
    MOV r0, r6      @ charCntTmp = charCount;
    MOV r1, r10     @ keyLenTmp = key2Len;
    MOV r2, r8      @ keystrTmp = key2Len;
    BL _countermodkey @ tmp = _countermodkey(charCntTmp,
                    @                keyLenTmp, keystrTmp);
    MOV r2, r0      @ key2char = tmp;
    MOV r1, r4      @ key1char = key1CharTmp;
    MOV r0, r5      @ currentChar = strippedChar;
	BL _decryption	@ _encryption(currentChar, key1char, key2char);
	ADD r6, r6, #1	@ charCount++;
	B decryptsetup	@ while (currentChar != 255)}


@ // The below code is a set of functions, either void or with
@ // return which should only be reached via specific calls to them.

_exit:		@ void _exit(){
@ // Return:	Program exits correctly.
@ // A simple function to write a new line and exit the program.
@ // r0 - msg.
	MOV r0, #10		@ char* msg = "\n";
	BL putchar		@ putchar(msg);
	POP {r4, lr}	@ //(pop the original lr from the stack)
	BX lr			@ return 0;}

_gcd:		@ int _gcd(int a, int b){
@ // Return:	The lowest value both numbers divide into, in r0.
@ // This function finds the GCD through recursion and returns it
@ // via r0. I chose to unwind the recursion after computation despite
@ // it not being necessary in ARM ASM as it would otherwise be an
@ // incorrect implementation of recursion.
@ // r0 - int a, r1 - int b.
	CMP r0, r1		@ if (a == b){
	MOVEQ pc, lr	@ 	return a;}
	STR lr, [sp, #-4]! @ // (save lr for the recursive call)
	SUBGT r0, r0, r1@ if (a > b){ a = a - b;
	BLGT _gcd		@	_gcd(a, b);}
	LDREQ pc, [sp], #4 @ return a; // (lr to pc to unwind - IMM post-ind)
	SUBLT r1, r1, r0@ else { b = b - a;
	BLLT _gcd		@ 	_gcd(a, b);}
	LDREQ pc, [sp], #4 @ return a;} // (load lr to pc to unwind)

_stripper:	@ char _stripper(char c){
@ // Return:	A char between a-z, or 0, in r0.
@ // This function will strip out all non-lower-case letters from the
@ // output stream by converting upper case characters to lower case
@ // and returning 0x0 if the passed char is outside the range of
@ // upper and lower case letters.
@ // r0 - char c.
	CMP r0, #64		@ if (c < 64){ // (value for 'A')
	MOVLE r0, #0	@ 	c = 0;
	MOVLE pc, lr	@ 	return c;}
	CMP r0, #91		@ if (c > 91){ // (value for 'Z')
	BGE lowercheck	@ 	goto lowercheck;} // (lowercase letter check)
	ADD r0, r0, #32 @ c = c + 32; // (convert from upper to lowercase)
	MOV pc, lr		@ return c;
	lowercheck:
		CMP r0, #122	@ if (c > 122){ // (is c > 'z'?)
		MOVGT r0, #0	@ 	c = 0;
		MOVGT pc, lr	@ 	return c;}
		CMP r0, #97		@ if (c < 97){ // otherwise is c < 'a'?)
		MOVLT r0, #0	@ 	c = 0;}
		MOV pc, lr		@ 	return c;} // (return what's left)

_countermodkey:	@ char _countermodkey(int charCount, int keyLen,
@										char *keyAddress){
@ // Return:	A character selected from the key string in r0.
@ // This function computes charCount MOD keyLen in order to return
@ // the correct key char for encryption or decryption. This was
@ // seperated from the main function to make the code easier to read.
@ // r0 - int charCount, r1 - int keyLen, r2 - char *keyAddress.
	CMP r0, r1			@ do{ if (charCount >= keyLen){
	SUBGE r0, r0, r1	@ 	charCount = charCount - keyLen;}
	BGE _countermodkey	@ while (charCount >= keyLen)}
	LDRB r0, [r2, r0]	@ char c = keyAddress[charCount];
	MOV pc, lr			@ return c;}

_encryption:	@ void _encryption(char c, char key1Char,
@									char key2Char){
@ // Require:	Three chars- the stripped char and both key chars.
@ // This function performs a simple calculation on the given inputs
@ // in order to generated the expected output. Care was taken to ensure
@ // each loop ends with a character between a-z to keep values from
@ // overflowing outside of 0-127 and potentially causing issues.
@ // r0 - char c, r1 - char key1Char, r2 - char key2Char,
@ // r3 - int keyFlag.
	PUSH {r4, lr}	@ // (save lr to stack, 32 byte aligned)
	MOV r3, #1		@ int keyFlag = 1;
	encryptionloop:
		CMP r3, #1		@ {if (keyFlag == 1){
		SUBEQ r0, r0, r1@ 	c = c - key1Char;}
		SUBNE r0, r0, r2@ else {c = c - key2Char;}
		ADD r0, r0, #98	@ c = c + 98 // (turn difference to a letter)
		CMP r0, #97		@ if (c < 97){ // (if c < 'a')
		ADDLT r0, #26	@	c = c + 26; // (loop to top of alphabet)
		CMPGE r0, #123	@ else if (c > 123){ // (the char 'z')
		MOVEQ r0, #97	@ 	c = 'a';}
		CMP r3, #1		@ if (keyFlag = 1){
		MOVEQ r3, #2	@ 	keyFlag = 2; // (now working on key2)
		BEQ encryptionloop@ goto encryptionloop;}
	BL putchar		@ putchar(c);}
	POP {r4, lr}	@ // (return the lr value from the stack)
	MOV pc, lr		@ // (exit function)

_decryption:	@ void _decryption(char c, char key1char,
@									char key2char);
@ // Return:	A decrypted char in r0.
@ // Similar to the encryption function, however this function returns
@ // the given encrypted char to its decrypted form, allowing messages
@ // to be recovered.
@ // r0 - char c, r1 - char key1Char, r2 - char key2Char,
@ // r3 - int keyFlag.
    PUSH {r4, lr}   @ // (save lr to stack, 32 byte aligned)
	SUB r1, #28		@ key1Char = key1Char - 28; //(underflow protection)
	SUB r2, #28		@ key2Char = key2Char - 28;
    MOV r3, #2		@ int keyFlag = 2;
	decryptionloop:
		SUB r0, r0, #96		@ {c = c - 96 // (underflow protection)
		CMP r3, #2			@ if (keyFlag == 2){
		ADDEQ r0, r0, r2	@ 	c = c + key2Char;}
		ADDNE r0, r0, r1	@ else {c = c + key1char;}
		CMP r0, #70			@ if (c == 70){ // (value 'a' - 24 - 1)
		MOVEQ r0, #122		@ 	c = 122;} // (character 'z')
		CMP r0, #97			@ if (c < 97){ // (outside 'a'-'z')
		ADDLT r0, r0, #26	@ c = c + 26;} // (pull value back up)
		CMP r3, #2			@ if (keyFlag = 2){
		MOVEQ r3, #1		@ 	keyFlag = 1;}
		BEQ decryptionloop	@ goto decryptionloop;}
	BL putchar		@ putchar(c);
	POP {r4, lr}	@ // (return the value of lr from the stack)
    MOV pc, lr      @ // (exit function)


.data
.balign 4
notcoprime:	@ // message to be printed when _gcd returns >1.
	.asciz "Key lengths are not co-prime.\n"
