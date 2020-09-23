# What It Does #
This program takes a given file (textfile.txt) and either encodes or decodes it using two private keys known to both parties, implementing a lowercase-only simple ROT Cypher based off the given keys. The project is written in both C and ARM Assembly and both versions give the same output when correctly run with the same arguments.

The program first checks that the two given keys are co-prime. That is, the Greatest Common Denominator of the lengths of the two keys is 1 (for example, the words "lock" and "key"). If this is true, the program then checks if it needs to encode or decode the given message. If encoding, it will stream the message from stdin, ignoring all non-letters (including spaces) and converting upper case letters to lower-case. It then encrypts the message over two stages, first by converting the ASCII value of the current message letter to a number (a=1, b=2 etc) then doing the same with the current first key letter and taking the value of the key from the value of the message and adding two, looping back round to 26 if the letter value drops below 0. It then takes this intermediate value and does the same with the second key letter's value, removing that from the intermediate value and adding two to produce the final value. Finally, this value is converted back into the correct ASCII letter and streamed to stdout. 

For example, if our textfile.txt contained the word 'message', our first key was 'lock' and our second key was 'key' the following would happen:
* 'm' from the stream is converted to its value by removing 96 (13), as is 'l' from the first key to get 12
* We take the first key value (12) from the message (13) to leave 1, then add 2 to get our intermediate value (3)
* 'k' from our second key is converted to its value (11)
* We take the second key value (11) from the intermediate value (3) and 2 is added to get our final value (-8)
* The final value is corrected to ensure it remains between 1 and 26 by adding 26 and 2 is added to get the corrected final value (20), which is converted to it's ASCII character value 't'.

This then continues character by character for the rest of the streamed word:
'e' - ('o' - 'e' + 2) + 2 = 'o'
'y' - ('c' - 's' + 2) + 2 = 'u'
'k' - ('k' - 's' + 2) + 2 = 'a'
'e' - ('l' - 'a' + 2) + 2 = 'n'
'y' - ('o' - 'g' + 2) + 2 = 'w'
'k' - ('c' - 'e' + 2) + 2 = 'u'

Decryption does this same process but in reverse.

# What I Learned #
This project taught me the basics of **cryptography** as well as gave some further experience to coding in **C** and an intro to coding in **ARMv7 Assembly**. To complete the ARM portion, I had to connect to a remote Raspberry Pi running **Arch Linux** using **PuTTY** and code in a **terminal environment** using **nano**, and using **GDB** for debugging. I also learned how to use the basics of a **makefile** to make compiling using **GCC** easier. Finally, this was the first project I wrote that could accept **command line arguments**, so I learned about how to find those arguments in the registers or stack in Assembly, and how to reference the argument values in C.

# Usage Notes #
## For C ##
Compile with GCC on Linux with the command 
<pre><code>gcc main.c -o cw1</code></pre>
Execute on Linux by piping your text file to be encoded into the program and using the following command line switches:
<pre><code>cw1 [0|1] [firstKey] [secondKey]</code></pre>
Where the first option refers to the mode, either Encryption (0) or Decryption (1) and the second and third options are the two given keys. An example usage could be the following:
<pre><code>cat textfile.txt | ./cw1 0 lock key</code></pre>
You could also encrypt and decrypt the same text to test the system works correctly:
<pre><code>cat textfile.txt | ./cw1 0 lock key | ./cw1 1 lock key</code></pre>

## For ARMv7 ASM ##
A makefile has been included with the ASM code to make it easier to compile with GCC in Linux (on an ARMv7 compatible device, such as a Raspberry Pi). Navigate to the 'assembly' project directory and type
<pre><code>make</code></pre>
to build the project. Running the project is the same as with C above, using the command line options 
<pre><code>cw1 [0|1] [firstKey] [secondKey].</code></pre>