# ANGELITA_128
An 128-bit SPN Symmetric Block Cipher, not yet peer reviewed

There are two versions contained here, one for general use, and the other ones for analysis purposes. 
The analysis source code has the name "Analysis" in the files, while the remainder is for general purpose. 
Note again that this algorithm hasn't gone through the peer review process, so it can't be deemed anywhere near secure.
As such, do not use this algorithm for any real secure purposes.

Refer to the PDF to see some of my own analysis of the algorithm. The analysis version is designed for easy testing, 
and can be easily modified for further testing. 

The main features of this encryption algorithm are its key-dependent S-Box and P-Box, with the idea of preventing typical modern
cryptanalytic attacks on it, though any proof of this resistance has yet to be found.
