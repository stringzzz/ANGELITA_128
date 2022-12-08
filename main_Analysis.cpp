/*
    This is part of the ANGELITA128 encryption system, the example main for using it (Analysis Version)
    Copyright (C) 2022 stringzzz, Ghostwarez Co.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*

This version is for test and analysis purposes only.

!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!
Also to note, this system hasn't gone through any kind of proper peer review process yet, so it should not be used
for any real secure purposes. You have been warned!
!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!

*/

/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Key Schedule	Bytes	% Key	Key Bytes	Key Bits
;
; S-Box		1216	59.375	9.5		76
; P-Box		320	15.625	2.5		20
; XOR1		256	12.5	2		16
; XOR2		256	12.5	2		16
; Total		2048	100	16		128
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;; ANGELITA128 Algorithm ;;;;;;;;;;;;;;;;;;;
; 1. Choose e/d (encryption/decryption)
; 2. Choose the key option
; 3. Input or generated key is expanded 128 times by
;	the key schedule (KISS)
; 4. The Key Schedule is split, some bytes used
;	to initialize the S-Box and P-Box. The rest is
;	used in the encryption/decryption loop
; 5. The encryption/decryption loop works on 128-Bit
;	blocks, for 16 cycles. Cycle below (Encryption):
;
;	b. XOR with KS 1
;	c. S-Box
;	d. XOR with KS 2
;	e. If cycles is multiple of 2, P-Box the pairs of bits of the block
;
;	Decryption is simply the reverse of this
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
*/

#include <iostream>
#include "ANGELITA128_Analysis.h"

int main() {
    try {
        srand(time(0)); //Do here, not in functions
        ANGELITA128 a1;

        //Do analysis
        
        //a1.GeneralDifference();
        //a1.PlaintextAvalanche();
        //a1.popCountTest();
        //a1.popCountTestBiasedPlaintext(0);
        //a1.popCountTestBiasedPlaintext(1);
        //a1.SboxDifference();
        //a1.KeyAvalanche();
        //a1.popCountTestBiasedPlaintext(85);
        //a1.PlaintextAvalancheExamination();
       
    }
    catch (ANGELITA128_Exception err) {
        std::cout << err.what() << "\n";
        exit(1);
    }
    return 0;
}
