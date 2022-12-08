/*
    This is part of the ANGELITA128 encryption system, the source code file for the ANGELITA128 class header
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
	ANGELITA128: Algorithm of Number Generation and Encryption Lightweight Intersperse Transform Automator 128-Bit

	Project Start date: 5-10-2022
	Project Completed: 7-20-2022
	Modified for Linux: 12-02-2022

	ANGELITA128 class

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

#ifndef ANGELITA128_H
#define ANGELITA128_H

#include "ANGELITA128_Exception.h"
#include <array>
#include <vector>

class ANGELITA128 {
private:
	std::array<unsigned char, 16> initialKey0;
	std::array<unsigned char, 16> initialKey1;
	std::array<unsigned char, 2048> keySchedule;
	std::array<unsigned char, 256> Sbox;
	std::array<unsigned char, 64> Pbox;
	std::array<unsigned char, 256> revSbox;
	std::array<unsigned char, 64> revPbox;
	std::array<unsigned char, 1216> KS_SBOX;
	std::array<unsigned char, 9728> KS_SBOX_BITS;
	std::array<unsigned char, 320> KS_PBOX;
	std::array<unsigned char, 2560> KS_PBOX_BITS;
	std::array<unsigned char, 256> KS_XOR1;
	std::array<unsigned char, 256> KS_XOR2;
	bool keySet = 0;
	bool reverseSet = 0;

	std::array<unsigned char, 9728> sp1_8(std::array<unsigned char, 1216> bytes);
	std::array<unsigned char, 2560> sp1_8(std::array<unsigned char, 320> bytes);
	std::array<unsigned char, 64> sp1_4(std::array<unsigned char, 16> bytes);
	std::array<unsigned char, 16> jn4_1(std::array<unsigned char, 64> twoBits);
	std::array<unsigned char, 256> rotateBytes(std::array<unsigned char, 256> bytes);
	std::array<unsigned char, 16> xorBytes(std::array<unsigned char, 16> bytes, unsigned char byte, unsigned int skippedIndex);

	std::array<unsigned char, 256> TeaParty2(std::array<unsigned char, 256> sbox);
	std::array<unsigned char, 64> TeaParty2(std::array<unsigned char, 64> pbox);
	void genSBox();
	void genPBox();
	void genRevSbox();
	void genRevPbox();

	std::array<unsigned char, 2048> ANGELITA128_KISS();
	std::array<unsigned char, 2048> ANGELITA128_KISS2();
	void genKS();

	unsigned char useSBox(unsigned char blockByte);
	std::array<unsigned char, 64> usePBox(std::array<unsigned char, 64> block2bits);
	unsigned char useRevSBox(unsigned char blockByte);
	std::array<unsigned char, 64> useRevPBox(std::array<unsigned char, 64> block2bits);

	std::array<unsigned char, 16> encrypt(std::array<unsigned char, 16> plaintextBlock);
	std::array<unsigned char, 16> decrypt(std::array<unsigned char, 16> ciphertextBlock);

	std::array<unsigned char, 16> GLORIA();

public:
	ANGELITA128();

	//Public interface
	void genKey();
	void setKeyS(std::string keyString);
	void setKeyH(std::string hexString);
	void showKey();
	void encrypt(std::string file, std::string mode);
	void decrypt(std::string file, std::string mode);

};

#endif
