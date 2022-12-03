/*
    This is part of the ANGELITA128 encryption system, the source code file containing the ANGELITA128 class methods (Analysis version)
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

	ANGELITA128 Analysis class methods

!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!
Also to note, this system hasn't gone through any kind of proper peer review process yet, so it should not be used
for any real secure purposes. You have been warned!
!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!

*/

/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Key Schedule	Bytes	% Key	Key Bytes	Key Bits
;
; S-Box			1216	59.375	9.5			76
; P-Box			320		15.625	2.5			20
; XOR1			256		12.5	2			16
; XOR2			256		12.5	2			16
; Total			2048	100		16			128
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

#include "ANGELITA128_Analysis.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <regex>
#include <sstream>
#include <iomanip>

std::array<unsigned char, 9728> ANGELITA128::sp1_8(std::array<unsigned char, 1216> bytes) {
	//Split list of Key Schedule bytes into bits for use in TeaParty2 for the S-Box
	std::array<unsigned char, 9728> bits;
	int i = 0;
	for (unsigned int n = 0; n < 1216; n++) {
		bits[i] = bytes[n] >> 7;
		i++;
		for (int n2 = 2; n2 <= 8; n2++) {
			bits[i] = (bytes[n] >> (8 - n2)) & 1;
			i++;
		}
	}
	return bits;
}

std::array<unsigned char, 2560> ANGELITA128::sp1_8(std::array<unsigned char, 320> bytes) {
	//Split list of Key Schedule bytes into bits for use in TeaParty2 for the P-Box
	std::array<unsigned char, 2560> bits;
	int i = 0;
	for (unsigned int n = 0; n < 320; n++) {
		bits[i] = bytes[n] >> 7;
		i++;
		for (int n2 = 2; n2 <= 8; n2++) {
			bits[i] = (bytes[n] >> (8 - n2)) & 1;
			i++;
		}
	}
	return bits;
}

std::array<unsigned char, 64> ANGELITA128::sp1_4(std::array<unsigned char, 16> bytes) {
	//Split a block of bytes into a block of 2-bits
	std::array<unsigned char, 64> twoBits;
	for (int n = 0, m = 0; m < 64; n++) {
		twoBits[m] = bytes[n] >> 6;
		m++;
		twoBits[m] = (bytes[n] >> 4) & 3;
		m++;
		twoBits[m] = (bytes[n] >> 2) & 3;
		m++;
		twoBits[m] = bytes[n] & 3;
		m++;
	}
	return twoBits;
}

std::array<unsigned char, 16> ANGELITA128::jn4_1(std::array<unsigned char, 64> twoBits) {
	//Join a block of 2-bits into a block of bytes
	std::array<unsigned char, 16> bytes;
	for (int n = 0, m = 0; m < 64; n++) {
		bytes[n] = ((twoBits[m] << 6) ^ (twoBits[m + 1] << 4) ^ (twoBits[m + 2] << 2) ^ (twoBits[m + 3])) & 255;
		m += 4;
	}
	return bytes;
}

std::array<unsigned char, 256> ANGELITA128::rotateBytes(std::array<unsigned char, 256> bytes) {
	//Move the leftmost bit to the right side of byte
	for (int i = 0; i < 256; i++) {
		bytes[i] = ((bytes[i] >> 7) ^ (bytes[i] << 1)) & 255;
	}
	return bytes;
}

std::array<unsigned char, 16> ANGELITA128::xorBytes(std::array<unsigned char, 16> bytes, unsigned char byte, unsigned int skippedIndex) {
	//XOR block with the byte, skip the index where the byte came from
	for (int i = 0; i < 16; i++) {
		if (i == skippedIndex) {
			continue;
		}
		bytes[i] ^= byte;
	}
	return bytes;
}

std::array<unsigned char, 256> ANGELITA128::TeaParty2(std::array<unsigned char, 256> sbox) {
	//Generate the S-Box dependent on the Key Schedule bits
	//Shuffle 256 bytes 38 times
	std::array<unsigned char, 256> TeaCup1;
	std::array<unsigned char, 256> TeaCup2;
	unsigned int KS_Counter = 0;
	this->KS_SBOX_BITS = this->sp1_8(this->KS_SBOX);
	for (unsigned int shuffles = 1; shuffles <= 38; shuffles++) {
		unsigned int TeaCupCounter1 = 0;
		unsigned int TeaCupCounter2 = 0;
		for (unsigned int boxBytes = 0; boxBytes < 256; boxBytes++) {
			if (this->KS_SBOX_BITS[KS_Counter] == 1) {
				TeaCup1[TeaCupCounter1] = sbox[boxBytes];
				TeaCupCounter1++;
			}
			else {
				TeaCup2[TeaCupCounter2] = sbox[boxBytes];
				TeaCupCounter2++;
			}
			KS_Counter++;
		}
		unsigned int i = 0;
		//sbox = TeaCup2 + TeaCup1 (Concatenated)
		for (unsigned int j = 0; j < TeaCupCounter2; i++, j++) {
			sbox[i] = TeaCup2[j];
		}
		for (unsigned int j = 0; j < TeaCupCounter1; i++, j++) {
			sbox[i] = TeaCup1[j];
		}
	}
	return sbox;
}

std::array<unsigned char, 64> ANGELITA128::TeaParty2(std::array<unsigned char, 64> pbox) {
	//Generate the P-Box dependent on the Key Schedule bits
	//Shuffle 64 bytes 40 times
	std::array<unsigned char, 64> TeaCup1;
	std::array<unsigned char, 64> TeaCup2;
	unsigned int KS_Counter = 0;
	this->KS_PBOX_BITS = this->sp1_8(this->KS_PBOX);
	for (unsigned int shuffles = 1; shuffles <= 40; shuffles++) {
		unsigned int TeaCupCounter1 = 0;
		unsigned int TeaCupCounter2 = 0;
		for (unsigned int boxBytes = 0; boxBytes < 64; boxBytes++) {
			if (this->KS_PBOX_BITS[KS_Counter] == 1) {
				TeaCup1[TeaCupCounter1] = pbox[boxBytes];
				TeaCupCounter1++;
			}
			else {
				TeaCup2[TeaCupCounter2] = pbox[boxBytes];
				TeaCupCounter2++;
			}
			KS_Counter++;
		}
		unsigned int i = 0;
		//pbox = TeaCup2 + TeaCup1 (Concatenated)
		for (unsigned int j = 0; j < TeaCupCounter2; i++, j++) {
			pbox[i] = TeaCup2[j];
		}
		for (unsigned int j = 0; j < TeaCupCounter1; i++, j++) {
			pbox[i] = TeaCup1[j];
		}
	}
	return pbox;
}

void ANGELITA128::genSBox() {
	//Create the S-Box, starting with default values
	std::array<unsigned char, 256> sbox;
	for (unsigned int n = 0; n < 256; n++) {
		sbox[n] = n;
	}
	sbox = this->TeaParty2(sbox);
	this->Sbox = sbox;
}

void ANGELITA128::genPBox() {
	//Create the P-Box, starting with default values
	std::array<unsigned char, 64> pbox;
	for (unsigned int n = 0; n < 64; n++) {
		pbox[n] = n;
	}
	pbox = this->TeaParty2(pbox);
	this->Pbox = pbox;
}

void ANGELITA128::genRevSbox() {
	//Create the reverse S-Box from the S-Box
	std::array<unsigned char, 256> rsbox;
	for (unsigned int i = 0; i < 256; i++) {
		rsbox[this->Sbox[i]] = i;
	}
	this->revSbox = rsbox;
}

void ANGELITA128::genRevPbox() {
	//Create the reverse P-Box from the P-Box
	std::array<unsigned char, 64> rpbox;
	for (unsigned int i = 0; i < 64; i++) {
		rpbox[this->Pbox[i]] = i;
	}
	this->revPbox = rpbox;
}

std::array<unsigned char, 2048> ANGELITA128::ANGELITA128_KISS() {
	//Expands the 128-bit key 128 times
	//First generate 256 bytes from the initial key by repeated XOR of 1 byte per block
	//Next generate 7 more 256 byte blocks by rotating the bits on the first block, 
	//then the next from that block, etc.
	//Lastly, run the working Key Schedule through a P-Box and S-Box twice, where the boxes are generated
	//using bytes from the working Key Schedule
	std::array<unsigned char, 2048> KS_ALL;
	unsigned int KS_Counter = 0;
	std::array<unsigned char, 16> block = this->initialKey1;
	std::array<unsigned char, 16> xorBlock;
	std::array<unsigned char, 256> rotateBlock;
	for (unsigned int xors = 0; xors < 16; xors++) {
		xorBlock = this->xorBytes(block, block[xors], xors);
		for (unsigned int i = 0; i < 16; i++) {
			KS_ALL[KS_Counter] = xorBlock[i];
			KS_Counter++;
		}
	}

	for (unsigned int i = 0; i < 256; i++) {
		rotateBlock[i] = KS_ALL[i];
	}
	for (unsigned int rotates = 1; rotates <= 7; rotates++) {
		rotateBlock = this->rotateBytes(rotateBlock);
		for (unsigned int i = 0; i < 256; i++) {
			KS_ALL[KS_Counter] = rotateBlock[i];
			KS_Counter++;
		}
	}

	for (unsigned mixes = 1; mixes <= 2; mixes++) {
		for (unsigned int i = 0; i < 320; i++) {
			this->KS_PBOX[i] = KS_ALL[i];
		}

		this->genPBox();
		std::array<unsigned char, 16> pBlock;
		unsigned int pBlockCounter = 0;
		for (unsigned int i = 1; i <= 128; i++) {
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				pBlock[j] = KS_ALL[pBlockCounter];
			}

			pBlock = this->jn4_1(this->usePBox(this->sp1_4(pBlock)));
			pBlockCounter -= 16;
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				KS_ALL[pBlockCounter] = pBlock[j];
			}
		}

		for (unsigned int i = 0; i < 1216; i++) {
			this->KS_SBOX[i] = KS_ALL[i];
		}
		this->genSBox();
		for (unsigned int i = 0; i < 2048; i++) {
			KS_ALL[i] = this->useSBox(KS_ALL[i]);
		}
	}


	return KS_ALL;
}

std::array<unsigned char, 2048> ANGELITA128::ANGELITA128_KISS2() {
	//Expands the 128-bit key 128 times
	//First generate 256 bytes from the initial key by repeated XOR of 1 byte per block
	//Next generate 7 more 256 byte blocks by rotating the bits on the first block, 
	//then the next from that block, etc.
	//Lastly, run the working Key Schedule through a P-Box and S-Box twice, where the boxes are generated
	//using bytes from the working Key Schedule
	
	//Then XOR all the Key Schedule blocks together to make a temp key
	//Generate new Key Schedule from the temp key, and set S-Box and P-Box
	//Encrypt the original Key Schedule with CBC mode (Except IV is last block instead of PRNG value)
	std::array<unsigned char, 2048> KS_ALL;
	unsigned int KS_Counter = 0;
	std::array<unsigned char, 16> block = this->initialKey1;
	std::array<unsigned char, 16> xorBlock;
	std::array<unsigned char, 256> rotateBlock;
	for (unsigned int xors = 0; xors < 16; xors++) {
		xorBlock = this->xorBytes(block, block[xors], xors);
		for (unsigned int i = 0; i < 16; i++) {
			KS_ALL[KS_Counter] = xorBlock[i];
			KS_Counter++;
		}
	}

	for (unsigned int i = 0; i < 256; i++) {
		rotateBlock[i] = KS_ALL[i];
	}
	for (unsigned int rotates = 1; rotates <= 7; rotates++) {
		rotateBlock = this->rotateBytes(rotateBlock);
		for (unsigned int i = 0; i < 256; i++) {
			KS_ALL[KS_Counter] = rotateBlock[i];
			KS_Counter++;
		}
	}

	for (unsigned mixes = 1; mixes <= 2; mixes++) {
		for (unsigned int i = 0; i < 320; i++) {
			this->KS_PBOX[i] = KS_ALL[i];
		}

		this->genPBox();
		std::array<unsigned char, 16> pBlock;
		unsigned int pBlockCounter = 0;
		for (unsigned int i = 1; i <= 128; i++) {
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				pBlock[j] = KS_ALL[pBlockCounter];
			}

			pBlock = this->jn4_1(this->usePBox(this->sp1_4(pBlock)));
			pBlockCounter -= 16;
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				KS_ALL[pBlockCounter] = pBlock[j];
			}
		}

		for (unsigned int i = 0; i < 1216; i++) {
			this->KS_SBOX[i] = KS_ALL[i];
		}
		this->genSBox();
		for (unsigned int i = 0; i < 2048; i++) {
			KS_ALL[i] = this->useSBox(KS_ALL[i]);
		}
	}

	//Create an initial key by XORing the Key Schedule together
	std::array<unsigned char, 16> spongeBlock;
	for (unsigned int i = 0; i < 16; i++) {
		spongeBlock[i] = KS_ALL[i];
	}

	unsigned int KS_INDEX = 16;
	for (unsigned int blockCount = 1; blockCount <= 127; blockCount++) {
		for (unsigned int i = 0; i < 16; i++, KS_INDEX++) {
			spongeBlock[i] ^= KS_ALL[KS_INDEX];
		}
	}
	std::array<unsigned char, 2048> tempKS = KS_ALL;
	std::array<unsigned char, 2064> tempKS2;

	//Use temp key to generate the temp Key Schedule, S-Box, and P-Box
	this->initialKey1 = spongeBlock;
	this->keySchedule = this->ANGELITA128_KISS();

	unsigned int KS_Counter2 = 0;
	for (unsigned int i = 0; i < 1216; i++, KS_Counter2++) {
		this->KS_SBOX[i] = this->keySchedule[KS_Counter2];
	}
	for (unsigned int i = 0; i < 320; i++, KS_Counter2++) {
		this->KS_PBOX[i] = this->keySchedule[KS_Counter2];
	}
	for (unsigned int i = 0; i < 256; i++, KS_Counter2++) {
		this->KS_XOR1[i] = this->keySchedule[KS_Counter2];
	}
	for (unsigned int i = 0; i < 256; i++, KS_Counter2++) {
		this->KS_XOR2[i] = this->keySchedule[KS_Counter2];
	}
	this->genSBox();
	this->genPBox();

	//Encrypt the original Key Schedule blocks with the temp setup, modified CBC mode
	//(IV is last block instead of PRNG)
	std::array<unsigned char, 16> plaintextBlock2;
	for (unsigned int i = 0, j = 2032; i < 16; i++, j++) {
		plaintextBlock2[i] = tempKS[j];
	}
	std::array<unsigned char, 16> plaintextBlock1;
	unsigned int blockIndex = 0;
	unsigned int blockIndex2 = 0;
	for (unsigned int blockNumber = 1; blockNumber <= 128; blockNumber++) {
		for (unsigned int i = 0; i < 16; i++, blockIndex++) {
			plaintextBlock1[i] = tempKS[blockIndex];
		}
		for (unsigned int i = 0; i < 16; i++) {
			plaintextBlock1[i] ^= plaintextBlock2[i];
		}

		for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
			tempKS2[blockIndex2] = plaintextBlock2[i];
		}
		plaintextBlock2 = this->encrypt(plaintextBlock1);

	}
	for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
		tempKS2[blockIndex2] = plaintextBlock2[i];
	}

	//Remove the IV from the Key Schedule and put the rest into KS_ALL
	for (unsigned int i = 0, j = 16; i < 2048; i++, j++) {
		KS_ALL[i] = tempKS2[j];
	}

	return KS_ALL;
}

void ANGELITA128::genKS() {
	//Generate the Key Schedule from the initial key and split it into groups
	this->keySchedule = this->ANGELITA128_KISS2();

	unsigned int KS_Counter = 0;
	for (unsigned int i = 0; i < 1216; i++, KS_Counter++) {
		this->KS_SBOX[i] = this->keySchedule[KS_Counter];
	}
	for (unsigned int i = 0; i < 320; i++, KS_Counter++) {
		this->KS_PBOX[i] = this->keySchedule[KS_Counter];
	}
	for (unsigned int i = 0; i < 256; i++, KS_Counter++) {
		this->KS_XOR1[i] = this->keySchedule[KS_Counter];
	}
	for (unsigned int i = 0; i < 256; i++, KS_Counter++) {
		this->KS_XOR2[i] = this->keySchedule[KS_Counter];
	}
}


unsigned char ANGELITA128::useSBox(unsigned char blockByte) {
	//S-Box, substitute input byte with byte from the S-Box
	return this->Sbox[blockByte];
}

std::array<unsigned char, 64> ANGELITA128::usePBox(std::array<unsigned char, 64> twoBits) {
	//P-Box, permute the input 2-bits according to the P-Box indexes
	std::array<unsigned char, 64> pTwoBits;
	for (unsigned int i = 0; i < 64; i++) {
		pTwoBits[this->Pbox[i]] = twoBits[i];
	}
	return pTwoBits;
}

unsigned char ANGELITA128::useRevSBox(unsigned char blockByte) {
	//Reverse S-Box, substitute input byte with byte from reverse S-Box
	return this->revSbox[blockByte];
}

std::array<unsigned char, 64> ANGELITA128::useRevPBox(std::array<unsigned char, 64> twoBits) {
	//Reverse P-Box, permute the input 2-bits according to the reverse P-Box indexes
	std::array<unsigned char, 64> pTwoBits;
	for (unsigned int i = 0; i < 64; i++) {
		pTwoBits[this->revPbox[i]] = twoBits[i];
	}
	return pTwoBits;
}

std::array<unsigned char, 16> ANGELITA128::encrypt(std::array<unsigned char, 16> plaintextBlock) {
	//Encryption routine
	//16 cycles:
	//XOR with Key Schedule byte 1
	//S-Box
	//XOR with Key Schedule byte 2
	//Every 2 cycles, run block through P-Box
	unsigned int KS_XOR1_Counter = 0;
	unsigned int KS_XOR2_Counter = 0;
	for (unsigned int cycles = 1; cycles <= 16; cycles++) {
		if (cycles % 2 == 0) {
			plaintextBlock = this->jn4_1(this->usePBox(this->sp1_4(plaintextBlock)));
		}
		for (int i = 0; i < 16; i++, KS_XOR1_Counter++, KS_XOR2_Counter++) {
			plaintextBlock[i] ^= this->KS_XOR1[KS_XOR1_Counter];
			plaintextBlock[i] = this->useSBox(plaintextBlock[i]);
			plaintextBlock[i] ^= this->KS_XOR2[KS_XOR2_Counter];
		}
	}
	return plaintextBlock;
}

std::array<unsigned char, 16> ANGELITA128::decrypt(std::array<unsigned char, 16> ciphertextBlock) {
	//Decryption routine
	//16 cycles going 16..0 (Decreasing):
	//Every cycles mod 2 == 0, reverse P-Box
	//XOR with Key Schedule byte 2
	//Reverse S-Box
	//XOR with Key Schedule byte 1
	unsigned int KS_XOR1_Counter = 255;
	unsigned int KS_XOR2_Counter = 255;
	for (unsigned int cycles = 16; cycles > 0; cycles--) {
		for (int i = 15; i >= 0; i--, KS_XOR1_Counter--, KS_XOR2_Counter--) {
			ciphertextBlock[i] ^= this->KS_XOR2[KS_XOR2_Counter];
			ciphertextBlock[i] = this->useRevSBox(ciphertextBlock[i]);
			ciphertextBlock[i] ^= this->KS_XOR1[KS_XOR1_Counter];
		}
		if (cycles % 2 == 0) {
			ciphertextBlock = this->jn4_1(this->useRevPBox(this->sp1_4(ciphertextBlock)));
		}
	}
	return ciphertextBlock;
}

std::array<unsigned char, 16> ANGELITA128::GLORIA() {
	//GLORIA: Generator of Lovely Random Intersperse Automator
	//First generate 2048 prng bytes
	//Then using these bytes to generate the S-Box and P-Box each cycle,
	//Run through P-Box and S-Box for 3 cycles, creating new S-Box and P-Box each time
	//Also used to genrate the IV for CBC mode

	//Store current S-Box and P-Box to avoid issues

	//!!!!!!!!!!!!!!!!!!!!!
	//srand(time(0)); //Uncomment for regular use, otherwise use in main code for testing purposes
	//!!!!!!!!!!!!!!!!!!!!!
	
	std::array<unsigned char, 256> SboxT = this->Sbox;
	std::array<unsigned char, 64> PboxT = this->Pbox;

	std::array<unsigned char, 2048> RNG_POOL;
	for (unsigned int i = 0; i < 2048; i++) {
		RNG_POOL[i] = rand() % 256;
	}

	for (unsigned mixes = 1; mixes <= 3; mixes++) {
		for (unsigned int i = 0; i < 320; i++) {
			this->KS_PBOX[i] = RNG_POOL[i];
		}

		this->genPBox();
		std::array<unsigned char, 16> pBlock;
		unsigned int pBlockCounter = 0;
		for (unsigned int i = 1; i <= 128; i++) {
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				pBlock[j] = RNG_POOL[pBlockCounter];
			}

			pBlock = this->jn4_1(this->usePBox(this->sp1_4(pBlock)));
			pBlockCounter -= 16;
			for (unsigned int j = 0; j < 16; j++, pBlockCounter++) {
				RNG_POOL[pBlockCounter] = pBlock[j];
			}
		}

		for (unsigned int i = 0; i < 1216; i++) {
			this->KS_SBOX[i] = RNG_POOL[i];
		}
		this->genSBox();
		for (unsigned int i = 0; i < 2048; i++) {
			RNG_POOL[i] = this->useSBox(RNG_POOL[i]);
		}
	}

	std::array<unsigned char, 16> spongeBlock;
	for (unsigned int i = 0; i < 16; i++) {
		spongeBlock[i] = RNG_POOL[i];
	}
	unsigned int RNG_INDEX = 16;
	for (unsigned int blockCount = 1; blockCount <= 127; blockCount++) {
		for (unsigned int i = 0; i < 16; i++, RNG_INDEX++) {
			spongeBlock[i] ^= RNG_POOL[RNG_INDEX];
		}
	}

	//Restore the original S-Box and P-Box
	this->Sbox = SboxT;
	this->Pbox = PboxT;

	return spongeBlock;
}

std::array<unsigned char, 128> ANGELITA128::sp1_8(std::array<unsigned char, 16> bytes) {
	std::array<unsigned char, 128> bits;
	int i = 0;
	for (unsigned int n = 0; n < 16; n++) {
		bits[i] = bytes[n] >> 7;
		i++;
		for (int n2 = 2; n2 <= 8; n2++) {
			bits[i] = (bytes[n] >> (8 - n2)) & 1;
			i++;
		}
	}
	return bits;
}

std::array<unsigned char, 2048> ANGELITA128::sp1_8(std::array<unsigned char, 256> bytes) {
	std::array<unsigned char, 2048> bits;
	int i = 0;
	for (unsigned int n = 0; n < 256; n++) {
		bits[i] = bytes[n] >> 7;
		i++;
		for (int n2 = 2; n2 <= 8; n2++) {
			bits[i] = (bytes[n] >> (8 - n2)) & 1;
			i++;
		}
	}
	return bits;
}

double ANGELITA128::H(std::array<unsigned char, 16> beforeBlock, std::array<unsigned char, 16> afterBlock) {
	std::array<unsigned char, 16> distance;
	for (unsigned int i = 0; i < 16; i++) {
		distance[i] = beforeBlock[i] ^ afterBlock[i];
	}
	std::array<unsigned char, 128> diffBits = sp1_8(distance);
	double popCount = 0;
	for (unsigned int i = 0; i < 128; i++) {
		popCount += diffBits[i];
	}
	return popCount;
}

double ANGELITA128::H(std::array<unsigned char, 256> beforeBlock, std::array<unsigned char, 256> afterBlock) {
	std::array<unsigned char, 256> distance;
	for (unsigned int i = 0; i < 256; i++) {
		distance[i] = beforeBlock[i] ^ afterBlock[i];
	}
	std::array<unsigned char, 2048> diffBits = sp1_8(distance);
	double popCount = 0;
	for (unsigned int i = 0; i < 2048; i++) {
		popCount += diffBits[i];
	}
	return popCount;
}

double ANGELITA128::getAverage(std::vector<double> differences) {
	double sum = 0;
	for (int i = 0; i < differences.size(); i++) {
		sum += differences[i];
	}
	return (sum / differences.size());
}

void ANGELITA128::setKeyA(std::array<unsigned char, 16> keyArray) {
	this->initialKey0 = keyArray;
	this->initialKey1 = keyArray;
	this->genKS();
	this->genSBox();
	this->genPBox();
	this->keySet = 1;
	this->reverseSet = 0;
}

unsigned int ANGELITA128::getPopCount(std::array<unsigned char, 16> ciphertextBlock) {
	std::array<unsigned char, 128> ciphertextBits = this->sp1_8(ciphertextBlock);
	unsigned int popCount = 0;
	for (unsigned int n = 0; n < 128; n++) {
		popCount += ciphertextBits[n];
	}
	return popCount;
}


///////////////////
//Public interface
///////////////////

ANGELITA128::ANGELITA128() {

}

void ANGELITA128::genKey() {
	//Generate a new prng key
	//Also create the key schedule, S-Box and P-Box from it
	this->initialKey0 = this->GLORIA();
	this->initialKey1 = initialKey0;
	this->genKS();
	this->genSBox();
	this->genPBox();
	this->keySet = 1;
	this->reverseSet = 0;
}

void ANGELITA128::setKeyS(std::string keyString) {
	//Set the key as a 16 character string
	//Also create the key schedule, S-Box and P-Box from it
	if (keyString.length() > 16) {
		throw ANGELITA128_Exception("ANGELITA128: Key as string must be exactly 16 characters, input key is greater then 16 characters.");
	}
	if (keyString.length() < 16) {
		throw ANGELITA128_Exception("ANGELITA128: Key as string must be exactly 16 characters, input key is less then 16 characters.");
	}

	for (unsigned int i = 0; i < 16; i++) {
		this->initialKey0[i] = (unsigned char)keyString[i];
	}
	this->initialKey1 = this->initialKey0;
	this->genKS();
	this->genSBox();
	this->genPBox();
	this->keySet = 1;
	this->reverseSet = 0;
}

void ANGELITA128::setKeyH(std::string hexString) {
	//Set the key as a 32 digit hexadecimal string
	//Also create the key schedule, S-Box and P-Box from it
	if (hexString.length() > 32) {
		throw ANGELITA128_Exception("ANGELITA128: Key as hex string must be exactly 32 digits, input key is greater than 32 digits.");
	}
	if (hexString.length() < 32) {
		throw ANGELITA128_Exception("ANGELITA128: Key as hex string must be exactly 32 digits, input key is less than 32 digits.");
	}

	unsigned int j = 0;
	for (size_t i = 0; i < 32; i += 2, j++) {
		std::istringstream strm(hexString.substr(i, 2));
		int h;
		strm >> std::hex >> h;
		this->initialKey0[j] = h;
	}
	this->initialKey1 = this->initialKey0;
	this->genKS();
	this->genSBox();
	this->genPBox();
	this->keySet = 1;
	this->reverseSet = 0;
}

void ANGELITA128::showKey() {
	//Output the key as a 32 digit hexadecimal string to the console
	std::cout << "Key: ";
	//Store old cout state:
	std::ios oldState(nullptr);
	oldState.copyfmt(std::cout);

	//Output hexadecimal digits to console:
	std::cout << std::hex << std::setfill('0');
	for (unsigned int i = 0; i < 16; i++) {
		std::cout << std::setw(2) << (int)this->initialKey0[i];
	}
	std::cout << "\n";

	//Restore old cout state
	std::cout.copyfmt(oldState);
}

void ANGELITA128::encrypt(std::string file, std::string mode) {
	//Encrypt the file using the set key and either "ecb" or "cbc" mode
	//ecb: Electronic Code Book mode
	//cbc: Cipher Block Chaining mode
	if (!keySet) {
		throw ANGELITA128_Exception("ANGELITA128: Key must be set to encrypt.");
	}
	if (mode != "ecb" && mode != "cbc") {
		throw ANGELITA128_Exception("ANGELITA128: Invalid encrypt mode, must be \"ecb\" or \"cbc\".");
	}

	//Input file as chars
	std::streampos size;
	std::ifstream fileHandle(file, std::ios::in | std::ios::binary | std::ios::ate);
	size = fileHandle.tellg();
	std::vector <char> inputFile0;
	inputFile0.resize(size);
	if (fileHandle.is_open()) {
		fileHandle.seekg(0, std::ios::beg);
		fileHandle.read(&inputFile0[0], size);
		fileHandle.close();
	}
	else {
		throw ANGELITA128_Exception("ANGELITA128: Could not open file for read and encrypt.");
	}

	//Convert input to unsigned chars
	std::vector <unsigned char> inputFile;
	inputFile.resize(size);
	for (unsigned int i = 0; i < inputFile0.size(); i++) {
		inputFile[i] = (reinterpret_cast<unsigned char&>(inputFile0[i]));
	}

	//Use padding to make 16n blocks even
	unsigned int paddingSize = 16 - (inputFile.size() % 16);
	for (unsigned int i = 0; i < paddingSize; i++) {
		inputFile.push_back((unsigned char)paddingSize);
	}

	//Resize output vector
	std::vector <unsigned char> outputFile1;
	if (mode == "ecb") {
		outputFile1.resize(size + (std::streampos)paddingSize);
	}
	else if (mode == "cbc") {
		outputFile1.resize(size + (std::streampos)paddingSize + (std::streampos)16);
	}

	//Encrypt either ecb or cbc mode
	unsigned blockCount = inputFile.size() / 16;
	if (mode == "ecb") {
		std::array<unsigned char, 16> plaintextBlock;
		unsigned int blockIndex = 0;
		unsigned int blockIndex2 = 0;
		for (unsigned int blockNumber = 0; blockNumber < blockCount; blockNumber++) {
			for (unsigned int i = 0; i < 16; i++, blockIndex++) {
				plaintextBlock[i] = inputFile[blockIndex];
			}
			plaintextBlock = this->encrypt(plaintextBlock);
			for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
				outputFile1[blockIndex2] = plaintextBlock[i];
			}
		}
	}
	else if (mode == "cbc") {
		std::array<unsigned char, 16> plaintextBlock2 = this->GLORIA();
		std::array<unsigned char, 16> plaintextBlock1;
		unsigned int blockIndex = 0;
		unsigned int blockIndex2 = 0;
		for (unsigned int blockNumber = 1; blockNumber <= blockCount; blockNumber++) {
			for (unsigned int i = 0; i < 16; i++, blockIndex++) {
				plaintextBlock1[i] = inputFile[blockIndex];
			}
			for (unsigned int i = 0; i < 16; i++) {
				plaintextBlock1[i] ^= plaintextBlock2[i];
			}

			for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
				outputFile1[blockIndex2] = plaintextBlock2[i];
			}
			plaintextBlock2 = this->encrypt(plaintextBlock1);

		}
		for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
			outputFile1[blockIndex2] = plaintextBlock2[i];
		}

	}

	//Make char output for file write
	std::vector <char> outputFile2;
	std::streampos size2;
	if (mode == "ecb") {
		size2 = size + (std::streampos)paddingSize;
	}
	else if (mode == "cbc") {
		size2 = size + (std::streampos)paddingSize + (std::streampos)16;
	}
	outputFile2.resize(size2);

	//Convert unsigned char to char
	for (unsigned int i = 0; i < outputFile1.size(); i++) {
		outputFile2[i] = (reinterpret_cast<char&>(outputFile1[i]));
	}

	//Output the encrypted file bytes
	std::ofstream file2(file, std::ios::out | std::ios::binary);
	if (file2.is_open()) {
		file2.write(&outputFile2[0], size2);
		file2.close();
	}
	else {
		throw ANGELITA128_Exception("ANGELITA128: Could not open file for write after encrypt.");
	}

	//Rename the encrypted file with the new extension
	std::string newFileName = file + ".ANGELITA128";
	std::string sysOut = "mv " + file + " " + newFileName;
	char* sysOutc = new char[150];
	unsigned int i = 0;
	for (; i < sysOut.length(); i++) {
		sysOutc[i] = sysOut[i];
	}
	sysOutc[i] = '\0';
	system(sysOutc);
	delete[] sysOutc;
}

void ANGELITA128::decrypt(std::string file, std::string mode) {
	//Decrypt the file using the set key and either "ecb" or "cbc" mode
	//ecb: Electronic Code Book mode
	//cbc: Cipher Block Chaining mode
	if (!this->keySet) {
		throw ANGELITA128_Exception("ANGELITA128: Key must be set to decrypt.");
	}
	if (mode != "ecb" && mode != "cbc") {
		throw ANGELITA128_Exception("ANGELITA128: Invalid decrypt mode, must be \"ecb\" or \"cbc\".");
	}

	//If reverse S-Box and P-Box are not set, set them
	if (!this->reverseSet) {
		this->genRevSbox();
		this->genRevPbox();
		this->reverseSet = 1;
	}

	//Input the file to decrypt
	std::streampos size;
	std::ifstream fileHandle(file, std::ios::in | std::ios::binary | std::ios::ate);
	size = fileHandle.tellg();
	std::vector <char> inputFile0;
	inputFile0.resize(size);
	if (fileHandle.is_open()) {
		fileHandle.seekg(0, std::ios::beg);
		fileHandle.read(&inputFile0[0], size);
		fileHandle.close();
	}
	else {
		throw ANGELITA128_Exception("ANGELITA128: Could not open file for read and encrypt.");
	}

	//Convert char to unsigned char
	std::vector <unsigned char> inputFile;
	inputFile.resize(size);
	std::vector <unsigned char> outputFile1;
	if (mode == "ecb") {
		outputFile1.resize(size);
	}
	else if (mode == "cbc") {
		outputFile1.resize(size - (std::streampos)16);
	}
	for (unsigned int i = 0; i < inputFile0.size(); i++) {
		inputFile[i] = (reinterpret_cast<unsigned char&>(inputFile0[i]));
	}

	//Decrypt in either ecb or cbc mode
	unsigned int blockCount = inputFile.size() / 16;
	if (mode == "ecb") {
		std::array<unsigned char, 16> ciphertextBlock;
		unsigned int blockIndex = 0;
		unsigned int blockIndex2 = 0;
		for (unsigned int blockNumber = 0; blockNumber < blockCount; blockNumber++) {
			for (unsigned int i = 0; i < 16; i++, blockIndex++) {
				ciphertextBlock[i] = inputFile[blockIndex];
			}
			ciphertextBlock = this->decrypt(ciphertextBlock);
			for (unsigned int i = 0; i < 16; i++, blockIndex2++) {
				outputFile1[blockIndex2] = ciphertextBlock[i];
			}
		}
	}
	else if (mode == "cbc") {
		std::array<unsigned char, 16> ciphertextBlock1;
		std::array<unsigned char, 16> ciphertextBlock2;
		int blockIndex = inputFile.size() - 1;
		int blockIndex2 = outputFile1.size() - 1;
		for (unsigned int blockNumber = blockCount; blockNumber > 1; blockNumber--) {
			if (blockNumber == blockCount) {
				for (int i = 15; i >= 0; i--, blockIndex--) {
					ciphertextBlock1[i] = inputFile[blockIndex];
				}
			}
			ciphertextBlock2 = this->decrypt(ciphertextBlock1);
			for (int i = 15; i >= 0; i--, blockIndex--) {
				ciphertextBlock1[i] = inputFile[blockIndex];
			}
			for (int i = 0; i < 16; i++) {
				ciphertextBlock2[i] ^= ciphertextBlock1[i];
			}
			for (int i = 15; i >= 0; i--, blockIndex2--) {
				outputFile1[blockIndex2] = ciphertextBlock2[i];
			}
		}
	}

	//Get the padding size and remove the padding from decrypted output
	unsigned int paddingSize = outputFile1[outputFile1.size() - 1];
	outputFile1.erase(outputFile1.end() - paddingSize, outputFile1.end());

	//Get the adjusted size minus the padding or IV for cbc mode
	std::streampos size2;
	if (mode == "ecb") {
		size2 = size - (std::streampos)paddingSize;
	}
	else if (mode == "cbc") {
		size2 = size - (std::streampos)paddingSize - (std::streampos)16;
	}
	std::vector <char> outputFile2;
	outputFile2.resize(size2);

	//Convert decrypted output in unsigned chars into chars
	for (unsigned int i = 0; i < outputFile1.size(); i++) {
		outputFile2[i] = (reinterpret_cast<char&>(outputFile1[i]));
	}

	//Output decrypted file
	std::ofstream file2(file, std::ios::out | std::ios::binary);
	if (file2.is_open()) {
		file2.write(&outputFile2[0], size2);
		file2.close();
	}
	else {
		throw ANGELITA128_Exception("ANGELITA128: Could not open file for write after decrypt.");
	}

	//Remove the "ANGELITA128" extension from the file name
	std::string newFileName = std::regex_replace(file, std::regex("(\\.ANGELITA128)$"), "");
	std::string sysOut = "mv " + file + " " + newFileName;
	char* sysOutc = new char[150];
	unsigned int i = 0;
	for (; i < sysOut.length(); i++) {
		sysOutc[i] = sysOut[i];
	}
	sysOutc[i] = '\0';
	system(sysOutc);
	delete[] sysOutc;
}

//The following methods are for analysis purposes

void ANGELITA128::GeneralDifference() {
	std::array<unsigned char, 16> testBlock;
	std::array<unsigned char, 16> beforeBlock;
	std::array<unsigned char, 16> afterBlock;
	std::vector<double> differences;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int bCount = 1; bCount <= 7500; bCount++) {
		std::cout << "Testing block: " << bCount << "/7500\n";
		testBlock = this->GLORIA();
		this->genKey();
		for (unsigned int n = 0; n < 16; n++) {
			for (unsigned int m = 0; m < 8; m++) {
				beforeBlock = testBlock;
				beforeBlock[n] ^= (1 << m);
				afterBlock = this->encrypt(beforeBlock);
				differences.push_back(this->H(beforeBlock, afterBlock));
				if (differences[differences.size() - 1] < lowCase) {
					lowCase = differences[differences.size() - 1];
				}
				if (differences[differences.size() - 1] > highCase) {
					highCase = differences[differences.size() - 1];
				}
			}
		}
	}
	std::cout << "\nGeneral difference 7500 block Test Complete.\nAverage difference between plaintext and ciphertext: " << this->getAverage(differences) << "/128 bits\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\n";
}

void ANGELITA128::PlaintextAvalanche() {
	std::array<unsigned char, 16> testBlockBefore;
	std::array<unsigned char, 16> testBlockAfter;
	std::array<unsigned char, 16> beforeBlock;
	std::array<unsigned char, 16> afterBlock;
	std::vector<double> differences;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int bCount = 1; bCount <= 7500; bCount++) {
		std::cout << "Testing block: " << bCount << "/7500\n";
		testBlockBefore = this->GLORIA();
		this->genKey();
		testBlockAfter = this->encrypt(testBlockBefore);
		for (unsigned int n = 0; n < 16; n++) {
			for (unsigned int m = 0; m < 8; m++) {
				beforeBlock = testBlockBefore;
				beforeBlock[n] ^= (1 << m);
				afterBlock = this->encrypt(beforeBlock);
				differences.push_back(this->H(testBlockAfter, afterBlock));
				if (differences[differences.size() - 1] < lowCase) {
					lowCase = differences[differences.size() - 1];
				}
				if (differences[differences.size() - 1] > highCase) {
					highCase = differences[differences.size() - 1];
				}
			}
		}
	}
	std::cout << "\nPlaintext Avalanche 7500 block Test Complete.\nChange in 1 bit of plaintext averaged: " << this->getAverage(differences) << "/128 bits of difference in the ciphertext\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\n";
}

void ANGELITA128::KeyAvalanche() {
	std::array<unsigned char, 16> testKey;
	std::array<unsigned char, 16> changedKey;
	std::array<unsigned char, 16> originalBlockBefore;
	std::array<unsigned char, 16> originalBlockAfter;
	std::array<unsigned char, 16> afterBlock;
	std::vector<double> differences;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int kCount = 1; kCount <= 1000; kCount++) {
		std::cout << "Testing key: " << kCount << "/1000\n";
		originalBlockBefore = this->GLORIA();
		this->genKey();
		testKey = this->initialKey1;
		originalBlockAfter = this->encrypt(originalBlockBefore);
		for (unsigned int n = 0; n < 16; n++) {
			for (unsigned int m = 0; m < 8; m++) {
				changedKey = testKey;
				changedKey[n] ^= (1 << m);
				this->setKeyA(changedKey);
				//this->showKey();	//Show each key in test
				afterBlock = this->encrypt(originalBlockBefore);
				differences.push_back(this->H(originalBlockAfter, afterBlock));
				if (differences[differences.size() - 1] < lowCase) {
					lowCase = differences[differences.size() - 1];
				}
				if (differences[differences.size() - 1] > highCase) {
					highCase = differences[differences.size() - 1];
				}
			}
		}
	}
	std::cout << "\nKey Avalanche 1000 key Test Complete.\nChange in 1 bit of key averaged: " << this->getAverage(differences) << "/128 bits of difference in the ciphertext\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\n";
}

void ANGELITA128::SboxDifference() {
	std::array<unsigned char, 256> inputs;
	std::vector<double> differences;
	double lowCase = 2048;
	double highCase = 0;
	for (unsigned int n = 0; n < 256; n++) {
		inputs[n] = n;
	}
	for (unsigned int sbCounts = 1; sbCounts <= 40000; sbCounts++) {
		std::cout << "Testing Pseudo-Random S-Box: " << sbCounts << "/40000\n";
		this->genKey();
		differences.push_back(H(inputs, this->Sbox));
		if (differences[differences.size() - 1] < lowCase) {
			lowCase = differences[differences.size() - 1];
		}
		if (differences[differences.size() - 1] > highCase) {
			highCase = differences[differences.size() - 1];
		}
	}
	std::cout << "\nS-Box Distance 40000 S-Box Test Complete.\nS-Box Distance Average: " << this->getAverage(differences) << "/2048\nLow case: " << lowCase << "/2048\nHigh case: " << highCase << "/2048\n";
}

void ANGELITA128::popCountTest() {
	std::array<unsigned char, 16> testBlockBefore;
	std::array<unsigned char, 16> testBlockAfter;
	std::vector<double> popCounts;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int blockCount = 1; blockCount <= 500; blockCount++) {
		std::cout << "Testing block: " << blockCount << "/500\n";
		testBlockBefore = this->GLORIA();
		for (unsigned int keyCount = 1; keyCount <= 50; keyCount++) {
			this->genKey();
			testBlockAfter = this->encrypt(testBlockBefore);
			popCounts.push_back(this->getPopCount(testBlockAfter));
			if (popCounts[popCounts.size() - 1] < lowCase) {
				lowCase = popCounts[popCounts.size() - 1];
			}
			if (popCounts[popCounts.size() - 1] > highCase) {
				highCase = popCounts[popCounts.size() - 1];
			}
		}
	}
	std::cout << "\nPop Count Test of 500 blocks with 50 keys per block complete.\nAverage number of 1s in the ciphertext: " << this->getAverage(popCounts) << "/128\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\n";
}

void ANGELITA128::popCountTestBiasedPlaintext(unsigned int biasedByte) {
	std::array<unsigned char, 16> testBlockBefore;
	std::array<unsigned char, 16> testBlockAfter;
	std::vector<double> popCounts;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int n = 0; n < 16; n++) {
		testBlockBefore[n] = biasedByte;
	}
	for (unsigned int keyCount = 1; keyCount <= 20000; keyCount++) {
		this->genKey();
		std::cout << "Testing key: " << keyCount << "/20000\n";
		testBlockAfter = this->encrypt(testBlockBefore);
		popCounts.push_back(this->getPopCount(testBlockAfter));
		if (popCounts[popCounts.size() - 1] < lowCase) {
			lowCase = popCounts[popCounts.size() - 1];
		}
		if (popCounts[popCounts.size() - 1] > highCase) {
			highCase = popCounts[popCounts.size() - 1];
		}
	}
	std::cout << "\nPop Count Test of all " << biasedByte << " block with 20,000 keys complete.\nAverage number of 1s in the ciphertext : " << this->getAverage(popCounts) << "/128\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\n";
}

void ANGELITA128::showKeySchedule() {
	for (unsigned int n = 0; n < 2048; n++) {
		if (n != 0 && n % 16 == 0) {
			std::cout << "\n";
		}
		std::cout << (unsigned int)this->keySchedule[n] << " ";
	}
}

void ANGELITA128::outputKeySchedule(std::string fileName) {
	std::ofstream fileHandle(fileName, std::ios::app);
	if (fileHandle.is_open()) {
		//Output the key as a 32 digit hexadecimal string to the file
		fileHandle << "Key: ";
		//Store old cout state:
		std::ios oldState(nullptr);
		oldState.copyfmt(fileHandle);

		//Output hexadecimal digits to console:
		fileHandle << std::hex << std::setfill('0');
		for (unsigned int i = 0; i < 16; i++) {
			fileHandle << std::setw(2) << (int)this->initialKey0[i];
		}
		fileHandle << "\n\n";

		//Restore old cout state
		fileHandle.copyfmt(oldState);
		for (unsigned int n = 0; n < 2048; n++) {
			if (n != 0 && n % 16 == 0) {
				fileHandle << "\n";
			}
			fileHandle << (unsigned int)this->keySchedule[n] << " ";
		}
		fileHandle << "\n\n";
	}
	fileHandle.close();
}

void ANGELITA128::PlaintextAvalancheExamination() {
	std::array<unsigned char, 16> testBlockBefore;
	std::array<unsigned char, 16> testBlockAfter;
	std::array<unsigned char, 16> beforeBlock;
	std::array<unsigned char, 16> afterBlock;
	std::vector<double> differences;
	unsigned int ones = 0;
	double lowCase = 128;
	double highCase = 0;
	for (unsigned int bCount = 1; bCount <= 50000; bCount++) {
		std::cout << "Testing block: " << bCount << "/50000\n";
		testBlockBefore = this->GLORIA();
		this->genKey();
		testBlockAfter = this->encrypt(testBlockBefore);
		for (unsigned int n = 0; n < 16; n++) {
			for (unsigned int m = 0; m < 8; m++) {
				beforeBlock = testBlockBefore;
				beforeBlock[n] ^= (1 << m);
				afterBlock = this->encrypt(beforeBlock);
				differences.push_back(this->H(testBlockAfter, afterBlock));
				if (differences[differences.size() - 1] < lowCase) {
					lowCase = differences[differences.size() - 1];
				}
				if (differences[differences.size() - 1] > highCase) {
					highCase = differences[differences.size() - 1];
				}
				if (differences[differences.size() - 1] == 1) {
					ones++;
					std::ofstream fileHandle("PlaintextAvalanche1BitsVersion4B.txt", std::ios::app);
					if (fileHandle.is_open()) {
						fileHandle << "Num: " << ones << "\n";
						//Output the key as a 32 digit hexadecimal string to the file
						fileHandle << "Key: ";
						//Store old cout state:
						std::ios oldState(nullptr);
						oldState.copyfmt(fileHandle);

						//Output hexadecimal digits to console:
						fileHandle << std::hex << std::setfill('0');
						for (unsigned int i = 0; i < 16; i++) {
							fileHandle << std::setw(2) << (int)this->initialKey0[i];
						}
						fileHandle << "\n\n";

						//Restore old cout state
						fileHandle.copyfmt(oldState);

						fileHandle << "Plaintext Before change: \n";
						for (unsigned int n2 = 0; n2 < 16; n2++) {
							fileHandle << (unsigned int)testBlockBefore[n2] << " ";
						}
						fileHandle << "\n\nPlaintext After change: \n";

						for (unsigned int n2 = 0; n2 < 16; n2++) {
							fileHandle << (unsigned int)beforeBlock[n2] << " ";
						}

						fileHandle << "\n\nCiphertext Before change: \n";
						for (unsigned int n2 = 0; n2 < 16; n2++) {
							fileHandle << (unsigned int)testBlockAfter[n2] << " ";
						}
						fileHandle << "\n\nCiphertext After change: \n";

						for (unsigned int n2 = 0; n2 < 16; n2++) {
							fileHandle << (unsigned int)afterBlock[n2] << " ";
						}

						fileHandle << "\n\nKey Schedule: \n";
						for (unsigned int n2 = 0; n2 < 2048; n2++) {
							if (n2 != 0 && n2 % 16 == 0) {
								fileHandle << "\n";
							}
							fileHandle << (unsigned int)this->keySchedule[n2] << " ";
						}
						fileHandle << "\n\nS-Box: \n";

						for (unsigned int n2 = 0; n2 < 256; n2++) {
							if (n2 != 0 && n2 % 16 == 0) {
								fileHandle << "\n";
							}
							fileHandle << (unsigned int)this->Sbox[n2] << " ";
						}
						fileHandle << "\n\nP-Box: \n";

						for (unsigned int n2 = 0; n2 < 64; n2++) {
							if (n2 != 0 && n2 % 16 == 0) {
								fileHandle << "\n";
							}
							fileHandle << (unsigned int)this->Pbox[n2] << " ";
						}
						fileHandle << "\n\n\n";
					}
					fileHandle.close();
				}
			}
		}
	}
	std::cout << "\nPlaintext Avalanche 50000 block Test Complete.\nChange in 1 bit of plaintext averaged: " << this->getAverage(differences) << "/128 bits of difference in the ciphertext\nLow case: " << lowCase << "/128\nHigh case: " << highCase << "/128\nNumber of 1-bit avalanches found: " << ones << "/50,000\n";
}
