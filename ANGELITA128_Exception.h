/*
    This is part of the ANGELITA128 encryption system, the source code for the ANGELITA128 exception error class
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

	ANGELITA128 Exception class

	!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!
	Also to note, this system hasn't gone through any kind of proper peer review process yet, so it should not be used
	for any real secure purposes. You have been warned!
	!!!!!!!!!!!!!! VERY IMPORTANT !!!!!!!!!!!

*/

#ifndef ANGELITA128_EXCEPTION_H
#define ANGELITA128_EXCEPTION_H

#include <exception>
#include <string>

class ANGELITA128_Exception : public std::exception {
private:
	std::string errorMessage;
public:
	ANGELITA128_Exception(std::string errMessage) : errorMessage(errMessage) {}
	virtual const char* what() { return errorMessage.c_str(); }
};

#endif