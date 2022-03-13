#!/usr/bin/env python
#!/usr/bin/env python3

import binascii
import random as rd
import sys


def cipher2(input1, key1, f):

	assert len(input1) == 8
	assert len(key1) == 4

	L, R = split(input1)
	assert len(L) and len(R) == 4

	fi_result = f(key1, R)
	R_new = xor(L, fi_result)
	L = R

	# do the 'SWITCH'
	Left_asdf = R_new
	Right_asdf = L

	new_result = Left_asdf + Right_asdf

	return new_result


# function for converting 'binary in string form' >> decimal integer
def bin_to_dec(input1: str = '111') -> [int]:

	# check if the 'input' in a 'string with only '0' or '1'
	if (type(input1) == str):
		dec_int = int(input1, 2)
		# print(dec_int)
		return dec_int
	else:
		print(f'error, input not a str')


# function for converting 'decimal integer' to 'string in binary'
def dec_to_bin(input1:int = 5) -> [str] :
  if ( type(input1) == int):
    return bin(input1).replace("0b", "")
  else:
    print(f'error, input not an integer')


def fistel(key1:str, input1:str):
	# convert input1 from str to int
	# input1, 1100
	input1_int = bin_to_dec(input1)

	# convert key1 from str to int
	key1_int = bin_to_dec(key1)

	cal_result_int = ( 2* pow(input1_int, key1_int)) % pow(2,4)
	cal_result_str = dec_to_bin(cal_result_int)

	# make the '4 bits'
	while len(cal_result_str) != 4:
		cal_result_str = "0"+cal_result_str

	assert len(cal_result_str) == 4

	return cal_result_str


def split(input1):
	assert len(input1) % 2 == 0

	debug1 = int(len(input1)/2)
	stuff1 = input1[:int(len(input1)/2)], input1[int(len(input1)/2):]

	return stuff1


def xor(a, b):
	output=""

	for i in range(len(a)):
		inter=int(a[i])+int(b[i])

		if inter == 2:
			inter = 0

		output = output+str(inter)

	return output


def keyGen(l=4, n=1):
	'''
	l: length of key
	n: number of keys needed
	'''
	output1=[]

	for i in range(n):
		k=""
		for i in range(l):
			k = k + str(rd.randint(0,1))
		output1.append(k)

	assert len(output1[0]) == 4
	return output1[0]


def binary_to_hex(binary):
	prefix = "0x"
	hexList = [hex(int(binary[i:i+8], 2))[2:] for i in range(0, len(binary),8)]

	for hexa in hexList:
		if len(hexa) == 1:
			hexa = "0"+hexa
		prefix = prefix + hexa

	return prefix


###
# program starts here
if __name__ == "__main__":

	# getting plain text and converting it to binary
	try:
		plainText = sys.argv[1]
	except:
		plainText = "Hello"


	'''
		encryption 'H' e l l o
		change this to encrypt SINGLE LETTER at a time
		example, 'hello' >> 'h' >> 100 1000 >> 0 + 100 1000 >> encryption
	'''
	encrypted = []
	key1 = keyGen(4, 1)

	for letter in plainText:
		letter_in_binary= bin(ord(letter))[2:]

		while len(letter_in_binary) != 8: # add '0' in front to make it '8 bits'
			letter_in_binary = "0" + letter_in_binary

		assert len(letter_in_binary) == 8

		result1 = cipher2(letter_in_binary, key1, fistel) # change the 3rd 'argument' here
		encrypted.append(result1)

	what2 = "".join(encrypted)

	# converting result to ASCII string
	resultToChar = [binary_to_hex(what2[i:i + 8]) for i in range(0, len(what2), 8)]
	cipherText = ""

	for letter in resultToChar:
		cipherText = cipherText + letter[2:]
	cipherText = "0x"+cipherText


	'''
		decrytion ['00111000', '11000101', '01011100', '01011100', '01101111']
	'''
	decrypted = []

	for item in encrypted:
		assert len(item) == 8
		result2 = cipher2(item, key1, fistel)
		decrypted.append(result2)

	what1 = "".join(decrypted)

	# converting result to ASCII string
	resultToChar2 = [chr(int(what1[i:i + 8], 2)) for i in range(0, len(what1), 8)]
	decryptedText = ""

	for letter in resultToChar2:
		decryptedText = decryptedText + letter


	# printing results
	print(f"Input text: {plainText}")
	print(f"Cipher text in Hexadeci: {cipherText}")
	print(f"Result to text: {decryptedText}")








