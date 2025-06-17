import math
import numpy
from numpy import random

#This is an example of AES-128 I created to teach myself the process.  This code should not be used to encrypt sensitive or commercial information.

#S-box substitution dictionary.  If you do a general search for "Rijndael S-box", there is a healthy amount of information available.
            
SubDict = {0: 99, 1: 124, 2: 119, 3: 123, 4: 242, 5: 107, 6: 111, 7: 197, 8: 48, 9: 1, 10: 103, 11: 43, 12: 254, 13: 215, 14: 171, 15: 118, 16: 202, 17: 130, 18: 201, 19: 125, 20: 250, 21: 89, 22: 71, 23: 240, 24: 173, 25: 212, 26: 162, 27: 175, 28: 156, 29: 164, 30: 114, 31: 192, 32: 183, 33: 253, 34: 147, 35: 38, 36: 54, 37: 63, 38: 247, 39: 204, 40: 52, 41: 165, 42: 229, 43: 241, 44: 113, 45: 216, 46: 49, 47: 21, 48: 4, 49: 199, 50: 35, 51: 195, 52: 24, 53: 150, 54: 5, 55: 154, 56: 7, 57: 18, 58: 128, 59: 226, 60: 235, 61: 39, 62: 178, 63: 117, 64: 9, 65: 131, 66: 44, 67: 26, 68: 27, 69: 110, 70: 90, 71: 160, 72: 82, 73: 59, 74: 214, 75: 179, 76: 41, 77: 227, 78: 47, 79: 132, 80: 83, 81: 209, 82: 0, 83: 237, 84: 32, 85: 252, 86: 177, 87: 91, 88: 106, 89: 203, 90: 190, 91: 57, 92: 74, 93: 76, 94: 88, 95: 207, 96: 208, 97: 239, 98: 170, 99: 251, 100: 67, 101: 77, 102: 51, 103: 133, 104: 69, 105: 249, 106: 2, 107: 127, 108: 80, 109: 60, 110: 159, 111: 168, 112: 81, 113: 163, 114: 64, 115: 143, 116: 146, 117: 157, 118: 56, 119: 245, 120: 188, 121: 182, 122: 218, 123: 33, 124: 16, 125: 255, 126: 243, 127: 210, 128: 205, 129: 12, 130: 19, 131: 236, 132: 95, 133: 151, 134: 68, 135: 23, 136: 196, 137: 167, 138: 126, 139: 61, 140: 100, 141: 93, 142: 25, 143: 115, 144: 96, 145: 129, 146: 79, 147: 220, 148: 34, 149: 42, 150: 144, 151: 136, 152: 70, 153: 238, 154: 184, 155: 20, 156: 222, 157: 94, 158: 11, 159: 219, 160: 224, 161: 50, 162: 58, 163: 10, 164: 73, 165: 6, 166: 36, 167: 92, 168: 194, 169: 211, 170: 172, 171: 98, 172: 145, 173: 149, 174: 228, 175: 121, 176: 231, 177: 200, 178: 55, 179: 109, 180: 141, 181: 213, 182: 78, 183: 169, 184: 108, 185: 86, 186: 244, 187: 234, 188: 101, 189: 122, 190: 174, 191: 8, 192: 186, 193: 120, 194: 37, 195: 46, 196: 28, 197: 166, 198: 180, 199: 198, 200: 232, 201: 221, 202: 116, 203: 31, 204: 75, 205: 189, 206: 139, 207: 138, 208: 112, 209: 62, 210: 181, 211: 102, 212: 72, 213: 3, 214: 246, 215: 14, 216: 97, 217: 53, 218: 87, 219: 185, 220: 134, 221: 193, 222: 29, 223: 158, 224: 225, 225: 248, 226: 152, 227: 17, 228: 105, 229: 217, 230: 142, 231: 148, 232: 155, 233: 30, 234: 135, 235: 233, 236: 206, 237: 85, 238: 40, 239: 223, 240: 140, 241: 161, 242: 137, 243: 13, 244: 191, 245: 230, 246: 66, 247: 104, 248: 65, 249: 153, 250: 45, 251: 15, 252: 176, 253: 84, 254: 187, 255: 22}

def encrypt(message, basekey):

	#Defines a function to convert the basekey and entered message strings into integers character by character. 

	def CharConvert(msg):

		asciiarr = []

		for i in range(len(msg)):

			asciiarr.append(ord(msg[i]))

		return asciiarr

	RoundKeyArr = CharConvert(basekey)

	asciimsg = CharConvert(message)

	#Begin function which calculates 10 round keys for later use in encrypting the message.

	def RKeyFunct():

		#First, we copy the last four elements of the current round key.  We will perform operations on this separate sub-array and then use it to confuse the current round key in order to make the next round key.

		mixingarr = []

		for i in range(4):

			mixingarr.insert(0, RoundKeyArr[len(RoundKeyArr) - 1 - i])

		#Rotation of the first element of the sub-array to the end of the sub-array.

		def Keyshift():

			holder = mixingarr[0]

			mixingarr.pop(0)

			mixingarr.append(holder)

			return mixingarr

		Keyshift()

		#Next, we use the S-box dictionary above to substitute out the values of the sub-array.

		def KeySubst():

			for i in range(4):
	
				holder = mixingarr[i]

				mixingarr.pop(i)

				element = SubDict[holder]

				mixingarr.insert(i, element)

			return mixingarr

		KeySubst()

		#Here we will add a round constant to the first element of the sub-array.

		def RoundConst():

			c = int(len(RoundKeyArr) / 16)

			rconstarr = [1,2,4,8,16,32,64,128,27,54]

			holder = (mixingarr[0] ^ rconstarr[c-1])

			mixingarr.pop(0)

			mixingarr.insert(0, holder)

			return mixingarr

		RoundConst()

		#Now we use the sub-array to confuse the current round key in order to compute the next round key.

		asciikey = []

		#For this code I found it easiest to create one massive array with all the round keys.  This very next for loop grabs the last 16 values of the round key array or the most recently completed round key.

		for i in range(16):

			asciikey.insert(0, RoundKeyArr[len(RoundKeyArr) - 1 - i])

		#Finally, we XOR through all parts of the round key.  The sub-array is introduced into the first four entries of the round key which then also permeate through the rest of the key.

		def Xor():
	
			for j in range(4):

				x = asciikey[j]

				y = mixingarr[j]

				xoy = x ^ y

				asciikey.pop(j)

				asciikey.insert(j, xoy)

			for k in range(4):

				x = asciikey[k]

				y = asciikey[k+4]

				xoy = x ^ y

				asciikey.pop(k+4)

				asciikey.insert(k+4, xoy)

			for m in range(4):

				x = asciikey[m+4]

				y = asciikey[m+8]

				xoy = x ^ y

				asciikey.pop(m+8)

				asciikey.insert(m+8, xoy)

			for n in range(4):

				x = asciikey[n+8]

				y = asciikey[n+12]

				xoy = x ^ y

				asciikey.pop(n+12)

				asciikey.insert(n+12, xoy)

			return asciikey

		asciikey = Xor()

		for i in range(16):

			RoundKeyArr.append(asciikey[i])

		return RoundKeyArr

	#Let's loop through that whole mess 10 times to create all 10 round keys.

	for i in range(10):

		RoundKeyArr = RKeyFunct()

	RKeyXOR = RoundKeyArr #Define the array that will be used in the xor steps to encrypt the message.  This stores all of the round keys we calculated above.

	#Begin interweaving state (message) and round key matrices.  Round 0 is only an XOR of the original two matrices.  Subsequent rounds 1-9 have sub, row, column, roundkey steps. Round 10 does not include a mix column step.

	msgarr = []

	#This is round 0 which is purely an XOR of the original message and original round key arrays.  This creates a singular "state matrix" denoted as "msgarr".  We will feed the state matrix to the next function to begin round 1.

	for i in range(16):

		msgarr.append(RKeyXOR[i] ^ asciimsg[i])

	for i in range(16):

		RKeyXOR.pop(0)

	#This is the beginning of the function for running rounds 1-9.

	def RFunct(msgarr, RKeyXOR):

		#Start with a substitution step utilizing the S-box dictionary above.

		def Subst():

			msgsubst = []

			for i in range(16):

				holder = msgarr[i]

				element = SubDict[holder]

				msgsubst.append(element)

			return msgsubst

		msgsubst = Subst()

		#The state matrix is a 4x4.  This next function shifts row 1 left by 0; row 2 left by 1; row 3 left by 2; and row 4 left by 3.  To do so, we create a new array by grabbing elements of the previous array in a specific order.

		def RowShift():

			msgshifted = []

			for i in range(16):

				posarr = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]

				msgshifted.append(msgsubst[posarr[i]])

			return msgshifted

		msgshifted = RowShift()

		#This Galois Field Multiplication function is the peasant's algorithm.  It is the means by which we accomplish the modular multplication over GF(2^8) required for this step. I wrote this myself, but I learned of the process from Wikipedia - Peasant's Alogrithm.

		def GFM(a,b):

			p = 0

			while a != 0 and b != 0:

				if b % 2 == 1:

					p = p ^ a

				if a >= 128:

					a = (a << 1) ^ 0x11b

				else:

					a = a << 1

				b = b >> 1

			return p

		a = 0

		b = 0

		#The shift column step multplies the state matrix by a fixed matrix (here called "colmatrix").  It necessitates use of the peasant's algorithm defined above.  This process expands the 16 elements of the state matrix into 64.

		def ColShift():

			msgmixed = []

			holder = []

			colmatrix = [2,3,1,1,1,2,3,1,1,1,2,3,3,1,1,2]

			counter = 0

			for i in range(4):

				for j in range(4):

						holder.append(GFM(msgshifted[j],colmatrix[counter]))

						counter = counter + 1
			counter = 0

			for i in range(4):

				for j in range(4):

						holder.append(GFM(msgshifted[j+4],colmatrix[counter]))

						counter = counter + 1

			counter = 0

			for i in range(4):

				for j in range(4):

						holder.append(GFM(msgshifted[j+8],colmatrix[counter]))

						counter = counter + 1

			counter = 0

			for i in range(4):

				for j in range(4):

						holder.append(GFM(msgshifted[j+12],colmatrix[counter]))

						counter = counter + 1

			#Next we reduce those 64 elements back down to 16 by xor'ing the appropriate values into singular matrix positions.

			for i in range(0, 64, 4):

				msgmixed.append(holder[i] ^ holder[i+1] ^ holder[i+2] ^ holder[i+3])

			return msgmixed


		msgmixed = ColShift()

		#Finally, we xor the current state matrix with the current round's key.

		def xorMatrix():

			msgarr = []

			for i in range(16):

				msgarr.append(msgmixed[i] ^ RKeyXOR[i])

			return msgarr

		msgarr = xorMatrix()

		return msgarr

	#It depends on how you handle your round keys, but this xorUpdate function was necessary for me to kick out already utilized keys.  This way the code can always reference the beginning of the round key array for ease.

	def xorUpdate(RKeyXOR):

		for i in range(16):

			RKeyXOR.pop(0)

		return RKeyXOR

	#Now let's run it 9 times to complete rounds 1 through 9.

	for i in range(9):

		msgarr = RFunct(msgarr, RKeyXOR)

		RKeyXOR = xorUpdate(RKeyXOR)

	#As mentioned before, round 10 is unique in that it does not have a mix columns step.  For that reason, it stands alone here.  These are all steps we have seen above.

	def RFunct10(msgarr, RKeyXOR):

		def Subst():

			msgsubst = []

			for i in range(16):

				holder = msgarr[i]

				element = SubDict[holder]

				msgsubst.append(element)

			return msgsubst

		msgsubst = Subst()

		def RowShift():

			msgshifted = []

			for i in range(16):

				posarr = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]

				msgshifted.append(msgsubst[posarr[i]])

			return msgshifted

		msgshifted = RowShift()

		def xorMatrix():

			msgarr = []

			for i in range(16):

				msgarr.append(msgshifted[i] ^ RKeyXOR[i])

			return msgarr

		msgarr = xorMatrix()

		return msgarr

	msgarr = RFunct10(msgarr, RKeyXOR)

	return msgarr

basekey = "Thats my Kung Fu" #This is the base key which must be known by both parties to encrypt and decrypt the message.  For this AES128 program, it must be exactly 16 characters in length.

print("The base key for this session is: " + str(basekey))

UserInput = input("Enter the text to be encrypted: ") #The user enters the text to be encrypted.

#This while loop ensures that we have filled out 128 bit blocks to perform calculations on.  We must have 128 bit blocks, but the message entered by the user may not necessarily perfectly end up being some multiple of 16 characters.

while len(UserInput) % 16 != 0:

	x = chr(random.randint(255))

	UserInput = UserInput + x

iterations = int(len(UserInput) / 16)

ciphertext = []

#Finally, we have a for loop which iterates through the 128 bit blocks created by the user / while loop and sends the blocks through the defined encrypt() function on line 9.

for i in range(0, iterations*16, 16):

	message = UserInput[i:i+16]

	ciphertext.append(encrypt(message, basekey))

#This last portion prints the fully encrypted arrays.  I have another file uploaded for the decryption side where these arrays are the input.

print("The array to be passed to the decryption file is: ")

print(ciphertext)





















