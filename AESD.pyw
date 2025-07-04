import math
import numpy
import random

#This is an example of AES-128 I created to teach myself the process.  This code should not be used to encrypt sensitive or commercial information.

#S-box substitution.  The guide I followed used hex, but it looked easier to simply keep it in ord().
            
SubDict = {0: 99, 1: 124, 2: 119, 3: 123, 4: 242, 5: 107, 6: 111, 7: 197, 8: 48, 9: 1, 10: 103, 11: 43, 12: 254, 13: 215, 14: 171, 15: 118, 16: 202, 17: 130, 18: 201, 19: 125, 20: 250, 21: 89, 22: 71, 23: 240, 24: 173, 25: 212, 26: 162, 27: 175, 28: 156, 29: 164, 30: 114, 31: 192, 32: 183, 33: 253, 34: 147, 35: 38, 36: 54, 37: 63, 38: 247, 39: 204, 40: 52, 41: 165, 42: 229, 43: 241, 44: 113, 45: 216, 46: 49, 47: 21, 48: 4, 49: 199, 50: 35, 51: 195, 52: 24, 53: 150, 54: 5, 55: 154, 56: 7, 57: 18, 58: 128, 59: 226, 60: 235, 61: 39, 62: 178, 63: 117, 64: 9, 65: 131, 66: 44, 67: 26, 68: 27, 69: 110, 70: 90, 71: 160, 72: 82, 73: 59, 74: 214, 75: 179, 76: 41, 77: 227, 78: 47, 79: 132, 80: 83, 81: 209, 82: 0, 83: 237, 84: 32, 85: 252, 86: 177, 87: 91, 88: 106, 89: 203, 90: 190, 91: 57, 92: 74, 93: 76, 94: 88, 95: 207, 96: 208, 97: 239, 98: 170, 99: 251, 100: 67, 101: 77, 102: 51, 103: 133, 104: 69, 105: 249, 106: 2, 107: 127, 108: 80, 109: 60, 110: 159, 111: 168, 112: 81, 113: 163, 114: 64, 115: 143, 116: 146, 117: 157, 118: 56, 119: 245, 120: 188, 121: 182, 122: 218, 123: 33, 124: 16, 125: 255, 126: 243, 127: 210, 128: 205, 129: 12, 130: 19, 131: 236, 132: 95, 133: 151, 134: 68, 135: 23, 136: 196, 137: 167, 138: 126, 139: 61, 140: 100, 141: 93, 142: 25, 143: 115, 144: 96, 145: 129, 146: 79, 147: 220, 148: 34, 149: 42, 150: 144, 151: 136, 152: 70, 153: 238, 154: 184, 155: 20, 156: 222, 157: 94, 158: 11, 159: 219, 160: 224, 161: 50, 162: 58, 163: 10, 164: 73, 165: 6, 166: 36, 167: 92, 168: 194, 169: 211, 170: 172, 171: 98, 172: 145, 173: 149, 174: 228, 175: 121, 176: 231, 177: 200, 178: 55, 179: 109, 180: 141, 181: 213, 182: 78, 183: 169, 184: 108, 185: 86, 186: 244, 187: 234, 188: 101, 189: 122, 190: 174, 191: 8, 192: 186, 193: 120, 194: 37, 195: 46, 196: 28, 197: 166, 198: 180, 199: 198, 200: 232, 201: 221, 202: 116, 203: 31, 204: 75, 205: 189, 206: 139, 207: 138, 208: 112, 209: 62, 210: 181, 211: 102, 212: 72, 213: 3, 214: 246, 215: 14, 216: 97, 217: 53, 218: 87, 219: 185, 220: 134, 221: 193, 222: 29, 223: 158, 224: 225, 225: 248, 226: 152, 227: 17, 228: 105, 229: 217, 230: 142, 231: 148, 232: 155, 233: 30, 234: 135, 235: 233, 236: 206, 237: 85, 238: 40, 239: 223, 240: 140, 241: 161, 242: 137, 243: 13, 244: 191, 245: 230, 246: 66, 247: 104, 248: 65, 249: 153, 250: 45, 251: 15, 252: 176, 253: 84, 254: 187, 255: 22}

#The next ~10 lines take a message, iterate through it to create an array in ascii integers.

def decrypt(msgarr, baskey):

	def CharConvert(msg):

		asciiarr = []

		for i in range(len(msg)):

			asciiarr.append(ord(msg[i]))

		return asciiarr

	RoundKeyArr = CharConvert(basekey)

	def RKeyFunct():

		mixingarr = []

		for i in range(4):

			mixingarr.insert(0, RoundKeyArr[len(RoundKeyArr) - 1 - i])

		#Rotation of the 12th element to the end of the key. 

		def Keyshift():

			holder = mixingarr[0]

			mixingarr.pop(0)

			mixingarr.append(holder)

			return mixingarr

		Keyshift()

		def KeySubst():

			for i in range(4):
	
				holder = mixingarr[i]

				mixingarr.pop(i)

				element = SubDict[holder]

				mixingarr.insert(i, element)

			return mixingarr

		KeySubst()

		def RoundConst():

			c = int(len(RoundKeyArr) / 16)

			rconstarr = [1,2,4,8,16,32,64,128,27,54]

			holder = (mixingarr[0] ^ rconstarr[c-1])

			mixingarr.pop(0)

			mixingarr.insert(0, holder)

			return mixingarr

		RoundConst()

		asciikey = []

		for i in range(16):

			asciikey.insert(0, RoundKeyArr[len(RoundKeyArr) - 1 - i])

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

	for i in range(10):

		RoundKeyArr = RKeyFunct()

	#Begin the decryption process.  This starts with a reversal of round 10 which only has the XOR, row shift, and substitution steps.  Then it goes on to reverse all steps from the encryption side.

	invDict = {v: k for k, v in SubDict.items()} #Invert the S-box dictionary for the substitution step.

	RKeyXORD = RoundKeyArr #Define the array that will be used in the xor steps to decrypt the message.

	def DecryptR10(msgarr, RKeyXORD):

		RKeyXORDeff = RKeyXORD[len(RKeyXORD)-16:len(RKeyXORD)]

		def unXOR():

			unxorarr = []

			for i in range(16):

				unxorarr.append(msgarr[i] ^ RKeyXORDeff[i])

			return unxorarr

		unxorarr = unXOR()

		def unshift():

			unshiftarr = []

			unpossarr = [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]

			for i in range(16):

				unshiftarr.append(unxorarr[unpossarr[i]])

			return unshiftarr

		unshiftarr = unshift()

		def unSub():

			unsubarr = []

			for i in range(16):

				element = invDict[unshiftarr[i]]

				unsubarr.append(element)

			return unsubarr

		msgarr = unSub()

		return msgarr

	msgarr = DecryptR10(msgarr, RKeyXORD)

	def xorUpdate():

		for i in range(16):

			RKeyXORD.pop(len(RKeyXORD)-1)
	
		return RKeyXORD

	RKeyXORD = xorUpdate()

	def DecryptRFunct(msgarr, RKeyXORD):

		RKeyXORDeff = RKeyXORD[len(RKeyXORD)-16:len(RKeyXORD)]

		def unXOR():

			unxorarr = []

			for i in range(16):

				unxorarr.append(msgarr[i] ^ RKeyXORDeff[i])

			return unxorarr

		unxorarr = unXOR()

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

		def ColShift():

			unmixed = []

			holder = []

			colmatrix = [14,11,13,9,9,14,11,13,13,9,14,11,11,13,9,14]

			counter = 0

			for i in range(4):

				for j in range(4):

					holder.append(GFM(unxorarr[j],colmatrix[counter]))

					counter = counter + 1

			counter = 0

			for i in range(4):

				for j in range(4):

					holder.append(GFM(unxorarr[j+4],colmatrix[counter]))

					counter = counter + 1

			counter = 0

			for i in range(4):

				for j in range(4):

					holder.append(GFM(unxorarr[j+8],colmatrix[counter]))

					counter = counter + 1

			counter = 0

			for i in range(4):

				for j in range(4):

					holder.append(GFM(unxorarr[j+12],colmatrix[counter]))

					counter = counter + 1

			for i in range(0, 64, 4):

				unmixed.append(holder[i] ^ holder[i+1] ^ holder[i+2] ^ holder[i+3])

			return unmixed


		unmixed = ColShift()

		def unshift():

			unshiftarr = []

			unpossarr = [0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3]

			for i in range(16):

				unshiftarr.append(unmixed[unpossarr[i]])

			return unshiftarr

		unshiftarr = unshift()

		def unSub():

			unsubarr = []

			for i in range(16):

				element = invDict[unshiftarr[i]]

				unsubarr.append(element)

			return unsubarr

		msgarr = unSub()

		return msgarr

	for i in range(9):

		msgarr = DecryptRFunct(msgarr, RKeyXORD)

		RKeyXORD = xorUpdate()

	ciphertext0 = []

	for i in range(16):

		ciphertext0.append(msgarr[i] ^ RKeyXORD[i])

	decmsg = ""

	for i in range(16):

		decmsg = decmsg + chr(ciphertext0[i])

	return decmsg

basekey = "Thats my Kung Fu"

#Copy the array printed from the encryption-side program and paste it here as the value of "UserInput" to decrypt the message. 

UserInput = [[135, 96, 233, 23, 204, 21, 47, 116, 125, 21, 169, 177, 9, 209, 122, 131], [153, 49, 12, 20, 215, 206, 34, 192, 18, 139, 21, 49, 22, 221, 2, 130], [5, 255, 0, 245, 16, 55, 80, 115, 173, 99, 29, 135, 69, 180, 57, 177]]

decryptedmsg = ""

for i in range(len(UserInput)):

	inputholder = UserInput[i]

	decholder = decrypt(inputholder, basekey)

	decryptedmsg = decryptedmsg + decholder

print("The decrypted message is: " + decryptedmsg)

























