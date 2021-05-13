'''
Class to create the Dual Pairing Vector Spaces

:Authors: 	Yannis Rouselakis
:Date:		4/24/12
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *

debug = False
class DualVectorSpace():

	def __init__(self, groupObj, dim, psiSet = 0):
		global group
		group = groupObj			#we will use Charm to do the modular arithmetic for us
		#global Base				# a 2 x dim x dim matrix
		#global Psi 	# the common inner product of all d_i d*_i
		if (type(psiSet) == int):
			self.Psi = group.random(ZR)
		else:
			self.Psi = psiSet
		self.Base = [None]*2
		self.Base[0] = self.createRandomMatrix(dim)
		self.Base[1] = self.gaussElimin(self.Base[0])
		
	def getVector(self, b, i):
		return self.Base[b][i]
		
	def getPsi(self):
		return self.Psi
		
	def createRandomMatrix(self,dim): 		#this function will return a random matrix in Z_p of dimension dim x dim
		return [ [group.random(ZR) for i in range(0,dim)] for j in range(0,dim)]
		
	def gaussElimin(self, mat):
	
		work = [ ([mat[i][j] for j in range(0,len(mat))] + [(self.Psi if (i==j) else group.init(ZR, 0)) for j in range(0,len(mat))] ) for i in range(0,len(mat[0]))]
		
		# self.printOneBasis(work)
		
		(h,w) = (len(work),len(work[0]))
		
		#making it upper triangular
		for i in range(0,h):
			for i2 in range(i+1,h):
				c = work[i2][i] / work[i][i]			#I should check here for singular matrices (no: negl prob)
				for j in range(i,w):
					work[i2][j] -= work[i][j] * c
		
		# print("")			
		# self.printOneBasis(work)
		
		#backsubstitution
		for i in range(h-1, 0-1, -1):
		
			# Normalize row i
			c = work[i][i]
			for j in range(i, w):
				work[i][j] /= c
				
			for i2 in range(0,i):
				c = work[i2][i]
				for j in range(i,w):
					work[i2][j] -= c * work[i][j] 

		# print("")			
		# self.printOneBasis(work)
		
		# transposing + cropping
		result = [ [work[i][j] for i in range(0,h)] for j in range(int(w/2), w)]
		
		# print("")
		# self.printOneBasis(result)
		return result
		
	def printBases(self, full = False):
		for b in range(0,2):
			if b==0:
				print("Normal Basis:")
			else:
				print("Star Basis:")
			self.printOneBasis(self.Base[b],full)

					
	def printOneBasis(self, mat, full = False):
		if full:
			print(mat[i])
		else:
			for i in range(0,len(mat)):
				bigStr = "["
				for j in range(0,len(mat[i])):
					cut = (int(mat[i][j]) > 999)
					
					smallStr = str(int(mat[i][j]) % 1000)
					extraSp = 3 - len(smallStr)
					
					if cut:
						bigStr += ".."
						for k in range(0, extraSp):
							bigStr += "0"
					else:
						bigStr += "  "
						for k in range(0, extraSp):
							bigStr += " "
					bigStr += smallStr

					if j!=(len(mat[i])-1):
						bigStr += ", "
					else:
						bigStr += "]"
				print(bigStr)		
	
	def checkOrthogonality(self):
		dim = len(self.Base[0][0]) # getting the dimension
		
		res = [ [group.init(ZR, 0) for i in range(0,dim)] for j in range(0,dim)]
		
		# matrix multiplication (the naive way)
		for i in range(0,dim):
			for j in range(0,dim):
				curr = group.init(ZR, 0)
				for k in range(0,dim):
					curr += self.Base[0][i][k] * self.Base[1][j][k]
				res[i][j] = curr
		
		print("B times transpose B*")		
		self.printOneBasis(res, False)
		
		
def main():
	groupObj = PairingGroup('MNT224')
	DV = DualVectorSpace(groupObj,10)
		
	DV.printBases()
	
	DV.checkOrthogonality() #visual check ;)
	
if __name__ == '__main__':
	debug = True
	main()
