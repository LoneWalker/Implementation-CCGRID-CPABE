'''
Lewko Unbounded Hierarchical Identity-Based Encryption

| From: 
| Published in: 	Eurocrypt 2012
| Available from: 
| Notes: 

* type:          hierarchical identity-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    dlin

:Authors:		Yannis Rouselakis
:Date:      	4/12
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *
from HIBEnc import HIBEnc
from BenchmarkFunctions import *
from DualVectorSpaces import *


debug = False
class IBE_L12(HIBEnc):
	def __init__(self, groupObj):
		HIBEnc.__init__(self)
		global group
		group = groupObj
		
	def setup(self):
		#Creation of the Dual Bases
		DV = DualVectorSpace(group,10)
		
		# DV.checkOrthogonality()
	
		g  = group.random(G1)
		g2 = group.random(G2)
		alpha1, alpha2, theta, sigma, gamma, ksi = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)
		
		# the inner products for the egg terms
		innPr = DV.getPsi()
					
		# six vectors for public parameters
		ppVecs = [ [ (g ** x) for x in DV.getVector(0,i) ] for i in range(0,6) ]
		
		# eight vectors for the master secret key
		mskVec1 =  [ (g2 ** x) for x in DV.getVector(1,0) ]
		mskVec2 =  [ (g2 ** x) for x in DV.getVector(1,1) ]
		mskVec3 =  [ (g2 ** (gamma * x)) for x in DV.getVector(1,0) ]
		mskVec4 =  [ (g2 ** (ksi * x)) for x in DV.getVector(1,1) ]
		mskVec5 =  [ (g2 ** (theta * x)) for x in DV.getVector(1,2) ]
		mskVec6 =  [ (g2 ** (theta * x)) for x in DV.getVector(1,3) ]
		mskVec7 =  [ (g2 ** (sigma * x)) for x in DV.getVector(1,4) ]
		mskVec8 =  [ (g2 ** (sigma * x)) for x in DV.getVector(1,5) ]
		
		mskVecs = [ mskVec1, mskVec2, mskVec3, mskVec4, mskVec5, mskVec6, mskVec7, mskVec8 ]
		
		pp = {'egg1': pair(g,g2)**(alpha1 * innPr), 'egg2': pair(g,g2)**(alpha2 * innPr), 'ppVecs': ppVecs}
		mk = {'alpha1':alpha1, 'alpha2':alpha2, 'mskVecs':mskVecs }
		return (pp, mk)

	# Defining a function to pick exponents in the group
	def exp(self,value):	
		return group.init(ZR, value)
		
	def extract(self, mk, IDV, pp):
		ell = len(IDV) #IDV is a vector of identities in Zp
		
		cntrW = self.exp(0) #identity element of ZR
		cntrY = self.exp(0) #identity element of ZR
		
		K0 = mk['mskVecs'][2:] # the last 6 vectors
		
		K1 = { }
		for i in range(0, ell-1):
			r1,r2 = group.random(ZR), group.random(ZR)
			y = group.random(ZR)
			cntrY += y #addition modulo the order of the group
			w = group.random(ZR)
			cntrW += w #addition modulo the order of the group
			
			# pairwise multiplication!!!
			K1[i] = [ ( (mk['mskVecs'][0][j] ** y) * (mk['mskVecs'][1][j] ** w) \
				* (mk['mskVecs'][4][j] ** (r1 * IDV[i])) * (mk['mskVecs'][5][j] ** (-r1)) \
				* (mk['mskVecs'][6][j] ** (r2 * IDV[i])) * (mk['mskVecs'][7][j] ** (-r2)) )\
				 for j in range(0,len(mk['mskVecs'][0])) ]
			
		r1,r2 = group.random(ZR), group.random(ZR)		
		y = mk['alpha1'] - cntrY
		w = mk['alpha2'] - cntrW
		K1[ell-1] = [ ( (mk['mskVecs'][0][j] ** y) * (mk['mskVecs'][1][j] ** w) \
			* (mk['mskVecs'][4][j] ** (r1 * IDV[ell-1])) * (mk['mskVecs'][5][j] ** (-r1)) \
			* (mk['mskVecs'][6][j] ** (r2 * IDV[ell-1])) * (mk['mskVecs'][7][j] ** (-r2)) )\
			for j in range(0,len(mk['mskVecs'][0])) ]
		
		return {'K0':K0, 'K1':K1}

	def encrypt(self, pp, IDV, message):
		s1, s2 = group.random(ZR), group.random(ZR)
		
		C0 = message * (pp['egg1'] ** s1) * (pp['egg2'] ** s2)
		
		n = len(IDV)
		C1 = {}
		for i in range(n):
			t1, t2 = group.random(ZR), group.random(ZR)
			C1[i] = [ ( (pp['ppVecs'][0][j] ** s1) * (pp['ppVecs'][1][j] ** s2) \
				* (pp['ppVecs'][2][j] ** t1) * (pp['ppVecs'][3][j] ** (t1 * IDV[i])) \
				* (pp['ppVecs'][4][j] ** t2) * (pp['ppVecs'][5][j] ** (t2 * IDV[i])) ) \
				for j in range(0,len(pp['ppVecs'][0])) ]
		
		return {'C0':C0, 'C1':C1}
	
	def decrypt(self, pp, sk, ct):
		# Find the length of the secret key
		ell = len(sk['K1'])
		# Find the length of the ciphertext
		n = len(ct['C1'])
		if ell <= n:
			B = group.init(GT) #identity element of GT
		
			for i in range(ell):
				for j in range(len(ct['C1'][0])):
					B *= pair(ct['C1'][i][j], sk['K1'][i][j])
		
			return ct['C0'] / B
		else:
			print("The length of the ciphertext is smaller")
			return group.init(GT) #the identity element of GT
		
	def delegate(self, pk, IDV, ID):
		HIBEnc.delegate(self)
		
	
def main():
	curve = 'MNT224'

	groupObj = PairingGroup(curve)
	scheme = IBE_L12(groupObj)
	#print("Setup(",curve,")")
	
	ID = InitBenchmark()
	startAll(ID)
	(pp, mk) = scheme.setup()
	EndBenchmark(ID)
	
	#print("The Public Parameters are",pp)
	#print("And the Master Key is",mk)
	#print("Done!\n")	
	box1 = getResAndClear(ID, "Setup("+curve+")", "Done!")
	
	#--------------------------------------------	
			
	IDVK = [scheme.exp(456), scheme.exp(187),scheme.exp(854)]
	#print("Keygen(", str(IDVK),")")

	ID = InitBenchmark()
	startAll(ID)
	sk = scheme.extract(mk,IDVK,pp)
	EndBenchmark(ID)

	#print("The secret key is",sk)
	#print("Done!\n")	
	box2 = getResAndClear(ID, "Keygen(" + str(IDVK) + ")", "Done!")
	
	#--------------------------------------------	
			
	m = group.random(GT)
	#print("Encrypting the message",m)
	IDVM = [scheme.exp(456), scheme.exp(187),scheme.exp(854),scheme.exp(765),scheme.exp(123)]
	#print("Encrypt(",str(IDVM),")")

	ID = InitBenchmark()
	startAll(ID)
	ct = scheme.encrypt(pp,IDVM,m)
	EndBenchmark(ID)
	
	#print("The ciphertext is",ct)
	#print("Done!\n")	
	box3 = getResAndClear(ID, "Encrypt("+str(IDVM)+")", "Done!")
	
	#--------------------------------------------	
				
	#print("Decrypt")
	
	ID = InitBenchmark()
	startAll(ID)
	res = scheme.decrypt(pp, sk, ct)
	EndBenchmark(ID)

	#print("The resulting ciphertext is",res)
	if res == m:
		fin = "Successful Decryption :)"
	else:
		fin = "Failed Decryption :("
	box4 = getResAndClear(ID, "Decrypt", fin)
	
	print(formatNice(box1,box2,box3,box4))
	
if __name__ == '__main__':
	debug = True
	main()
