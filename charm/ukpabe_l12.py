'''
Lewko Unbounded Key-Policy Attribute-Based Encryption

| From: 
| Published in: 	Not Yet
| Available from: 
| Notes: 

* type:          attribute-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    dlin

:Authors:		Yannis Rouselakis
:Date:      	4/12
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *
from toolbox.secretutil import SecretUtil
from toolbox.ABEnc import *
from BenchmarkFunctions import *
from DualVectorSpaces import *

debug = False
class KPABE_L12(ABEnc):
	def __init__(self, groupObj, verbose = False):
		ABEnc.__init__(self)
		global util, group
		group = groupObj
		util = SecretUtil(group, verbose)

	# Defining a function to pick explicit exponents in the group
	def exp(self,value):	
		return group.init(ZR, value)
		
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
		
		egg = pair(g,g2)
		
		pp = {'egg1': egg**(alpha1 * innPr), 'egg2': egg**(alpha2 * innPr), 'ppVecs': ppVecs}
		mk = {'alpha1':alpha1, 'alpha2':alpha2, 'mskVecs':mskVecs }
		return (pp, mk)
		
	def keygen(self, pp, mk, policy_str):
		# the secret alpha will be shared according to the policy	
		policy = util.createPolicy(policy_str)
		a_list = util.getAttributeList(policy)
		# print("\n\n THE A-LIST IS", a_list,"\n\n")
		sharesY = util.calculateSharesDict(mk['alpha1'], policy) #alpha1 is shared
		sharesW = util.calculateSharesDict(mk['alpha2'], policy) #alpha1 is shared
				
		K1 = {}
		for i in a_list:
			rho = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
			r1,r2 = group.random(ZR), group.random(ZR)
			
			# pairwise multiplication!!!
			K1[i] = [ ( (mk['mskVecs'][0][j] ** sharesY[i]) * (mk['mskVecs'][1][j] ** sharesW[i]) \
				* (mk['mskVecs'][4][j] ** (r1 * rho)) * (mk['mskVecs'][5][j] ** (-r1)) \
				* (mk['mskVecs'][6][j] ** (r2 * rho)) * (mk['mskVecs'][7][j] ** (-r2)) )\
				 for j in range(0,len(mk['mskVecs'][0])) ]

		return { 'Policy':policy_str, 'K1':K1}

	def encrypt(self, pp, message, S):
		# S is a list of attributes written as STRINGS i.e. {'1', '2', '3',...}
		s1, s2 = group.random(ZR), group.random(ZR)
		
		C0 = message * (pp['egg1'] ** s1) * (pp['egg2'] ** s2)
		
		#for efficiency
		Common = [ ( (pp['ppVecs'][0][j] ** s1) * (pp['ppVecs'][1][j] ** s2) ) for j in range(0,len(pp['ppVecs'][0])) ]
		
		C1 = {}
		for i in S:
			t1, t2 = group.random(ZR), group.random(ZR)
			C1[i] = [ ( Common[j] \
				* (pp['ppVecs'][2][j] ** t1) * (pp['ppVecs'][3][j] ** (t1 * self.exp(int(i)) )) \
				* (pp['ppVecs'][4][j] ** t2) * (pp['ppVecs'][5][j] ** (t2 * self.exp(int(i)) )) ) \
				for j in range(0,len(Common)) ]
				
		S = [i for i in S] #Have to be an array for util.prune
		return { 'S':S, 'C0':C0, 'C1':C1 } 
	
	def decrypt(self, pp, sk, ct):
	
		policy = util.createPolicy(sk['Policy'])
		z = util.getCoefficients(policy)
		# print("\n\n THE COEFF-LIST IS", z,"\n\n")		
		
		pruned_list = util.prune(policy, ct['S'])
		# print("\n\n THE PRUNED-LIST IS", pruned_list,"\n\n")

		if (pruned_list == False):
			return group.init(GT,1)
		
		B = group.init(GT) #identity element of GT
		
		for i in range(len(pruned_list)):
			x = pruned_list[i].getAttribute( ) #without the underscore
			y = pruned_list[i].getAttributeAndIndex( ) #with the underscore
			for j in range(len(ct['C1'][x])):
				B *= (pair(ct['C1'][x][j], sk['K1'][y][j])) ** z[y]
		
		return ct['C0'] / B
		
	def randomMessage(self):
		return group.random(GT)				
	
def main():
	curve = 'MNT224'
	
	groupObj = PairingGroup(curve)
	scheme = KPABE_L12(groupObj)
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
		
	policy = '(123 or 444) and (231 or 999)'	
	#print("Keygen(", policy,")")

	ID = InitBenchmark()
	startAll(ID)
	sk = scheme.keygen(pp,mk,policy)
	EndBenchmark(ID)
	
	#print("The secret key is",sk)
	#print("Done!\n")	
	box2 = getResAndClear(ID, "Keygen(" + policy + ")", "Done!")
	
	#--------------------------------------------	
			
	m = group.random(GT)
	#print("Encrypting the message",m)
	S = {'123', '842',  '231', '384'}
	#print("Encrypt(", str(S),")")
	
	ID = InitBenchmark()
	startAll(ID)
	ct = scheme.encrypt(pp,m,S)
	EndBenchmark(ID)

	#print("The ciphertext is",ct)
	#print("Done!\n")	
	box3 = getResAndClear(ID, "Encrypt("+str(S)+")", "Done!")
	
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
