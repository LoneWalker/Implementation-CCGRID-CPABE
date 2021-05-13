'''
Okamoto Takashima Unbounded Key-Policy Attribute-Based Encryption

| From: Fully Secure Unbounded Inner-Product and Attribute-Based Encryption
| Published in: Asiacrypt 2012
| Available from: 
| Notes: 

* type:          attribute-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    dlin

:Authors:		Yannis Rouselakis
:Date:      	2/13
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *
from toolbox.secretutil import SecretUtil
from toolbox.ABEnc import *
from BenchmarkFunctions import *
from DualVectorSpaces import *

debug = False
class KPABE_OT12(ABEnc):
	def __init__(self, groupObj, verbose = False):
		ABEnc.__init__(self)
		global util, group
		group = groupObj
		util = SecretUtil(group, verbose)

	# Defining a function to pick explicit exponents in the group
	def exp(self,value):	
		return group.init(ZR, value)
		
	def setup(self):
		# dimension of the two bases
		N0 = 5
		N1 = 14
		
		psi = group.random(ZR)
		#Creation of the  two Dual Bases with the same psi
		DV0 = DualVectorSpace(group,N0,psi)
		DV1 = DualVectorSpace(group,N1,psi)
		
		#DV0.printBases()
		#DV0.checkOrthogonality()
		#DV1.printBases()
		#DV1.checkOrthogonality()
	
		g  = group.random(G1)
		g2 = group.random(G2)
		
		B0 = [ [ (g ** x) for x in DV0.getVector(0,i) ] for i in [0, 2, 4] ]
		B  = [ [ (g ** x) for x in DV1.getVector(0,i) ] for i in [0, 1, 2, 3, 12, 13] ]
		B0st = [ [ (g2 ** x) for x in DV0.getVector(1,i) ] for i in [0, 2, 3] ]
		Bst  = [ [ (g2 ** x) for x in DV1.getVector(1,i) ] for i in [0, 1, 2, 3, 10, 11] ]
		
		gPsi = g ** psi
		gT = pair(g,g2) ** psi
		
		pp = {'N0':N0, 'N1':N1, 'g':g, 'g2':g2, 'gPsi':gPsi, 'gT':gT, 'B0':B0, 'B':B}
		mk = {'B0st':B0st, 'Bst':Bst}
		return (pp, mk)
		
	def keygen(self, pp, mk, policy_str):

		s0, eta0 = group.random(ZR), group.random(ZR)
		K0 = [ ( mk['B0st'][0][j]**(-s0) * mk['B0st'][1][j] * mk['B0st'][2][j]**eta0 ) for j in range(pp['N0']) ]
		
		policy = util.createPolicy(policy_str)
		a_list = util.getAttributeList(policy)
		# print("\n\n THE A-LIST IS", a_list,"\n\n")
		shares = util.calculateSharesDict(s0, policy) #s0 is shared
		
		K1 = {}
		for i in a_list:
			t = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
			mu, th, eta1, eta2 = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)
			
			# v_i=1 ALWAYS
			K1[i] = [ ( mk['Bst'][0][j]**(mu * t) * mk['Bst'][1][j]**(-mu) * mk['Bst'][2][j]**(shares[i]+th) * mk['Bst'][3][j]**(-th) \
				* mk['Bst'][4][j]**(eta1) * mk['Bst'][5][j]**(eta2)) for j in range(pp['N1']) ]
		
		return { 'Policy':policy_str, 'K0':K0, 'K1':K1}

	def encrypt(self, pp, message, S):
		# S is a list of attributes written as STRINGS i.e. {'1', '2', '3',...}
		
		omg, zeta, phi0 = group.random(ZR), group.random(ZR), group.random(ZR)
		
		C0 = [ ( pp['B0'][0][j]**(omg) * pp['B0'][1][j]**(zeta) * pp['B0'][2][j]**(phi0) ) for j in range(pp['N0']) ]
		
		C1 = message * (pp['gT'] ** zeta) # this is the c_{d+1}
		
		
		C2 = {}
		for i in S:
			sigma, phi1, phi2 = group.random(ZR), group.random(ZR), group.random(ZR)
			
			# x_t = 1 ALWAYS
			C2[i] = [ ( pp['B'][0][j]**(sigma) * pp['B'][1][j]**(sigma*int(i)) * pp['B'][2][j]**(omg) * pp['B'][3][j]**(omg) \
				* pp['B'][4][j]**(phi1) * pp['B'][5][j]**(phi2)) for j in range(pp['N1']) ]
				
		S = [i for i in S] #Have to be an array for util.prune
		return { 'S':S, 'C0':C0, 'C1':C1 , 'C2':C2}
		
	#multidimensional pairing
	def mpair(self,vec1, vec2):
		temp = group.init(GT)
		for i in range(len(vec1)):
			temp *= pair(vec1[i],vec2[i])
		return temp
	
	def decrypt(self, pp, sk, ct):
	
		policy = util.createPolicy(sk['Policy'])
		z = util.getCoefficients(policy)
		# print("\n\n THE COEFF-LIST IS", z,"\n\n")		
		
		pruned_list = util.prune(policy, ct['S'])
		# print("\n\n THE PRUNED-LIST IS", pruned_list,"\n\n")

		if (pruned_list == False):
			return group.init(GT,1)
		
		B = self.mpair(ct['C0'],sk['K0'])
		
		for i in range(len(pruned_list)):
			x = pruned_list[i].getAttribute( ) #without the underscore
			y = pruned_list[i].getAttributeAndIndex( ) #with the underscore
			B *= (self.mpair(ct['C2'][x], sk['K1'][y])) ** z[y]
		
		return ct['C1'] / B
		
	def randomMessage(self):
		return group.random(GT)				
	
def main():
	curve = 'SS512'
	
	groupObj = PairingGroup(curve)
	scheme = KPABE_OT12(groupObj)
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
	#print(len(sk['K0']))
	#print(len(sk['K1']['123']))
	#print("Done!\n")	
	box2 = getResAndClear(ID, "Keygen(" + policy + ")", "Done!")
	
	#--------------------------------------------	
			
	m = group.random(GT)
	#print("Encrypting the message",m)
	S = {'123', '842', '231', '384'}
	#print("Encrypt(", str(S),")")
	
	ID = InitBenchmark()
	startAll(ID)
	ct = scheme.encrypt(pp,m,S)
	EndBenchmark(ID)

	#print("The ciphertext is",ct)
	#print(len(ct['C0']))
	#print(len(ct['C2']['123']))
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
