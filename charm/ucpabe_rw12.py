'''
Rouselakis - Waters Unbounded Ciphertext-Policy Attribute-Based Encryption

| From: 
| Published in: 
| Available from: 
| Notes: 

* type:          attribute-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    complex q-type assumption

:Authors:		Yannis Rouselakis
:Date:      	02/12
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *
from toolbox.secretutil import SecretUtil
from toolbox.ABEnc import *
from BenchmarkFunctions import *

debug = False
class CPABE_RW12(ABEnc):
	def __init__(self, groupObj, verbose = False):
		ABEnc.__init__(self)
		global util, group
		group = groupObj
		util = SecretUtil(group, verbose)

	# Defining a function to pick explicit exponents in the group
	def exp(self,value):	
		return group.init(ZR, value)
		
	def setup(self):
		# Due to assymmetry in the groups we prefer most of the terms to be in G1
		g = group.random(G2)
		g2, u, h, w, v = group.random(G1), group.random(G1), group.random(G1), group.random(G1), group.random(G1)
		alpha = group.random( )
		egg = pair(g2,g)**alpha
		pp = {'g':g, 'g2':g2, 'u':u, 'h':h, 'w':w, 'v':v, 'egg':egg}
		mk = {'alpha':g2 ** alpha }
		return (pp, mk)
		
	def keygen(self, pp, mk, S):
		# S is a list of attributes written as STRINGS i.e. {'1', '2', '3',...}
		r = group.random( )
		K0 = mk['alpha'] * (pp['w']**r)
		K1 = pp['g']**r
		
		vR = pp['v']**r
		
		K2, K3 = {}, {}
		for i in S:
			ri = group.random( )
			K2[i] = pp['g']**ri
			K3[i] = (pp['u']**self.exp(int(i)) * pp['h'])**ri * vR #NOTICE THE CONVERSION FROM STRING TO INT
		S = [s for s in S] #Have to be an array for util.prune
		return { 'S':S, 'K0':K0, 'K1':K1, 'K2':K2, 'K3':K3 }

	def encrypt(self, pp, message, policy_str):
		s = group.random()	

		policy = util.createPolicy(policy_str)
		a_list = util.getAttributeList(policy)
		#print("\n\n THE A-LIST IS", a_list,"\n\n")
		shares = util.calculateSharesDict(s, policy) #These are correctly set to be exponents in Z_p
		
		C = message * (pp['egg']**s)
		C0 = pp['g']**s
		
		C1, C2, C3 = {}, {}, {}
		for i in a_list:
			inti = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
			#print('The exponent is ',inti)
			ti = group.random()
			C1[i] = pp['w']**shares[i] * pp['v']**ti
			C2[i] = (pp['u']**self.exp(inti) * pp['h'])**ti	
			C3[i] = pp['g']**ti
		return { 'Policy':policy_str, 'C':C, 'C0':C0, 'C1':C1, 'C2':C2, 'C3':C3 } 
	
	def decrypt(self, pp, sk, ct):
		policy = util.createPolicy(ct['Policy'])
		z = util.getCoefficients(policy)
		#print("\n\n THE COEFF-LIST IS", z,"\n\n")
		
		pruned_list = util.prune(policy, sk['S'])
		# print("\n\n THE PRUNED-LIST IS", pruned_list,"\n\n")

		if (pruned_list == False):
			return group.init(GT,1)
		
		B = group.init(GT,1)
		for i in range(len(pruned_list)):
			x = pruned_list[i].getAttribute( ) #without the underscore
			y = pruned_list[i].getAttributeAndIndex( ) #with the underscore
			#print(x,y)
			B *= ( pair( ct['C1'][y], sk['K1']) * pair( ct['C2'][y], sk['K2'][x]) / pair(sk['K3'][x], ct['C3'][y]) )**z[y]
			
		return ct['C'] * B / pair(sk['K0'] , ct['C0'])	
		
	def randomMessage(self):
		return group.random(GT)			
			
		
def main():
	curve = 'MNT224'

	groupObj = PairingGroup(curve)
	scheme = CPABE_RW12(groupObj)
	# print("Setup(",curve,")")	
	
	ID = InitBenchmark()
	startAll(ID)
	(pp, mk) = scheme.setup()
	EndBenchmark(ID)

	#print("The Public Parameters are",pp)
	#print("And the Master Key is",mk)
	#print("Done!\n")	
	box1 = getResAndClear(ID, "Setup("+curve+")", "Done!")
	
	#--------------------------------------------	
		
	S = {'123', '842',  '231', '384'}
	#print("Keygen(", str(S),")")

	ID = InitBenchmark()
	startAll(ID)
	sk = scheme.keygen(pp,mk,S)
	EndBenchmark(ID)
	
	#print("The secret key is",sk)
	#print("Done!\n")	
	box2 = getResAndClear(ID, "Keygen(" + str(S) + ")", "Done!")
	
	#--------------------------------------------	
			
	m = group.random(GT)
	policy = '(123 or 444) and (231 or 999)'
	#print("Encrypt(",policy,")")

	ID = InitBenchmark()
	startAll(ID)
	ct = scheme.encrypt(pp,m,policy)
	EndBenchmark(ID)

	#print("The ciphertext is",ct)
	#print("Done!\n")	
	box3 = getResAndClear(ID, "Encrypt("+policy+")", "Done!")
	
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
