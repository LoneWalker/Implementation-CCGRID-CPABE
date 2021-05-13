'''
Rouselakis - Waters Unbounded Key-Policy Attribute-Based Encryption

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

from charm.toolbox.pairinggroup import *
from charm.core.crypto.cryptobase import *
#from cryptobase import *
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import *
from charm.BenchmarkFunctions import *

debug = False
class KPABE_RW12(ABEnc):
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
		g2, u, h, w = group.random(G1), group.random(G1), group.random(G1), group.random(G1)
		alpha = group.random( )
		egg = pair(g2,g)**alpha
		pp = {'g':g, 'g2':g2, 'u':u, 'h':h, 'w':w, 'egg':egg}
		mk = {'alpha':alpha }
		return (pp, mk)
		
	def keygen(self, pp, mk, policy_str):
		# the secret alpha will be shared according to the policy	
		policy = util.createPolicy(policy_str)
		a_list = util.getAttributeList(policy)
		# print("\n\n THE A-LIST IS", a_list,"\n\n")
		shares = util.calculateSharesDict(mk['alpha'], policy) #These are correctly set to be exponents in Z_p; Here alpha is shared
				
		K0, K1, K2 = {}, {}, {}
		for i in a_list:
			inti = int(util.strip_index(i)) #NOTICE THE CONVERSION FROM STRING TO INT
			ri = group.random(ZR)
			K0[i] = pp['g2']**shares[i] * pp['w']**ri
			K1[i] = (pp['u']**self.exp(inti) * pp['h'])**ri 
			K2[i] = pp['g']**ri

		return { 'Policy':policy_str, 'K0':K0, 'K1':K1, 'K2':K2 }

	def encrypt(self, pp, message, S):
		# S is a list of attributes written as STRINGS i.e. {'1', '2', '3',...}
		s = group.random()	

		C = message * (pp['egg']**s)
		C0 = pp['g']**s
		wS = pp['w']**s
		
		C1, C2 = {}, {}
		for i in S:
			ti = group.random()
			C1[i] = pp['g']**ti
			C2[i] = (pp['u']**self.exp(int(i)) * pp['h'])**ti * wS	#NOTICE THE CONVERSION FROM STRING TO INT
		S = [i for i in S] #Have to be an array for util.prune
		return { 'S':S, 'C':C, 'C0':C0, 'C1':C1, 'C2':C2 } 
	
	def decrypt(self, pp, sk, ct):
		policy = util.createPolicy(sk['Policy'])
		z = util.getCoefficients(policy)
		# print("\n\n THE COEFF-LIST IS", z,"\n\n")		
		
		pruned_list = util.prune(policy, ct['S'])
		# print("\n\n THE PRUNED-LIST IS", pruned_list,"\n\n")

		if (pruned_list == False):
			return group.init(GT,1)
				
		
		B = group.init(GT,1) # the identity element of GT
		for i in range(0,len(pruned_list)):
			x = pruned_list[i].getAttribute( ) #without the underscore
			y = pruned_list[i].getAttributeAndIndex( ) #with the underscore
			B *= ( pair(sk['K0'][y], ct['C0']) * pair(sk['K1'][y], ct['C1'][x]) / pair(ct['C2'][x], sk['K2'][y] ) )**z[y]
			
		return ct['C'] / B 
		
	def randomMessage(self):
		return group.random(GT)		
		
	
def main():
	curve = 'MNT224'

	groupObj = PairingGroup(curve)
	scheme = KPABE_RW12(groupObj)
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
