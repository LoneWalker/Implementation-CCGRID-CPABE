'''
Rouselakis - Waters Unbounded Hierarchical Identity-Based Encryption

| From: 
| Published in: 
| Available from: 
| Notes: 

* type:          hierarchical identity-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    complex q-type assumption

:Authors:		Yannis Rouselakis
:Date:      	02/12
'''

from toolbox.pairinggroup import *
from charm.cryptobase import *
from HIBEnc import HIBEnc
from BenchmarkFunctions import *

#import time


debug = False
class IBE_RW12(HIBEnc):
	def __init__(self, groupObj):
		HIBEnc.__init__(self)
		global group
		group = groupObj
		
	def setup(self):
		g = group.random(G1)
		g2, u, h, w = group.random(G2), group.random(G2), group.random(G2), group.random(G2)
		alpha = group.random( )
		egg = pair(g,g2)**alpha
		#time.sleep(3)
		pp = {'g':g, 'g2':g2, 'u':u, 'h':h, 'w':w, 'egg':egg}
		mk = {'alpha':alpha }
		return (pp, mk)


	# Defining a function to pick exponents in the group
	def exp(self,value):	
		return group.init(ZR, value)
		
	def extract(self, mk, IDV, pp):
		ell = len(IDV) #IDV is a vector of identities in Zp
		
		cntr = group.init(ZR) #identity element of ZR
		
		K0, K1, K2 = {}, {}, {}
		for i in range(ell-1):
			r = group.random(ZR)
			lam = group.random(ZR)
			cntr += lam #addition modulo the order of the group
			K0[i] = (pp['g2']**lam) * (pp['w']**r)
			K1[i] = ((pp['u']**(IDV[i])) * pp['h'])**r
			K2[i] = pp['g']**r
			
		r = group.random(ZR)		
		cntr = mk['alpha'] - cntr 
		K0[ell-1] = (pp['g2']**cntr) * (pp['w']**r)
		K1[ell-1] = ((pp['u']**(IDV[ell-1])) * pp['h'])**r
		K2[ell-1] = pp['g']**r
		return {'K0':K0, 'K1':K1, 'K2':K2}

	def encrypt(self, pp, IDV, message):
		s = group.random( )
		C = message * (pp['egg'] ** s)
		C0 = pp['g'] ** s
		
		n = len(IDV)
		C1, C2 = {}, {}
		for i in range(n):
			t = group.random( )
			C1[i] = pp['g']**t
			C2[i] = (((pp['u']**(IDV[i])) * pp['h'])**t) * (pp['w']**s)
		
		return {'C':C, 'C0':C0, 'C1':C1, 'C2':C2}
	
	def decrypt(self, pp, sk, ct):
		# Find the length of the secret key
		ell = len(sk['K0'])
		# Find the length of the ciphertext
		n = len(ct['C1'])
		if ell <= n:
			B = group.init(GT) #identity element of GT
		
			for i in range(ell):
				B = B * pair(ct['C0'], sk['K0'][i]) * pair(ct['C1'][i] , sk['K1'][i]) / pair(sk['K2'][i], ct['C2'][i])
		
			return ct['C'] / B
		else:
			print("The length of the ciphertext is smaller")
			return group.init(GT) #the identity element of GT
		
	def delegate(self, pk, IDV, ID):
		HIBEnc.delegate(self)
		
	
def main():
	curve = 'MNT224'

	groupObj = PairingGroup(curve)
	scheme = IBE_RW12(groupObj)
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
