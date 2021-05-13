'''
Base class for hierarchical identity-based encryption
 
 Notes: 	This class implements an interface for a standard hierarchical identity-based encryption scheme. 
 			It is a generalization of a standard identity-based encryption interface. It contains the
 			IBE algorithms (setup, extract, encrypt, and decrypt) and an additional algorithm called (delegate).
'''

from toolbox.schemebase import *
from toolbox.IBEnc import IBEnc

class HIBEnc(IBEnc):
	def __init__(self):
		IBEnc.__init__(self)
		SchemeBase.setProperty(self, scheme='HIBEnc')

	def setup(self):
		IBEnc.setup(self)
		
	def extract(self, mk, IDV):	#notice that it takes as input a vector of identities
		IBEnc.extract(self)

	def encrypt(self, pk, IDV, message):
		IBEnc.encrypt(self)

	def decrypt(self, pk, sk, ct):
		IBEnc.decrypt(self)
		
	def delegate(self, pk, IDV, ID):
		raise NotImplementedError	
