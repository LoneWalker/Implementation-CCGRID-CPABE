'''
Getting Averaged results
'''
from toolbox.pairinggroup import *
from ukpabe_rw12 import *
from ukpabe_l12 import *
from ucpabe_rw12 import *
from ukpabe_ot12 import *
from ucpabe_ot12 import *

#formatting function for time
def ft(timeReal):
	string = str(timeReal)
	ind = string.find(".")
	spcs = 5 - ind
	tmp = ""
	for i in range(spcs):
		tmp += " "
	string = tmp + string
	
	spcs = 13 - len(string)
	tmp = ""
	for i in range(spcs):
		tmp += " "
		
	return string + tmp

#number of iterations (BE CAREFUL WITH THIS!)
N = 1

curves = [ 'SS512', 'SS1024', 'MNT159', 'MNT201', 'MNT224' ]
types = ['rwkpabe', 'lwkpabe', 'otkpabe', 'rwcpabe', 'otcpabe']

results = { curve:{ tp:None for tp in types } for curve in curves }

for curve in curves:
	groupObj = PairingGroup(curve)

	#RW KPABE
	print("RW KPABE ",curve)
	scheme = KPABE_RW12(groupObj)
	stpTime = 0.0
	kgnTime = 0.0
	encTime = 0.0
	decTime = 0.0

	for i in range(0,N):
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		(pp, mk) = scheme.setup()
		EndBenchmark(ID)
		stpTime += GetGeneralBenchmarks(ID)[RealTime]
	
		policy = '(123 or 444) and (231 or 999)'	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		sk = scheme.keygen(pp,mk,policy)
		EndBenchmark(ID)
		kgnTime += GetGeneralBenchmarks(ID)[RealTime]
	
		m = scheme.randomMessage()
		S = {'123', '842',  '231', '384'}
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		ct = scheme.encrypt(pp,m,S)
		EndBenchmark(ID)
		encTime += GetGeneralBenchmarks(ID)[RealTime]
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		res = scheme.decrypt(pp, sk, ct)
		EndBenchmark(ID)
		decTime += GetGeneralBenchmarks(ID)[RealTime]

		if res != m:
			print('Unsuccessful Decryption')
			break

	stpTime = round((stpTime * 1000) / N, 1)
	kgnTime = round((kgnTime * 1000) / N, 1)
	encTime = round((encTime * 1000) / N, 1)
	decTime = round((decTime * 1000) / N, 1)
	
	results[curve]['rwkpabe'] = {'stp':stpTime, 'kgn':kgnTime, 'enc':encTime, 'dec':decTime}
	
	#------------------------------------------------------------------------
	#L  KPABE
	print("L  KPABE ",curve)
	scheme = KPABE_L12(groupObj)
	stpTime = 0.0
	kgnTime = 0.0
	encTime = 0.0
	decTime = 0.0

	for i in range(0,N):
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		(pp, mk) = scheme.setup()
		EndBenchmark(ID)
		stpTime += GetGeneralBenchmarks(ID)[RealTime]
	
		policy = '(123 or 444) and (231 or 999)'	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		sk = scheme.keygen(pp,mk,policy)
		EndBenchmark(ID)
		kgnTime += GetGeneralBenchmarks(ID)[RealTime]
	
		m = scheme.randomMessage()
		S = {'123', '842',  '231', '384'}
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		ct = scheme.encrypt(pp,m,S)
		EndBenchmark(ID)
		encTime += GetGeneralBenchmarks(ID)[RealTime]
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		res = scheme.decrypt(pp, sk, ct)
		EndBenchmark(ID)
		decTime += GetGeneralBenchmarks(ID)[RealTime]

		if res != m:
			print('Unsuccessful Decryption')
			break

	stpTime = round((stpTime * 1000) / N, 1)
	kgnTime = round((kgnTime * 1000) / N, 1)
	encTime = round((encTime * 1000) / N, 1)
	decTime = round((decTime * 1000) / N, 1)
	
	results[curve]['lwkpabe'] = {'stp':stpTime, 'kgn':kgnTime, 'enc':encTime, 'dec':decTime}
	
	#------------------------------------------------------------------------
	#OT KPABE
	print("OT KPABE ",curve)
	scheme = KPABE_OT12(groupObj)
	stpTime = 0.0
	kgnTime = 0.0
	encTime = 0.0
	decTime = 0.0

	for i in range(0,N):
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		(pp, mk) = scheme.setup()
		EndBenchmark(ID)
		stpTime += GetGeneralBenchmarks(ID)[RealTime]
	
		policy = '(123 or 444) and (231 or 999)'	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		sk = scheme.keygen(pp,mk,policy)
		EndBenchmark(ID)
		kgnTime += GetGeneralBenchmarks(ID)[RealTime]
	
		m = scheme.randomMessage()
		S = {'123', '842',  '231', '384'}
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		ct = scheme.encrypt(pp,m,S)
		EndBenchmark(ID)
		encTime += GetGeneralBenchmarks(ID)[RealTime]
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		res = scheme.decrypt(pp, sk, ct)
		EndBenchmark(ID)
		decTime += GetGeneralBenchmarks(ID)[RealTime]

		if res != m:
			print('Unsuccessful Decryption')
			break

	stpTime = round((stpTime * 1000) / N, 1)
	kgnTime = round((kgnTime * 1000) / N, 1)
	encTime = round((encTime * 1000) / N, 1)
	decTime = round((decTime * 1000) / N, 1)
	
	results[curve]['otkpabe'] = {'stp':stpTime, 'kgn':kgnTime, 'enc':encTime, 'dec':decTime}
	
	#------------------------------------------------------------------------

	#RW  CPABE
	print("RW CPABE ",curve)
	scheme = CPABE_RW12(groupObj)
	stpTime = 0.0
	kgnTime = 0.0
	encTime = 0.0
	decTime = 0.0

	for i in range(0,N):
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		(pp, mk) = scheme.setup()
		EndBenchmark(ID)
		stpTime += GetGeneralBenchmarks(ID)[RealTime]
	
		S = {'123', '842',  '231', '384'}
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		sk = scheme.keygen(pp,mk,S)
		EndBenchmark(ID)
		kgnTime += GetGeneralBenchmarks(ID)[RealTime]
	
		m = scheme.randomMessage()
		policy = '(123 or 444) and (231 or 999)'		
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		ct = scheme.encrypt(pp,m,policy)
		EndBenchmark(ID)
		encTime += GetGeneralBenchmarks(ID)[RealTime]
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		res = scheme.decrypt(pp, sk, ct)
		EndBenchmark(ID)
		decTime += GetGeneralBenchmarks(ID)[RealTime]

		if res != m:
			print('Unsuccessful Decryption')
			break

	stpTime = round((stpTime * 1000) / N, 1)
	kgnTime = round((kgnTime * 1000) / N, 1)
	encTime = round((encTime * 1000) / N, 1)
	decTime = round((decTime * 1000) / N, 1)
	
	results[curve]['rwcpabe'] = {'stp':stpTime, 'kgn':kgnTime, 'enc':encTime, 'dec':decTime}
	
	#------------------------------------------------------------------------

	#OT  CPABE
	print("OT CPABE ",curve)
	scheme = CPABE_OT12(groupObj)
	stpTime = 0.0
	kgnTime = 0.0
	encTime = 0.0
	decTime = 0.0

	for i in range(0,N):
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		(pp, mk) = scheme.setup()
		EndBenchmark(ID)
		stpTime += GetGeneralBenchmarks(ID)[RealTime]
	
		S = {'123', '842',  '231', '384'}
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		sk = scheme.keygen(pp,mk,S)
		EndBenchmark(ID)
		kgnTime += GetGeneralBenchmarks(ID)[RealTime]
	
		m = scheme.randomMessage()
		policy = '(123 or 444) and (231 or 999)'		
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		ct = scheme.encrypt(pp,m,policy)
		EndBenchmark(ID)
		encTime += GetGeneralBenchmarks(ID)[RealTime]
	
		ID = InitBenchmark()
		StartBenchmark(ID, [RealTime])
		res = scheme.decrypt(pp, sk, ct)
		EndBenchmark(ID)
		decTime += GetGeneralBenchmarks(ID)[RealTime]

		if res != m:
			print('Unsuccessful Decryption')
			break

	stpTime = round((stpTime * 1000) / N, 1)
	kgnTime = round((kgnTime * 1000) / N, 1)
	encTime = round((encTime * 1000) / N, 1)
	decTime = round((decTime * 1000) / N, 1)
	
	results[curve]['otcpabe'] = {'stp':stpTime, 'kgn':kgnTime, 'enc':encTime, 'dec':decTime}

print(" ")
print(N," iterations")
for curve in curves:
	print('Type ', curve)
	for tp in types:
		print(tp, ' Setup: ', ft(results[curve][tp]['stp']), ' Keygen: ', ft(results[curve][tp]['kgn']), ' Encrypt: ', ft(results[curve][tp]['enc']), ' Decrypt: ', ft(results[curve][tp]['dec']) )
		
		
# writing results in a latex file
f = open('./results.tex','w')
f.write('\\documentclass{article}\n')
f.write('\\usepackage{amsmath, multirow}\n\n')
f.write('\\begin{document}\n')
f.write('\\center\n')
f.write('{\\Large Results!}\\\\\n\n')
f.write('\\begin{tabular}{|c|c|c|r|r|r|r|}\n')

f.write('\\hline\n')
f.write('Curve & Type & Scheme & $\\mathsf{Setup}$ & $\\mathsf{KeyGen}$ & $\\mathsf{Encrypt}$ & $\\mathsf{Decrypt}$\\\\\n')

for curve in curves:
	f.write('\\hline\n')
	f.write('\\multirow{5}{*}{``' + curve + '\'\'}')
	for tp in types:
		if (tp == 'rwkpabe'):
			f.write('& \\multirow{3}{*}{Key Pol.} & ')
		elif (tp == 'rwcpabe'):
			f.write('& \\multirow{2}{*}{Ciph. Pol.} & ')
		else:
			f.write('& & ')
		
		if ((tp == 'rwkpabe') or (tp=='rwcpabe')):
			f.write('RW')
		elif (tp == 'lwkpabe'):
			f.write('L')
		else:
			f.write('OT')
		
		f.write('&' + ft(results[curve][tp]['stp']) + ' & ')
		f.write(ft(results[curve][tp]['kgn']) + ' & ')
		f.write(ft(results[curve][tp]['enc']) + ' & ')
		f.write(ft(results[curve][tp]['dec']) + ' \\\\\n')
		if (tp == 'otcpabe'):
			f.write('\\hline\n')
		elif (tp == 'otkpabe'):
			f.write('\\cline{2-7}\n')

f.write('\\end{tabular}\n')
f.write('\\end{document}\n')
f.close()
