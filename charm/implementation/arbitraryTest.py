#from charm.implementation.benchmarkUtils import *
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.schemes.abenc.abenc_waters09 import CPabe09
from microBenchmark import *
from utl import encoding_utf, generateVerificationTag
from utl import *
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair

from numpy import poly

from sys import getsizeof


benchArray=["CpuTime", "RealTime", "NativeTime", "Add", "Sub", "Mul", "Div", "Exp", "Pair", "Granular"]
curve = curves[3]
trials=1
group = PairingGroup(curve)




msg = group.random()

hashed_message = group.hash(str(msg),ZR)
hashed_message = group.hash(str(msg),G2)

print(hashed_message)




g,msg = group.random(G1),group.random(G1)
b,a= group.random(),group.random()




print('Printing binary')

l=2
k=2

str_l = bin(l)[2:]

final_list = ('0'* (k-len(str_l))) + str_l

for c in final_list:
    print(c)


group.InitBenchmark()
group.StartBenchmark(benchArray)


g1 =  group.random(G1)
g2 = group.random(G2)
a =  group.random()
b = group.random()

gt = group.random(GT)

i=10
print('integer size:', i.__sizeof__())
print('len:', len(str(g1)))
print('g1 size:',g1.__sizeof__())
print('g2 size:',g2.__sizeof__())
print('gt size:',gt.__sizeof__())
print('p size:',a.__sizeof__())



print('integer size:',getsizeof(i))
print('g1 size:',getsizeof(g1))
print('g2 size:',getsizeof(g2))
print('gt size:',getsizeof(gt))
print('p size:',getsizeof(a))

generateVerificationTag('Hello World', g1)