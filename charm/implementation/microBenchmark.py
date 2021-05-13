from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.ecgroup import ECGroup,ZR,G
from charm.toolbox.eccurve import prime192v2
from charm.core.math.integer import *
from utl import *

class MicroBenchmark():

    def __init__(self,grp,n=100):
        self.group=grp
        self.trials=n
        self.benchArray = benchArray
        #self.benchArray = [ "Add", "Sub", "Mul", "Div", "Exp", "Pair"]

    def groupMulG1(self):
        g =  self.group.random(G1)
        #print("Exponentiation in G1")
        self.group.InitBenchmark()

        self.group.StartBenchmark(self.benchArray)
        for i in range(self.trials):
            result = g**self.group.random(ZR)
        self.group.EndBenchmark()

        msmtDict = self.group.GetGeneralBenchmarks()
        print('G1:', avgBenchmark(msmtDict,self.trials)['RealTime'])


    def groupMulG2(self):
        g =  self.group.random(G2)
        #print("Exponentiation in G2")
        self.group.InitBenchmark()
        self.group.StartBenchmark(self.benchArray)

        for i in range(self.trials):
            result = g**self.group.random(ZR)

        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        print('G2:',avgBenchmark(msmtDict,self.trials)['RealTime'])

    def groupMulGT(self):
        g =  self.group.random(GT)
        #print("Exponentiation in GT")
        self.group.InitBenchmark()
        self.group.StartBenchmark(self.benchArray)

        for i in range(self.trials):
            result = g**self.group.random(ZR)

        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        print('GT:',avgBenchmark(msmtDict,self.trials)['RealTime'])


    def groupPairing(self):

        g = self.group.random(G1)
        h = self.group.random(G1)
        i = self.group.random(G2)

        #print("Pairing Cost")
        self.group.InitBenchmark()
        self.group.StartBenchmark(self.benchArray)

        for x in range(self.trials):
            #n = pair(g, h)
            n = pair(h, i)

        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        print('Pairing:',avgBenchmark(msmtDict,self.trials)['RealTime'])


def avgBenchmark(arr, trials):

    for key in benchArray:
        if key in arr:
            if key == "CpuTime" or key == "RealTime":
                arr[key] = arr[key] * miliSecConversion/trials
            else:
                arr[key] = arr[key] * miliSecConversion/trials

    return arr
