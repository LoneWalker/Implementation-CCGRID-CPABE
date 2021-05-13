from charm.toolbox.pairinggroup import PairingGroup,G1,ZR
from microBenchmark import *
from utl import  TRIALS





def runBenchmark():
    print("Microbenchmark testing>>>>>>>>>>>>>>>>>>>>>>>")
    for curve in curves:
        print("<<<<<<<<<For curve type" + curve + ">>>>>>>>>>>>>>>")
        group = PairingGroup(curve)
        micro = MicroBenchmark(group, TRIALS)
        micro.groupMulG1()
        micro.groupMulG2()
        micro.groupMulGT()
        micro.groupPairing()
