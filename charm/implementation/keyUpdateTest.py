from microBenchmark_test import *
from charm.toolbox.pairinggroup import PairingGroup,G1,ZR
from utl import UNIVERSE_SIZE, ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS,curves,benchArray,miliSecConversion
from revo_abe_test import runReVO_ABE
from hur_II_test import runHur_II



#runBenchmark()

#no_of_users=[50,100,150,200,300,400,500,600,800]

no_of_users=[20, 30, 40, 50, 60, 70, 80, 90, 100, 150, 200, 250, 300, 350, 400, 500, 600, 700, 800]
#no_of_users=[20,  100, 1000]


def groupMergeTime(group):
    g = group.random(G1)
    a = group.random()
    b = group.random()
    ga = g ** a
    gb = g ** b
    group.InitBenchmark()
    group.StartBenchmark(benchArray)

    gab = ga ** b

    group.EndBenchmark()
    msmtDict = group.GetGeneralBenchmarks()
    print("Group merge time:", (msmtDict['RealTime']*miliSecConversion))

curves =['SS512']

for users in no_of_users:

    print('######################Total Users:',users,'########################')

    for curve in curves:

        print('>>>>>>>>>>>>>>>>>>>>>>>>>>>', curve, '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
        groupObj = PairingGroup(curve)

        groupMergeTime(groupObj)
        runReVO_ABE(groupObj,users)
        #runHur_II(groupObj,users)
        #runBSW(curve)

        print('  ')
        print('  ')
        print('  ')


