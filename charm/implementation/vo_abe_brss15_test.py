from revo_abe import *
from charm.toolbox.pairinggroup import PairingGroup,G1,GT,ZR
from vo_abe_brss15 import *

from utl import UNIVERSE_SIZE, ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS
from utl import *



def runVO_ABE(grp_obj ):
    print('<<<<<<<    VO_ABE    >>>>>>>')

    #groupObj = PairingGroup(curve)
    groupObj = grp_obj
    cpabe = VO_ABE(groupObj,UNIVERSE_SIZE)

    stpTime = 0.0
    kgnTime = 0.0
    encTime = 0.0
    transTime=0.0
    decTime = 0.0

    #print('>>>>>>>>>>>>>>>>>>>>>>>>>>>',curve,'<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
    for itr in range(TRIALS):

        #print("########  setup  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (pk, mk) = cpabe.setup()
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        stpTime+=msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print('pk=>',pk)
        #print('sk=>',mk)


        #print("########  keygen  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        SK = cpabe.keygen(pk, mk, ATTRIBUTES)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        kgnTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print("pk :=>", pk)
        #print("sk :=>", SK['sk'])
        #print("tk :=>", SK['tk'])


        #print("########  Encrypt  #######")

        #rand_msg = groupObj.random(GT)
        #print("msg =>", rand_msg)

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct = cpabe.encrypt(pk, MESSAGE, ACCESS_POLICY)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        encTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))


        #print(ct_full)


        #print("########  Transform  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct_part = cpabe.transform(pk, SK['TK_S'], ct['CT'])
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        transTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))



        #print("########  Decrypt   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        rec_msg = cpabe.decrypt(pk, SK['DK_S'], ct['CT'],ct['VK'], ct_part )
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        decTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print("Rec msg =>", rec_msg)

        assert MESSAGE == rec_msg, "FAILED Decryption: message is incorrect"
        #if message == rec_msg:
         #   print("Successful Decryption!!!")
        #else:
        #    print("FAILED Decryption: message is incorrect")

    stpTime = stpTime*miliSecConversion/TRIALS
    kgnTime = kgnTime*miliSecConversion/TRIALS
    encTime = encTime*miliSecConversion/TRIALS
    transTime = transTime*miliSecConversion/TRIALS
    decTime = decTime*miliSecConversion/TRIALS

    results={'stpTime':stpTime,'kgnTime':kgnTime,'encTime':encTime,'transTime':transTime,'decTime':decTime}
    print(results)

groupObj = PairingGroup(curves[0])
runVO_ABE(groupObj)