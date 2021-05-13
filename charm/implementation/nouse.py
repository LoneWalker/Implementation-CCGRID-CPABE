from revo_abe import *
from charm.toolbox.pairinggroup import PairingGroup,G1,GT,ZR
from vo_abe_brss15 import *

from utl import message
from utl import *

print('<<<<<<<    VO_ABE    >>>>>>>')

for curve in curves:


    groupObj = PairingGroup(curve)

    uni_size = 100
    cpabe = VO_ABE(groupObj,uni_size)

    stpTime = 0.0
    kgnTime = 0.0
    encTime = 0.0
    transTime=0.0
    decTime = 0.0

    print('>>>>>>>>>>>>>>>>>>>>>>>>>>>',curve,'<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
    for itr in range(trials):

        print("########  setup  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (pk, mk) = cpabe.setup()
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        stpTime+=msmtDict['RealTime']
        print(avgBenchmark(msmtDict, trials))

        #print('pk=>',pk)
        #print('sk=>',mk)


        print("########  keygen  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        SK = cpabe.keygen(pk, mk, attrs)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        kgnTime += msmtDict['RealTime']
        print(avgBenchmark(msmtDict, trials))

        #print("pk :=>", pk)
        #print("sk :=>", SK['sk'])
        #print("tk :=>", SK['tk'])


        print("########  Encrypt  #######")

        #rand_msg = groupObj.random(GT)
        #print("msg =>", rand_msg)

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct = cpabe.encrypt(pk, message, access_policy)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        encTime += msmtDict['RealTime']
        print(avgBenchmark(msmtDict, trials))


        #print(ct_full)


        print("########  Transform  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct_part = cpabe.transform(pk, SK['TK_S'], ct['CT'])
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        transTime += msmtDict['RealTime']
        print(avgBenchmark(msmtDict, trials))



        print("########  Decrypt   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        rec_msg = cpabe.decrypt(pk, SK['DK_S'], ct['CT'],ct['VK'], ct_part )
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        decTime += msmtDict['RealTime']
        print(avgBenchmark(msmtDict, trials))

        #print("Rec msg =>", rec_msg)

        #assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
        if message == rec_msg:
            print("Successful Decryption!!!")
        else:
            print("FAILED Decryption: message is incorrect")

    stpTime = stpTime*miliSecConversion/trials
    kgnTime = kgnTime*miliSecConversion/trials
    encTime = encTime*miliSecConversion/trials
    transTime = transTime*miliSecConversion/trials
    decTime = decTime*miliSecConversion/trials

    results={'stpTime':stpTime,'kgnTime':kgnTime,'encTime':encTime,'transTime':transTime,'decTime':decTime}
    print(results)
