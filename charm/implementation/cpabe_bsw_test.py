from revo_abe import *
from charm.toolbox.pairinggroup import PairingGroup,G1,GT,ZR
from utl import *
from utl import UNIVERSE_SIZE, ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS, bytesToString
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc




def runBSW(grp_obj):
    print('<<<<<<< BSW CPABE_0 >>>>>>>')


    #groupObj = PairingGroup(curve)
    groupObj = grp_obj
    cpabe = CPabe_BSW07(groupObj)
    hyb_abe = HybridABEnc(cpabe, groupObj)

    stpTime = 0.0
    kgnTime = 0.0
    encTime = 0.0
    decTime = 0.0

    #print('>>>>>>>>>>>>>>>>>>>>>>>>>>>',curve,'<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
    for itr in range(TRIALS):

        #print("########  setup  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (pk, mk) = hyb_abe.setup()
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        stpTime+=msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))


        #print("########  keygen  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        sk = hyb_abe.keygen(pk, mk, ATTRIBUTES)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        kgnTime += msmtDict['RealTime']



        #print("########  Encrypt  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct = hyb_abe.encrypt(pk, MESSAGE, ACCESS_POLICY)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        encTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))
        #print(ct)

        #print("########  Decrypt   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        rec_msg = hyb_abe.decrypt(pk, sk, ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        decTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))
        rec_msg =  bytesToString(rec_msg)

        assert MESSAGE == rec_msg, "FAILED Decryption: message is incorrect"

    stpTime = stpTime*miliSecConversion/TRIALS
    kgnTime = kgnTime*miliSecConversion/TRIALS
    encTime = encTime*miliSecConversion/TRIALS
    decTime = decTime*miliSecConversion/TRIALS

    results={'stpTime':stpTime,'kgnTime':kgnTime,'encTime':encTime,'decTime':decTime}
    print(results)
