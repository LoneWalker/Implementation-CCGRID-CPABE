from charm.toolbox.pairinggroup import PairingGroup,G1,GT,ZR
from utl import ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS,miliSecConversion, benchArray
from utl import *
from hur_II import Hur_II_13Improving






def runHur_II(grp_obj, total_users):
    print('<<<<<<<Hur-II>>>>>>>')


    #groupObj = PairingGroup(curve)
    groupObj = grp_obj

    #MESSAGE =  groupObj.random(GT)

    cpabe = Hur_II_13Improving(groupObj, total_users)
    stpTime = 0.0
    kgnTime = 0.0
    encTime = 0.0
    decTime = 0.0
    reEncTime=0.0
    ctUpdate = 0.0
    cloudKeyUpdate = 0.0
    localKeyUpdate = 0.0


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


        #print("########  keygen  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        sk = cpabe.keygen(pk, mk, ATTRIBUTES)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        kgnTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print("pk :=>", pk)
        #print("sk :=>", SK['sk'])
        #print("tk :=>", SK['tk'])


        #print("########  Encrypt  #######")


        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct = cpabe.encrypt(pk, MESSAGE, ACCESS_POLICY)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        encTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))


        #print(ct_full)

        # print("########  Re-Encrypt  #######")

        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct = cpabe.reEncrypt(pk, ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        reEncTime += msmtDict['RealTime']



        #print("########  Decrypt   #######")

        "During each decryption, HDr decryption is necessary since for different ciphertext, it is different"
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        rec_msg = cpabe.decrypt(pk, sk, ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        decTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print("Rec msg =>", rec_msg)

        assert MESSAGE == rec_msg, "FAILED Decryption: message is incorrect"



        # print("########  Local KeyUpdate   #######")
        "This cost is exactly the same as Hdr decryption cost"
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        cpabe.localKeyUpdate(pk, sk, ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        localKeyUpdate += msmtDict['RealTime']




        # print("########  ctUpdate   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (ct, K_lambda_g) = cpabe.ciphertextUpdate(pk,ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        ctUpdate += msmtDict['RealTime']

        # print("########  keyUpdate   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        Hdr = cpabe.keyUpdateOnRemove(K_lambda_g, pk)
        ct['Hdr'] = Hdr
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        cloudKeyUpdate += msmtDict['RealTime']

        # print("########  Decrypt   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        rec_msg = cpabe.decrypt(pk, sk, ct)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        #decTime += msmtDict['RealTime']
        assert MESSAGE == rec_msg, "FAILED Decryption: message is incorrect"

    stpTime = stpTime*miliSecConversion/TRIALS
    kgnTime = kgnTime*miliSecConversion/TRIALS
    encTime = encTime*miliSecConversion/TRIALS
    reEncTime = reEncTime * miliSecConversion / TRIALS
    decTime = decTime*miliSecConversion/TRIALS
    ctUpdate = ctUpdate * miliSecConversion / TRIALS
    cloudKeyUpdate = cloudKeyUpdate * miliSecConversion / TRIALS
    localKeyUpdate = localKeyUpdate * miliSecConversion / TRIALS

    results={'stpTime':stpTime,'kgnTime':kgnTime,'encTime':encTime,'decTime':decTime, 'reEncTime':reEncTime, 'ctUpdate':ctUpdate, 'keyUpdate':cloudKeyUpdate,'localKeyUpdate':localKeyUpdate}
    print(results)
