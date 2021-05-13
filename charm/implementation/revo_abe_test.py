from revo_abe import *
from charm.toolbox.pairinggroup import PairingGroup,G1,GT,ZR
from utl import ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS,benchArray, miliSecConversion
from utl import *







def runReVO_ABE(grp_obj,total_users):
    print('<<<<<<<ReVO_ABE>>>>>>>')


    #groupObj =  PairingGroup(curve)
    groupObj = grp_obj
    cpabe = ReVO_ABE(groupObj,total_users)
    stpTime = 0.0
    kgnTime = 0.0
    encTime = 0.0
    transTime=0.0
    decTime = 0.0
    grpStpTime=0.0
    updateTime=0.0
    cloudUpdateTime=0.0
    reKeyingTime =0.0


    for itr in range(TRIALS):

        #print("########  setup  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (pk, mk) = cpabe.setup()
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        stpTime+=msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        # print("########  Groupsetup  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        cpabe.group_setup(pk)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        grpStpTime += msmtDict['RealTime']
        # print(avgBenchmark(msmtDict, trials))



        #print("########  keygen  #######")

        "Group public private key preparation"
        version = 0
        skg = groupObj.random()
        SKG = {'version': version, 'skg': skg}
        pkg = pk['g'] ** skg
        PKG = {'version': version, 'pkg': pkg}
        "Group public private key preparation ends "

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


        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct_full = cpabe.encrypt(pk, MESSAGE, ACCESS_POLICY, PKG)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        encTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))


        #print(ct_full)


        #print("########  Transform  #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct_part = cpabe.transform(pk, SK['tk'], ct_full['ct'])
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        transTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))



        #print("########  Decrypt   #######")
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (rg,seed,rec_msg) = cpabe.decrypt(pk, SK['sk'], SKG, ct_full['ct'], ct_part, ct_full['ctg'], ct_full['ct_se'],ct_full['vk'])
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        decTime += msmtDict['RealTime']
        #print(avgBenchmark(msmtDict, trials))

        #print("Rec msg =>", rec_msg)

        assert MESSAGE == rec_msg, "FAILED Decryption: message is incorrect"
        #if message == rec_msg:
        #    print("Successful Decryption!!!")
        #else:
        #    print("FAILED Decryption: message is incorrect")


        # print("########  Update Time   #######")
        "Cost at the owner side during re-encryption"
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        (ct_full, p_rk) = cpabe.update(pk, ct_full, rg, seed, MESSAGE,PKG)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        updateTime += msmtDict['RealTime']
        # print(avgBenchmark(msmtDict, trials))


        # print("########  Cloud Update   #######")
        "Cost at the cloud side during re-encryption"
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        ct_full = cpabe.updateCloud(pk, ct_full, p_rk)
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        cloudUpdateTime += msmtDict['RealTime']
        # print(avgBenchmark(msmtDict, trials))


        # print("########  Re-Keying   #######")
        "Local re-keying time"
        groupObj.InitBenchmark()
        groupObj.StartBenchmark(benchArray)
        cpabe.reKey()
        groupObj.EndBenchmark()
        msmtDict = groupObj.GetGeneralBenchmarks()
        reKeyingTime+= msmtDict['RealTime']
        # print(avgBenchmark(msmtDict, trials))

    stpTime = stpTime*miliSecConversion/TRIALS
    grpStpTime = grpStpTime * miliSecConversion / TRIALS
    kgnTime = kgnTime*miliSecConversion/TRIALS
    encTime = encTime*miliSecConversion/TRIALS
    transTime = transTime*miliSecConversion/TRIALS
    decTime = decTime*miliSecConversion/TRIALS
    reKeyingTime = reKeyingTime * miliSecConversion / TRIALS
    updateTime = updateTime * miliSecConversion / TRIALS
    cloudUpdateTime = cloudUpdateTime * miliSecConversion / TRIALS

    results={'stpTime':stpTime,'grpStpTime':grpStpTime, 'kgnTime':kgnTime,'encTime':encTime,'transTime':transTime,'decTime':decTime, 'reKeyingTime':reKeyingTime,'updateTime':updateTime, 'cloudUpdateTime':cloudUpdateTime}

    print(results)
