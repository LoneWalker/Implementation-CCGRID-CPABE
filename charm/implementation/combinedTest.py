from microBenchmark_test import *
from charm.toolbox.pairinggroup import PairingGroup,G1,ZR
from utl import UNIVERSE_SIZE, ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS,curves,TOTAL_USERS
from vo_abe_brss15_test import runVO_ABE
from revo_abe_test import runReVO_ABE
from hur_II_test import runHur_II
from cpabe_bsw_test import runBSW



runBenchmark()


for curve in curves:
    print('>>>>>>>>>>>>>>>>>>>>>>>>>>>', curve, '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<')
    groupObj = PairingGroup(curve)

    runReVO_ABE(groupObj,TOTAL_USERS)
    runVO_ABE(groupObj)
    runHur_II(groupObj, TOTAL_USERS)
    runBSW(groupObj)

    print('  ')
    print('  ')
    print('  ')





