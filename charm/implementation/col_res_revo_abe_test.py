from microBenchmark_test import *
from charm.toolbox.pairinggroup import PairingGroup,G1,ZR
from utl import UNIVERSE_SIZE, ATTRIBUTES, ACCESS_POLICY, MESSAGE, TRIALS,curves,TOTAL_USERS
from col_res_revo_abe import MembershipTree, ColResABECCGRID


groupObj = PairingGroup(curves[0])
g1 = groupObj.random(G1)
m = 8
RL = [2,6]
revoked_user = 2
nonrevoked_user = 8
message = "This is message is supposed to be secret!"

abe_obj = ColResABECCGRID(groupObj)
pk, msk = abe_obj.setup(m)
ctxt = abe_obj.encrypt(pk, message , ACCESS_POLICY, RL)
key = abe_obj.keygen(pk, msk, ATTRIBUTES, nonrevoked_user)
plaintext = abe_obj.decrypt(pk, ctxt, key)

print(plaintext)



"""
tree = MembershipTree(m, g1, groupObj)

for node in  tree.getSubsetCover(RL):
    print("node_id: {}".format(node.y_i))

print(tree.m)
"""





