from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.msp import MSP
from math import log2, ceil, floor
from collections import deque, defaultdict
from utl import *


debug = False

"""
Note: 
    1) h1, h2, h3, ..... are replaced by hash function hash: {0,1}* -> G1
        In the implementation, it is self.group.hash(attr, G1)
    2) In the paper, we have K_i in group G2 and D in group G1
        in the implementation, we have to switch the groups.
        because hash of attribute in G1 produces different result
        than hash of attribute in G2

"""
class ColResABECCGRID(ABEnc):

    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        #self.uni_size = uni_size  # bound on the size of the universe of attributes
        # MSP = monotone span program
        self.util = MSP(self.group, verbose)
        self.membership_tree = None
        self.m = 0



    def setup(self, m:int):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        self.m = m
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        g1_alpha = g1 ** alpha
        g2_beta = g2 ** beta
        e_gg_alpha = pair(g1_alpha, g2)

        a = self.group.random(ZR)
        g1_a = g1 ** a

        self.membership_tree = MembershipTree(m, g1, self.group)

        pk = {'membership_tree':self.membership_tree, 'g1': g1, 'g2': g2,
              'e_gg_alpha': e_gg_alpha, 'g1_a': g1_a, 'g2_beta': g2_beta}
        msk = {'g1_alpha': g1_alpha, 'beta': beta}
        return pk, msk

    def keygen(self, pk, msk, attr_list, user_id):
        """
        Generate a key for the user with user id = user_id and a set of attributes.
        """
        if not self.membership_tree or  not (1 <= user_id <= self.m): return None

        if debug: print('Key generation algorithm:\n')

        t = self.group.random(ZR)
        g_alpha_at = msk['g1_alpha'] * (pk['g1_a'] ** t)
        L = pk['g2'] ** t
        K_y = {}
        for node in pk['membership_tree'].getUserPath(user_id):
            K_y[node.y_i] = (g_alpha_at*node.g_y_i) ** (1/msk['beta'])

        K_i = {}
        for attr in attr_list:
            K_i[attr] = self.group.hash(attr, G1) ** t


        return {'attr_list': attr_list, 'K_y':K_y , 'L': L, 'K_i': K_i}

    def encrypt(self, pk, msg, policy_str, RL):
        """
         Encrypt a message M under a monotone span program.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret
        r = self.group.random(ZR)
        C_prime = pk['g2_beta']**s
        D = pk['g2']**r

        C_y = {}
        for node in pk['membership_tree'].getSubsetCover(RL):
            C_y[node.y_i] = node.g_y_i ** s

        C_i = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            lambda_i = 0
            for i in range(cols):
                lambda_i += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            C_i[attr] = (pk['g1_a'] ** lambda_i) / (self.group.hash(attr_stripped, G1)**r)

        seed = self.group.random(GT)
        C = (pk['e_gg_alpha'] ** s) * seed

        "creating verification key"
        (CT_SE, VK) = generateVerificationTag(msg, seed)

        return {'policy': policy, 'C': C, 'C_prime':C_prime, 'D': D, 'C_y':C_y, 'C_i':C_i, 'CT_SE': CT_SE, 'VK':VK}

    def decrypt(self, pk, ctxt, key):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        # Getting the common y_i associated with K_y and C_y
        common_y_i = set(key['K_y'].keys()).intersection(ctxt['C_y'])
        if not common_y_i:
            print ("This user is in the revocation list.")
            return None
        y_i = list(common_y_i)[0]

        P = pair(key['K_y'][y_i], ctxt['C_prime'])
        Q = pair(ctxt['C_y'][y_i], pk['g2'])


        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prodC_i = 1
        prodK_i = 1
        # here in the implementation omega_i = 1 because we are only rows that are necessary
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodC_i*= ctxt['C_i'][attr]
            prodK_i*= key['K_i'][attr_stripped]

        # in the paper, we have K_i in group G2 and D in group G1
        # in the implementation, we have to switch the groups.
        # because hash of attribute in G1 produces different result
        # than hash of attribute in G2
        W = P / (Q * pair(prodC_i, key['L']) * pair(prodK_i, ctxt['D']) )

        seed = ctxt['C']/W
        return verifyVerificationTag(ctxt['CT_SE'], ctxt['VK'], seed)

class MembershipTree:
    def __init__(self, m, g1, group):
        self.m = m
        self.user_id_to_leaf = defaultdict(TreeNode)
        self.root = self.createTree(g1, group)

    def getUserPath(self, user_id):
        if not (1 <= user_id <= self.m): return []
        res = []
        node = self.user_id_to_leaf[user_id]
        while node:
            res.append(node)
            node = node.parent
        return res



    def getSubsetCover(self, RL:list):
        res = []
        if not RL: return []
        # all the nodes in the path of each user in RL are colored as RED
        def colorRED(node):
            while node and node.color == node.GREEN:
                node.color = node.RED
                node = node.parent
            return
        def getSubsetCoverNodesAndResetColor(node):
            if not node: return
            if node.color == node.GREEN:
                res.append(node)
                return
            node.color = node.GREEN
            getSubsetCoverNodesAndResetColor(node.left)
            getSubsetCoverNodesAndResetColor(node.right)
            return

        for user_id in RL:
            if 1 <= user_id <= self.m: colorRED(self.user_id_to_leaf[user_id])

        getSubsetCoverNodesAndResetColor(self.root)
        return res

    def createTreeNode(self, g1, group, parent, y_i):
        node = TreeNode(y_i, g1 ** group.random(ZR), parent)
        return node

    def createTree(self, g1, group):
        if self.m < 1: return None
        user_id_counter = 1

        def dfs(parent, y_i, h):
            nonlocal  user_id_counter
            node = self.createTreeNode(g1, group,parent, y_i)
            if h == 0:
                node.user_id = user_id_counter
                self.user_id_to_leaf[user_id_counter] = node
                user_id_counter+=1
                return node

            node.left = dfs(node, 2*y_i, h-1)
            node.right = dfs(node, 2*y_i+1, h-1)
            return node

        return dfs(None, 1, ceil(log2(self.m)))

class TreeNode:
    def __init__(self, y_i, g_y_i, parent):
        self.y_i = y_i
        self.g_y_i = g_y_i
        self.left, self.right, self.parent = None, None, parent
        self.user_id = -1
        self.RED, self.GREEN = 0, 1
        self.color = self.GREEN


