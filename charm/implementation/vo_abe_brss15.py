'''
Brent Waters

| From: "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization"
| Published in: 2011
| Available from: https://doi.org/10.1007/978-3-642-19379-8_4
| Notes: Implemented an asymmetric version of the scheme in Section 3
| Security Assumption: Decisional Parallel Bilinear Diffie-Hellman Exponent
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing

:Authors:         Shashank Agrawal
:Date:            05/2016
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.msp import MSP
from utl import text2int,generateVerificationTag,verifyVerificationTag
from utl import *

debug = False


class VO_ABE(ABEnc):

    def __init__(self, group_obj, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        g1.initPP()
        g2.initPP()

        alpha = self.group.random(ZR)
        g1_alpha = g1 ** alpha
        e_gg_alpha = pair(g1_alpha, g2)

        a = self.group.random(ZR)
        g1_a = g1 ** a

        "So that attributes can be indexed from 1"
        h = [0]
        for i in range(self.uni_size):
            h.append(self.group.random(G1))

        pk = {'g1': g1, 'g2': g2, 'g1_a': g1_a, 'h': h, 'e_gg_alpha': e_gg_alpha}
        msk = {'g1_alpha': g1_alpha}
        return (pk, msk)

    def keygen(self, pk, msk, attr_list):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')


        t,alpha_prime = self.group.random(ZR),self.group.random(ZR)

        k0 = (msk['g1_alpha']** (1/alpha_prime) )* (pk['g1_a'] ** t)
        L = pk['g2'] ** t

        K = {}
        for attr in attr_list:
            K[attr] = pk['h'][text2int(attr)] ** t

        return {'TK_S':{'attr_list': attr_list, 'k0': k0, 'L': L, 'K': K},'DK_S':alpha_prime}

    def encrypt(self, pk, msg, policy_str):
        """
         Encrypt a message M under a monotone span program.
        """


        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        u = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            u.append(rand)
        s = u[0]    # shared secret

        c0 = pk['g2'] ** s

        C = {}
        D = {}
        for attr, row in mono_span_prog.items():
            cols = len(row)
            sum = 0
            for i in range(cols):
                sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            r_attr = self.group.random(ZR)
            c_attr = (pk['g1_a'] ** sum) / (self.group.hash(attr_stripped, G1) ** r_attr)
            C[attr] = c_attr

        seed = self.group.random(GT)
        c_m = (pk['e_gg_alpha'] ** s) * seed

        "creating verification key"
        (CT_SE, VK) = generateVerificationTag(msg, seed)


        return {'CT':{'policy': policy, 'c0': c0, 'C': C, 'D': D, 'c_m': c_m, 'CT_SE':CT_SE}, 'VK':VK}

    def transform(self, pk, key, ctxt):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prodG = 1
        prodGT = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodG *= ctxt['C'][attr]
            prodGT *= pair(key['K'][attr_stripped], ctxt['D'][attr])

        ct_part= pair(key['k0'], ctxt['c0'])/(pair(prodG, key['L']) * prodGT)
        return ct_part



    def decrypt(self, pk, DK_S, ctxt,VK,ct_part):
        """
         Decrypt ciphertext ctxt with key key.
        """
        tmp = ct_part ** DK_S
        seed= ctxt['c_m']/tmp

        "testing verification and returning the message"
        return verifyVerificationTag(ctxt['CT_SE'], VK, seed)

