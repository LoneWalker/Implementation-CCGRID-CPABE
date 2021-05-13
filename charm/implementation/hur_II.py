'''
:Authors:         Azharul Islam
:Date:            12/01/2017
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from utl import generateVerificationTag,verifyVerificationTag, bytesToString
from utl import *
from numpy import poly
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.math.pairing import hashPair as sha2




debug = False


class Hur_II_13Improving(ABEnc):

    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = Hur_II_13Improving(group)
    >>> msg = group.random(GT)
    >>> attributes = ['ONE', 'TWO', 'THREE']
    >>> access_policy = '((four or three) and (three or one))'
    >>> (master_public_key, master_key) = cpabe.setup()
    >>> secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> msg == decrypted_msg
    True
    """

    """
    It was assumed that x_i are created in the setup phase. During the encryption, a single polynomial group is created for all the attributes.
    For that, first polynomial is created from all x_i. Then these are raised in the exponent of g1. The the polynomial is randomized by blinding
    factor R. For now this is done once and used for all the polinomials.
    """

    def __init__(self, groupObj, total_users):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
        self.total_users = total_users

    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        # initialize pre-processing for generators
        g.initPP();
        gp.initPP()

        (beta, h, f) = self.KKeyGen(g)
        (g2_alpha, e_gg_alpha, PK_D_agree,gamma, rho, g_rho) = self.DKeyGen(g,gp)

        pk = {'g': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha, 'PK_D_agree':PK_D_agree, 'g_rho':g_rho}
        mk = {'beta': beta, 'g2_alpha': g2_alpha, 'gamma':gamma, 'rho':rho}
        return (pk, mk)


    def keygen(self, pk, mk, S):
        r = group.random()
        g2_r = (pk['g2'] ** r)
        D = (mk['g2_alpha'] * g2_r) ** (1 / (mk['beta']))
        D_j, D_j_pr = {}, {}

        for j in S:
            r_j = group.random()
            D_j[j] = g2_r * (group.hash(j, G2) ** (r_j))
            D_j_pr[j] = pk['g'] ** (r_j)

        SK_ut_agree = group.hash(str(self.list_ID[0]),G2) ** mk['gamma']

        return {'D': D, 'Dj': D_j, 'Djp': D_j_pr, 'S': S, 'SK_ut_agree':SK_ut_agree}


    def KKeyGen(self, g1):
        beta = group.random()
        h = g1 ** beta
        f = g1 ** ~beta
        return (beta, h, f)


    def DKeyGen(self, g1, g2):
        alpha, gamma, rho = group.random(ZR), group.random(ZR), group.random(ZR)
        g2_alpha = g2 ** alpha
        e_gg_alpha = pair(g1, g2_alpha)
        PK_D_agree = g1 ** gamma
        g_rho=g1 ** rho

        self.list_ID=[]
        self.list_xi = {}
        for i in range(self.total_users):
            ID= group.random(ZR)
            self.list_ID.append(ID)
            hash_ID= group.hash(str(ID),G2)
            x_ID_pairing = pair(PK_D_agree,hash_ID ** rho)
            x_i = group.hash(str(x_ID_pairing),ZR)
            self.list_xi[ID]=x_i
        return (g2_alpha, e_gg_alpha, PK_D_agree,gamma, rho, g_rho)

    def createPolyExponent(self, user_id_list, g1, attr):
        poly_root_list = []
        for user_id in user_id_list:
            poly_root_list.append(self.list_xi[user_id])

        "function poly will return the coefficients in a list in the order: a_n x^n + a_(n-1)x^(n-1)+.........+a_0"
        polynomial =  poly(poly_root_list)
        self.exp_poly = []
        for exp in polynomial:
            self.exp_poly.append(g1**exp)
        return self.exp_poly

    def randomizeExpPoly(self, exp_poly):
        randomized_exp_poly = []
        R= group.random(ZR)
        for exp_poly_term in exp_poly:
            randomized_exp_poly.append(exp_poly_term **R)

        return randomized_exp_poly

    def createHdr(self, K_lambda,pk):
        exp_poly = self.createPolyExponent(self.list_ID, pk['g'], 'dummy')
        randomized_exp_poly = self.randomizeExpPoly(exp_poly)
        P_0_R_lambda = K_lambda * randomized_exp_poly[-1]

        return {'P_0_lambda':P_0_R_lambda,'P_R_list':randomized_exp_poly[0:-1] }


    def encrypt(self, pk, M, policy_str):

        session_key = group.random(GT)
        cipher = AuthenticatedCryptoAbstraction(sha2(session_key))
        c2 = cipher.encrypt(M)

        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s = group.random(ZR)
        shares = util.calculateSharesDict(s, policy)

        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = group.hash(j, G2) ** shares[i]

        return {'C_tilde': (pk['e_gg_alpha'] ** s) * session_key,
                'C': C, 'Cy': C_y, 'Cyp': C_y_pr, 'policy': policy_str, 'attributes': a_list, 'ct_se':c2}


    def reEncrypt(self, pk, CT):

        C_y_pr = CT['Cyp']
        K_lambda_g = group.random(G1)
        K_lambda = group.hash(str(K_lambda_g),ZR)
        Cy_pr_reenc = {}

        #print('original K-Lambda_g:', K_lambda_g)
        #print('original K-Lambda:', K_lambda)

        for att in C_y_pr.keys():
            Cy_pr_reenc[att] =  C_y_pr[att] ** K_lambda

        CT['Cy_pr_re'] = Cy_pr_reenc
        CT['Cy_re'] = CT['Cy']

        Hdr = self.createHdr(K_lambda_g,pk)
        CT['Hdr']=Hdr

        return CT



    def decrypt(self, pk, sk, ct ):


        K_lambda_g = self.decryptHdr(pk,sk, ct)
        K_lambda =  group.hash(str(K_lambda_g),ZR)

        #print('k_lambda_g', K_lambda_g)
        #print('k_lambda',K_lambda)

        D_j_pr = sk['Djp']
        D_j_pr_re = {}
        for key in D_j_pr.keys():
            D_j_pr_re[key] = D_j_pr[key] ** (1/K_lambda)


        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, sk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex();
            k = i.getAttribute()
            A *= (pair(ct['Cy_re'][j], sk['Dj'][k]) / pair(D_j_pr_re[k], ct['Cy_pr_re'][j])) ** z[j]

        session_key = ct['C_tilde'] / (pair(ct['C'], sk['D']) / A)
        cipher = AuthenticatedCryptoAbstraction(sha2(session_key))
        return bytesToString(cipher.decrypt(ct['ct_se']))


    def localKeyUpdate(self, pk, sk, ct ):
        K_lambda_g = self.decryptHdr(pk,sk, ct)
        K_lambda =  group.hash(str(K_lambda_g),ZR)



    def decryptHdr(self, pk, sk, ct):

        x_t_pairing = pair(pk['g_rho'], sk['SK_ut_agree'] )
        curr_x_t = x_t = group.hash(str(x_t_pairing),ZR)

        Hdr =  ct['Hdr']
        result = Hdr['P_0_lambda']
        reversed_P_R_list = Hdr['P_R_list'][::-1]
        for P_R_i in reversed_P_R_list:
            result = result * ((P_R_i)**curr_x_t)
            curr_x_t=curr_x_t*x_t

        return result


    def ciphertextUpdate(self, pk, ct):
        s_pr = group.random(ZR)
        K_lambda_g = group.random(G1)
        K_lambda = group.hash(str(K_lambda_g), ZR)

        ct['C_tilde'] = ct['C_tilde'] * (pk['e_gg_alpha'] ** s_pr)
        ct['C'] = ct['C'] * (pk['h'] ** s_pr)

        C_y = ct['Cy']

        for i in C_y.keys():
            j = util.strip_index(i)
            ct['Cy_re'][i] = ct['Cy'][i] * (pk['g'] ** s_pr)
            ct['Cy_pr_re'][i] = (ct['Cyp'][i] * (group.hash(j, G2) ** s_pr)) ** K_lambda

        #ct['Hdr'] = self.keyUpdateOnRemove(K_lambda, pk, self.list_ID[-1])

        return (ct, K_lambda_g)


    def keyUpdateOnRemove(self, K_lambda_g, pk):

        "Revoking the last member"

        #remove_id = self.list_ID[-1]
        #self.list_ID.remove(remove_id)
        remove_id = self.list_ID.pop()
        self.list_xi.pop(remove_id)


        return self.createHdr(K_lambda_g,pk)








