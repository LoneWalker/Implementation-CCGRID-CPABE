'''
:Authors:         Azharul Islam
:Date:            12/01/2017
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from utl import generateVerificationTag,verifyVerificationTag
from utl import *
from math import log2, ceil, floor




debug = False



class ReVO_ABE(ABEnc):


    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = ReVO_ABE(group)
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

    leafNodeList=[]


    def __init__(self, groupObj,total_users):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj
        self.total_users = total_users





    def setup(self):
        g, gp = group.random(G1), group.random(G2)
        alpha, beta = group.random(ZR), group.random(ZR)
        # initialize pre-processing for generators
        g.initPP();
        gp.initPP()

        h = g ** beta;
        f = g ** ~beta
        g2_alpha = gp ** alpha
        e_gg_alpha = pair(g, g2_alpha)

        pk = {'g': g, 'g2': gp, 'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
        mk = {'beta': beta, 'g2_alpha': g2_alpha}
        return (pk, mk)



    def keygen(self, pk, mk, S):
        r,t = group.random(),group.random(ZR)
        g2_r = (pk['g2'] ** r)
        D = (mk['g2_alpha'] * g2_r) ** (1 / (mk['beta']*t))
        D_j, D_j_pr = {}, {}
        g2_r_t = g2_r ** (1/t)
        for j in S:
            r_j = group.random()
            D_j[j] = g2_r_t * (group.hash(j, G2) ** (r_j/t))
            D_j_pr[j] = pk['g'] ** (r_j/t)
        return {'sk':t,'tk':{'D': D, 'Dj': D_j, 'Djp': D_j_pr, 'S': S}}


    def encrypt(self, pk, M, policy_str,PKG):
        policy = util.createPolicy(policy_str)
        a_list = util.getAttributeList(policy)
        s,g_rg,w_ = group.random(ZR), group.random(G1),group.random(ZR)
        shares = util.calculateSharesDict(s, policy)

        "Creating group token"
        rg= group.hash(str(g_rg),ZR)
        #print("rg=>",rg)
        C_4=pk['g']**w_
        C_5=g_rg * (PKG['pkg']**w_)
        ctg = {'version':PKG['version'],'C_4':C_4,'C_5':C_5}
        "end group token creating"

        C = pk['h'] ** (s/rg)

        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = util.strip_index(i)
            C_y[i] = pk['g'] ** (shares[i]/rg)
            C_y_pr[i] = group.hash(j, G2) ** (shares[i]/rg)

        seed = group.random(GT)
        C_tilde=(pk['e_gg_alpha'] ** (s*rg)) * seed

        "Generation of verification key VK"
        "creating verification key"
        (CT_SE, VK) = generateVerificationTag(M, seed)


        return {'ct':{'C_tilde': C_tilde,
                'C': C, 'Cy': C_y, 'Cyp': C_y_pr, 'policy': policy_str, 'attributes': a_list},'ctg':ctg,'ct_se': CT_SE, 'vk':VK}




    def transform(self, pk, tk, ct):
        policy = util.createPolicy(ct['policy'])
        pruned_list = util.prune(policy, tk['S'])
        if pruned_list == False:
            return False
        z = util.getCoefficients(policy)
        A = 1
        for i in pruned_list:
            j = i.getAttributeAndIndex();
            k = i.getAttribute()
            A *= (pair(ct['Cy'][j], tk['Dj'][k]) / pair(tk['Djp'][k], ct['Cyp'][j])) ** z[j]

        D_0_prime = pair(ct['C'], tk['D']) / A
        return {'D_0_prime':D_0_prime}

    def decrypt(self, pk, sk, SKG, ct, ct_part,ctg,ct_se,vk):

        g_rg = ctg['C_5']/(ctg['C_4']**SKG['skg'] )
        rg= group.hash(str(g_rg),ZR)
        #print('rg=>',rg)

        D_0 = ct_part['D_0_prime']**(sk*rg*rg)

        seed = ct['C_tilde'] / D_0
        return (rg, seed, verifyVerificationTag(ct_se, vk, seed) )

    def update(self, pk, ct_full, rg_old, seed_old, M,PKG):
        g_rg,w_ = group.random(G1),group.random(ZR)
        ct = ct_full['ct']

        "Creating group token"
        rg= group.hash(str(g_rg),ZR)
        #print("rg=>",rg)
        C_4=pk['g']**w_
        C_5=g_rg * (PKG['pkg']**w_)
        ctg = {'version':PKG['version'],'C_4':C_4,'C_5':C_5}
        "end group token creating"
        "proxy key for cloud"
        p_rk = rg_old / rg


        seed = group.random(GT)
        C_tilde = ((ct['C_tilde']/seed_old) ** (1/p_rk)) * seed
        ct['C_tilde']=C_tilde

        "Symmetric encryption and Generation of verification key VK"

        (CT_SE, VK) = generateVerificationTag(M, seed)

        ct_full['ct']=ct
        ct_full['ctg']=ctg
        ct_full['ct_se']=CT_SE
        ct_full['vk']=VK

        return (ct_full, p_rk)

    def updateCloud(self,pk, ct_full, p_rk):

        ct=ct_full['ct']

        ct['C']=ct['C']** p_rk

        C_y, C_y_pr = ct['Cy'], ct['Cyp']
        for i in C_y.keys():
            C_y[i] = C_y[i] ** p_rk
            C_y_pr[i] = C_y_pr[i] ** p_rk

        ct['Cy']=C_y
        ct['Cyp']=C_y_pr
        ct_full['ct']=ct
        return ct_full

    def initTree(self):
        isComplete =False

        h_tmp = log2(self.total_users)
        x = ceil(h_tmp)
        y = floor(h_tmp)

        if x == y:
            isComplete =True

        h =  int(x)

        if isComplete:
            self.initCompleteBinTree(h)
        else:
            self.initCompleteBinTree(h-1)
            splitNodeCount = self.total_users -  int(2 ** (h-1))

            for i in range(splitNodeCount):
                node=self.leafNodeList.pop(0)
                self.splitNode(node)
                self.leafNodeList.append(node.l_child)
                self.leafNodeList.append(node.r_child)




    def splitNode(self, node):
        node.l_child =  TGDHTreeNode((node.l+1),(2*node.k))
        node.r_child = TGDHTreeNode((node.l+1),(2*node.k+1))


        node.l_child.parent = node
        node.r_child.parent=node

        node.isLeaf = False
        node.l_child.isLeaf=True
        node.r_child.isLeaf=True




    def initCompleteBinTree(self, h):
        self.cur_root = TGDHTreeNode()
        self.buildCompleteBinTree(self.cur_root,h)
        self.cur_version = 0
        self.cur_root_list ={ 0:(0,self.cur_root) }


    def buildCompleteBinTree(self, node, h):

        if node.l < h:
            node.l_child = TGDHTreeNode((node.l+1), (2*node.k))
            node.l_child.parent = node
            self.buildCompleteBinTree(node.l_child, h)

            node.r_child =  TGDHTreeNode((node.l+1), (2*node.k+1))
            node.r_child.parent = node
            self.buildCompleteBinTree(node.r_child,h)

        elif node.l == h:
            node.isLeaf = True
            self.leafNodeList.append(node)



    def group_setup(self,pk):
        self.initializeUserIDs(pk)
        self.initTree()
        self.computeAllKeysRecursively(self.cur_root,pk['g'])
        self.assignLeavesToUsers()
        a = self.cur_root.BK

    def initializeUserIDs(self,pk):
        self.list_userID=[]
        #print('total users:',self.total_users)
        for i in range(self.total_users):
            self.list_userID.append(group.random(ZR))



    " Assume this function returns the secret key K"
    def computeAllKeysRecursively(self,p, g):

        if not p.isLeaf:
            ln = p.l_child
            rn= p.r_child
            #ln.BK = g ** self.convertToZR(ln, self.computeAllKeysRecursively(ln, g))
            #p.K = ln.BK ** self.convertToZR(rn,self.computeAllKeysRecursively(rn, g))
            #p.BK=g ** self.convertToZR(p,p.K)

            ln.BK = g ** self.computeAllKeysRecursively(ln, g)
            p.K = group.hash(str(ln.BK ** self.computeAllKeysRecursively(rn,g)),ZR)
            p.BK=g ** p.K

        if p.isLeaf:
            p.K = group.random(ZR)
        return p.K



    """
        def convertToZR(self, node, element):
        if not node.isLeaf:
            return group.hash(str(element),ZR)
        else:
            return element
    """



    def assignLeavesToUsers(self):
        self.list_user_leaf={}
        for id in self.list_userID:
            self.list_user_leaf[id]=self.leafNodeList.pop(0)

    def reKey(self):
        user_id = self.list_userID[-1]
        (root_BK, co_path_bk_list) = self.getCoPathBKList(user_id)
        leaf_k = self.list_user_leaf[user_id].K
        sk = self.computeRootK(leaf_k, co_path_bk_list)

        a = self.cur_root


    def getCoPathBKList(self, user_id):
        leaf_node = self.list_user_leaf[user_id]
        path = self.getPath(leaf_node.l,leaf_node.k)

        cur_node = self.cur_root
        rev_BK_list =[]
        for c in path:
            if c=='0':
                rev_BK_list.append(cur_node.r_child.BK)
                cur_node = cur_node.l_child
            else:
                rev_BK_list.append(cur_node.l_child.BK)
                cur_node = cur_node.r_child

        return (self.cur_root.BK, rev_BK_list[::-1])

    def computeRootK(self,leaf_k,list_bk):
        cur_sk = leaf_k
        for bk in list_bk:
            cur_sk =  group.hash(str(bk ** cur_sk),ZR)
        return cur_sk


    def getPath(self, l,k):

        str_k = bin(k)[2:]
        final_list = ('0' * (l - len(str_k))) + str_k
        return final_list







class TGDHTreeNode:
    r_child = None
    l_child = None
    parent = None
    l = 0
    k = 0
    BK = None
    K = None
    isLeaf = False

    def __init__(self, l=0, k=0):
        self.l=l
        self.k=k


