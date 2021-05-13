from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.math.pairing import hashPair as sha2
import hashlib
#from revo_abe_test import runReVO_ABE
#from hur_II_test import runHur_II
#import charm.schemes.hashlib
from sys import getsizeof


TRIALS=30
UNIVERSE_SIZE = 100
ATTRIBUTE_UNIVERSE = ['zero','ONE', 'TWO', 'THREE', 'FOUR', 'five','six', 'seven', 'eight']
ATTRIBUTES = [ATTRIBUTE_UNIVERSE[1],ATTRIBUTE_UNIVERSE[2], ATTRIBUTE_UNIVERSE[3],ATTRIBUTE_UNIVERSE[4]]
ACCESS_POLICY = '((one or two) and (three or four) and (two or five))'
MESSAGE="Hello World!! Life is good!!"
TOTAL_USERS=16

#curves=["SS512","SS1024","MNT159","MNT201","MNT224"]
curves=["SS512","MNT159","MNT201","MNT224"]
benchArray = ["CpuTime", "RealTime", "NativeTime", "Add", "Sub", "Mul", "Div", "Exp", "Pair", "Granular"]
encoding_utf='utf-8'
miliSecConversion=1000.0

def avgBenchmark(arr,trials):

    for key in benchArray:
        if key in arr:
            if key=="CpuTime" or key == "RealTime":
                arr[key] = arr[key]*miliSecConversion
            else:
                arr[key] = arr[key]

    return arr


def text2int(textnum, numwords={}):
    if not numwords:
      units = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
        "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
        "sixteen", "seventeen", "eighteen", "nineteen",
      ]

      tens = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]

      scales = ["hundred", "thousand", "million", "billion", "trillion"]

      numwords["and"] = (1, 0)
      for idx, word in enumerate(units):    numwords[word] = (1, idx)
      for idx, word in enumerate(tens):     numwords[word] = (1, idx * 10)
      for idx, word in enumerate(scales):   numwords[word] = (10 ** (idx * 3 or 2), 0)

    current = result = 0
    for word in textnum.split():
        word=word.lower()

        if word not in numwords:
          raise Exception("Illegal word: " + word)

        scale, increment = numwords[word]
        current = current * scale + increment
        if scale > 100:
            result += current
            current = 0

    return result + current


def bytesToString(byte_data):
    return byte_data.decode(encoding_utf)


def SHA224(str_message):
    return hashlib.sha224(str_message.encode(encoding_utf)).hexdigest()

def SHA256(str_message):
    return hashlib.sha256(str_message.encode(encoding_utf)).hexdigest()





def generateVerificationTag( msg, seed):

    # the output of sha2 is byte
    tag_0 = SHA256(str(seed))

    K_SE = sha2(seed)

    cipher = AuthenticatedCryptoAbstraction(K_SE)
    CT_SE = cipher.encrypt(msg)

    'CT_SE is a dictionary element that contains the ciphertext. Key value for the ciphertext is msg'
    msg_ct  = CT_SE['msg']

    "msg_ct is str type"
    cat_msg =  tag_0+msg_ct
    #print('catenated message=>',cat_msg)
    vk = SHA224(cat_msg)
    #print('SHA256 size  :', getsizeof(tag_0), tag_0)
    #print('F output size:', getsizeof(K_SE), K_SE)
    #print('VK size      :', getsizeof(vk), vk)
    return (CT_SE, vk)

def verifyVerificationTag(CT_SE, VK,seed):

    tag_0 = SHA256(str(seed))
    msg_ct =  CT_SE['msg']

    VK_prime= SHA224(tag_0+msg_ct)

    assert VK == VK_prime, "Failed outsourced verification!!"
    if (VK != VK_prime):
        return None

    else:
        K_SE = sha2(seed)
        cipher = AuthenticatedCryptoAbstraction(K_SE)
        msg = cipher.decrypt(CT_SE)
        return bytesToString(msg)






