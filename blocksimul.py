
# ////////////////////////////////////////////////////////////////////////
# import /////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////
import binascii
import time
import sys

import os
import array
import collections

import csv
import math

# ///////////////////////////////////////////////////////////////////////
# DEF ///////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////



# ///////////////////////////////////////////////////////////////////////

# ///////////////////////////////////////////////////////////////////////

def my_hexa_to_int(my_hexa):
    a = binascii.hexlify(bytearray(my_hexa))
    b = int(a, 16)
    return b

# ///////////////////////////////////////////////////////////////////////

def my_copy( a, b, c):
    for i in range(0, c, 1):
        a[i] = b[i]

# ///////////////////////////////////////////////////////////////////////

def my_copy_step( a, a_step, b, b_step, c):
    for i in range(0, c, 1):
        a[a_step+i] = b[b_step+i]

# ///////////////////////////////////////////////////////////////////////

def my_cut(a, b, c):
    cut = a[:(b+c)]
    cut2 = cut[b:]
    return cut2

# ///////////////////////////////////////////////////////////////////////

def my_comp( a, b, c):
    for i in range(0, c, 1):
        if a[i] != b[i]:
            return False

    return True

# ///////////////////////////////////////////////////////////////////////

def my_binar_to_bin(a):
    a_str = binascii.hexlify(bytearray(a))
    a_bin = binascii.unhexlify(bytearray(a_str))
    return a_bin

# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

def lv(bytestring):
    import re
    bytestr = ''.join(re.split('\W+', bytestring.upper()))
    length = int(len(bytestr) / 2)
    if (length > 0xFF):
        # length on 2 bytes
        return intToHexString(length, 2) + bytestr
    else:
        return intToHexString(length, 1) + bytestr

# /////////////////////////////////////////////////////////////////////

def lv_byte(bytearr):
    t_len = len(bytearr)
    t_buff = [0x00] * (t_len + 1)
    t_buff[0] = t_len
    my_copy_step(t_buff, 1, bytearr, 0, t_len)
    return t_buff

# /////////////////////////////////////////////////////////////////////

def getBytes(data, byteNumber, length=1):
    import re
    bytestr = ''.join(re.split('\W+', data.upper()))
    byteArray = toByteArray(bytestr)
    part = byteArray[byteNumber - 1:byteNumber - 1 + length]
    return toHexString(part)

# /////////////////////////////////////////////////////////////////////
def toByteArray(byteString):
    import re
    packedstring = ''.join(re.split('\W+', byteString.upper()))
    aArray = bytearray.fromhex(packedstring.upper())
    value = list(aArray)
    return value

# /////////////////////////////////////////////////////////////////////
def toHexString(byte_data=[]):
    value = ""
    for i in range(0, len(byte_data)):
        if (byte_data[i] < 0x00):
            return None
        value += ("%-0.2X" % byte_data[i])

    return value

# /////////////////////////////////////////////////////////////////////

def intToHexString(intValue, len=1):
    stringValue = hex(intValue).lstrip('0x')
    stringValue = stringValue.rjust(len * 2, '0')
    return stringValue.upper()


#================================ 

import struct
 
def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_from_compact(c):
    """Convert compact encoding to uint256
    Used for the nBits compact encoding of the target in the block header.
    """
    nbytes = (c >> 24) & 0xFF
    if nbytes <= 3:
        v = (c & 0xFFFFFF) >> 8 * (3 - nbytes)
    else:
        v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v

def compact_from_uint256(v):
    """Convert uint256 to compact encoding
    """
    nbytes = (v.bit_length() + 7) >> 3
    compact = 0
    if nbytes <= 3:
        compact = (v & 0xFFFFFF) << 8 * (3 - nbytes)
    else:
        compact = v >> 8 * (nbytes - 3)
        compact = compact & 0xFFFFFF

    # If the sign bit (0x00800000) is set, divide the mantissa by 256 and
    # increase the exponent to get an encoding without it set.
    if compact & 0x00800000:
        compact >>= 8
        nbytes += 1

    return compact | nbytes << 24

def uint256_to_str(u):
    r = b""
    for i in range(8):
        r += struct.pack('<I', u >> (i * 32) & 0xffffffff)
    return r

def uint256_to_shortstr(u):
    s = "%064x" % (u,)
    return s[:16]
    


def target_int2bits(target):
    # comprehensive explanation here: bitcoin.stackexchange.com/a/2926/2116
    # get in base 256 as a hex string
    target_hex = int2hex(target)

    bits = "00" if (hex2int(target_hex[: 2]) > 127) else ""
    bits += target_hex # append
    bits = hex2bin(bits)
    length = int2bin(len(bits), 1)

    # the bits value could be zero (0x00) so make sure it is at least 3 bytes
    bits += hex2bin("0000")

    # the bits value could be bigger than 3 bytes, so cut it down to size
    bits = bits[: 3]

    return length + bits


def bits2target_int(bits_bytes):
    exp = bin2int(bits_bytes[: 1]) # exponent is the first byte
    mult = bin2int(bits_bytes[1:]) # multiplier is all but the first byte
    return mult * (2 ** (8 * (exp - 3)))

def int2hex(intval):
    hex_str = hex(intval)[2:]
    if hex_str[-1] == "L":
        hex_str = hex_str[: -1]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return hex_str

def hex2int(hex_str):
    return int(hex_str, 16)

def hex2bin(hex_str):
    return binascii.a2b_hex(hex_str)

def int2bin(val, pad_length = False):
    hexval = int2hex(val)
    if pad_length: # specified in bytes
        hexval = hexval.zfill(2 * pad_length)
    return hex2bin(hexval)

def bin2hex(binary):
    # convert raw binary data to a hex string. also accepts ascii chars (0 - 255)
    return binascii.b2a_hex(binary)

# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

"""
import numpy as np
from scipy.stats import truncnorm
import matplotlib.pyplot as plt

def gettruncatedRandom(a, b):
    scale = 3.
    range = 10
    size = 100000
    X = truncnorm(a=-range/scale, b=+range/scale, scale=scale).rvs(size=size)
    X = X.round().astype(int)
"""    

from scipy.stats import truncnorm

def get_truncated_normal_Random(mean=0, sd=1, low=0, upp=10):
    return truncnorm(
        (low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)



import numpy as np
def getGaussianRandom(mean, sigma):
    return np.random.normal(mean, sigma, 1)
    
# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

class pydiff:
    powminimumbits = 22
    nTargetSpacing = 180
    targetadjustfreq = 86400
    nTargetSpacingShort = targetadjustfreq
    nTargetSpacingLong = targetadjustfreq
    genesisNbits = 0x1E03FFFF
    maximumTarget = 0x00000000FFFF0000000000000000000000000000000000000000000000000000  
    maximumDiff = 0x0000FFFF
    nCompactProofOfWorkLimit = 0   
    nProofOfWorkLimit = 0
    
    def init(self):
        full_uint256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        self.nProofOfWorkLimit = full_uint256 >> self.powminimumbits
        self.nCompactProofOfWorkLimit = compact_from_uint256(self.nProofOfWorkLimit)
        self.nTargetSpacingShort = self.targetadjustfreq / 4
        self.nTargetSpacingLong = self.targetadjustfreq * 4
    
        print("                   : " + "{0:0256b}".format(full_uint256))
        print("                   : " + "{0:0256b}".format(nProofOfWorkLimit))
        print("                   : " + hex(self.bnProofOfWorkLimit))
    
    #def GetBitsLimit(self):
        print("          " + "{0:064x}".format(self.maximumTarget))
        print("          " + "{0:0256b}".format(self.maximumTarget))

    def GetDifficulty(self, nBits = 0x00000000, bDisplay = 0):
        newBits = nBits & 0x00FFFFFF
        if newBits < 1:
            return 0

        nSize = (nBits >> 24) & 0xFF
        fmaximumDiff = float(self.maximumDiff)
        fnewBits = float(newBits)
        fdiff = fmaximumDiff / fnewBits
        
        if nSize < 29:
            dup = 29 - nSize
            newDiff = 256**dup
            fdiff *= newDiff
        elif nSize > 29:
            dup = nSize - 29
            newDiff = 256**dup
            fdiff /= newDiff
        
        #if bDisplay :
            print("Current Difficulty : " + "%.8f"%fdiff + " <> "+ "%d"%newBits)
            Print("        Difficulty : " + "%.8f"%fdiff + " <> "+ "%d"%newBits)
        
        return fdiff
    
    
    def GetNextWorkRequired(self, nBits = 0x00000000, tSpan = 86400):        
        
        print("Current nBits      : " + hex(nBits))
        print("Current nBits      : 0x" + "{0:08x}".format(nBits) + " <> "+ "%d"%nBits)
        print("Time Span          : " + "%d"%tSpan)
        currentCompact = uint256_from_compact(nBits)        
        #self.GetDifficulty(nBits, 1)                
        print("                     " + "{0:08x}".format(nBits))
        print("                     " + "{0:064x}".format(currentCompact))
        #print "                     " + "{0:0256b}".format(currentCompact)
        
        #print self.nTargetSpacingShort
        #print self.nTargetSpacingLong
        
        nTargetTimespan = tSpan
        
        if tSpan < self.nTargetSpacingShort:
            nTargetTimespan = self.nTargetSpacingShort
        
        if tSpan > self.nTargetSpacingLong:
            nTargetTimespan = self.nTargetSpacingLong
        
        nextCompact = currentCompact * nTargetTimespan / self.targetadjustfreq
        
        if self.nProofOfWorkLimit < nextCompact : 
            nextCompact = self.nProofOfWorkLimit
        
        #print "Next nBits String  : " + "{0:0256b}".format(nextCompact)
        
        nextBits = compact_from_uint256(nextCompact)
        #print "Next nBits         : " + hex(nextBits)
        #print "Next nBits         : 0x" + "{0:08x}".format(nextBits)
        #self.GetDifficulty(nextBits, 1)
        return nextBits

    def GetBlockProof(self, nBits = 0x00000000, preWork = 0x0000000000000000000000000000000000000000000000000000000000000000):
        currentCompact = uint256_from_compact(nBits)
        work = 2**256
        work -= currentCompact - 1
        work /= (currentCompact+1)
        work += 1
        work += preWork
        #print "{0:064x}".format(work)
        #print work
        return work
        
    def GetBlockProofTemp(self, nBits = 0x00000000):
        currentCompact = uint256_from_compact(nBits)
        work = 2**256
        work -= currentCompact - 1
        work /= (currentCompact+1)
        work += 1
        return work
                
# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

DEF_RAW_FNAME = "data.csv"
DEF_RAW_FNAME_TEST = "data_temp.csv"

DEF_RAW_INDEX_NAME_BINDEX = "BINDEX"
DEF_RAW_INDEX_NAME_BnTIME = "BnTIME"
DEF_RAW_INDEX_NAME_BnBITS = "BnBITS"
DEF_RAW_INDEX_NAME_BnNONCE = "BnNONCE"
DEF_RAW_INDEX_NAME_BCHAINWORK = "BCHAINWORK"
DEF_RAW_INDEX_NAME_BSADDR = "BSADDR"
DEF_RAW_INDEX_NAME_BCADDR = "BCADDR"
DEF_RAW_INDEX_NAME_BTXS = "BTXS"
DEF_RAW_INDEX_NAME_BSIZE = "BSIZE"

class rawItems:    
    bLoadOk = False
    itemsColInfo = []
    items = []
    numItems = 0
    numCol = 0
    colOffsetFrom = 0
    colOffsetTo = 0
    dataOffsetFrom = 0
    dataOffsetTo = 0
    rowOffsetFrom = 0
    rowOffsetTo = 0
    
    # ///////////////////////////////////////////////////////////////////////
    
    def init(self):
        self.bLoadOk = False
        
        if (len(self.itemsColInfo)) :
            self.itemsColInfo[:]=[]
            
        if (len(self.items)) :
            self.items[:]=[]
        
        self.numItems = 0
        self.numCol = 0
        
        self.colOffsetFrom = 0
        self.colOffsetTo = 0
        self.dataOffsetFrom = 0
        self.dataOffsetTo = 0    
        self.rowOffsetFrom = 0
        self.rowOffsetTo = 0
        
        self.db_init()
        
        return
    
    # ///////////////////////////////////////////////////////////////////////

    def db_init(self):
    
        colList=[]
        colList.append(DEF_RAW_INDEX_NAME_BINDEX)
        colList.append(DEF_RAW_INDEX_NAME_BnTIME)
        colList.append(DEF_RAW_INDEX_NAME_BnBITS)
        colList.append(DEF_RAW_INDEX_NAME_BnNONCE)
        colList.append(DEF_RAW_INDEX_NAME_BCHAINWORK)
        colList.append(DEF_RAW_INDEX_NAME_BSADDR)
        colList.append(DEF_RAW_INDEX_NAME_BCADDR)
        colList.append(DEF_RAW_INDEX_NAME_BTXS)
        colList.append(DEF_RAW_INDEX_NAME_BSIZE)
        colLen = len(colList)        
        
        for i in range(colLen):
            itemsInfo = [colList[i] ,i]
            self.itemsColInfo.append(itemsInfo)
        
        self.colOffsetTo = colLen-1
        self.numCol = colLen
        
        return
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getColIndex(self, name=""):
        if (name==""):
            return -1
        
        indexFounded = -1
        for i in range(self.numCol):
            if (self.itemsColInfo[i][0] == name):
                indexFounded = self.itemsColInfo[i][1]
        
        if (indexFounded < self.colOffsetFrom ):
            return -1
        elif(indexFounded > self.colOffsetTo  ):
            return -1
            
        return indexFounded
    
    # ///////////////////////////////////////////////////////////////////////
  
    def checkIndexRange(self, index):
        #print "rawItems : %s : %d : [%d-%d]" % ("checkIndexRange",index,self.rowOffsetFrom,self.rowOffsetTo)
        
        if (index < self.rowOffsetFrom):
            return False
        elif(index > self.rowOffsetTo):
            return False
        
        return True
            
    # ///////////////////////////////////////////////////////////////////////
    
    def read_csv(self, fname="", load=False):
        if(fname==""):
            return
        
        num  = 0
        with open(fname, 'r') as raw:
            wrapper = csv.reader(raw)
            for record in wrapper:
                if record:
                    items = []*self.numCol
                    #print(record)
                    items.append(int(record[0]))
                    items.append(int(record[1]))
                    items.append(int(record[2],16))
                    items.append(int(record[3]))
                    items.append(int(record[4]))
                    items.append(record[5])
                    items.append(record[6])
                    items.append(int(record[7]))
                    items.append(int(record[8]))
                    
                    num += 1
                    
                    if load :
                        self.items.append(items)
                        self.numItems = num
                        self.rowOffsetTo = self.numItems - 1
        
        
        return num
    
    # ///////////////////////////////////////////////////////////////////////
    
    def load(self, fname):
        if self.bLoadOk : 
            self.bLoadOk = False
        
        self.init()
        
        numItems = 0
        numItems = self.read_csv(fname, False)
        
        if (numItems < 1):
            return
        
        numItems = self.read_csv(fname, True)
        
        if (numItems!=self.numItems):
            self.init()
            return
        
        # check index
        abnormalItems = False
        tIndex = 0
        
        for i in range(self.numItems):
            tIndex = self.items[i][0] + 1
            if (tIndex<0):
                abnormalItems = True
                break;                    
            
            for j in range(i+1, self.numItems, 1):
                if (tIndex != self.items[j][0]):
                    abnormalItems = True
                    break;
        
        if not abnormalItems:
            self.init()
            return
        
        self.rowOffsetFrom = 0
        self.dataOffsetFrom = self.items[0][0]
        self.dataOffsetTo = self.items[self.rowOffsetTo][0]
        
        self.bLoadOk = True
        return


# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

DEF_STAT_TRACE_FNAME = "trace.csv"
DEF_STAT_GENERAL_FNAME = "stat.csv"
DEF_STAT_GENERAL_FNAME_TEST = "stat_temp.csv"

DEF_STAT_GENERAL_INDEX_NAME_DFINDEX = "DFINDEX"
DEF_STAT_GENERAL_INDEX_NAME_CNF = "CNF"
DEF_STAT_GENERAL_INDEX_NAME_SNF = "SNF"
DEF_STAT_GENERAL_INDEX_NAME_CWS = "CWS"
DEF_STAT_GENERAL_INDEX_NAME_SWS = "SWS"
DEF_STAT_GENERAL_INDEX_NAME_CCONT = "CCONT"
DEF_STAT_GENERAL_INDEX_NAME_SCONT = "SCONT"
DEF_STAT_GENERAL_INDEX_NAME_DIFF = "DIFF"
DEF_STAT_GENERAL_INDEX_NAME_mTIME = "mTIME"
DEF_STAT_GENERAL_INDEX_NAME_dChainW = "dChainW"
DEF_STAT_GENERAL_INDEX_NAME_TTxs = "TTxs"
DEF_STAT_GENERAL_INDEX_NAME_HPS = "HPS"
DEF_STAT_GENERAL_INDEX_NAME_HPS120B = "HPS120B"
DEF_STAT_GENERAL_INDEX_NAME_HPS480B = "HPS480B"

DEF_STAT_DIFF_INDEX_NAME_ELAPSED = "ELAPSED"
DEF_STAT_DIFF_INDEX_NAME_BTAVR = "BTAVR"
DEF_STAT_DIFF_INDEX_NAME_BR = "BR"
DEF_STAT_DIFF_INDEX_NAME_BRF = "BRF"
DEF_STAT_DIFF_INDEX_NAME_BO = "BO"
DEF_STAT_DIFF_INDEX_NAME_HPS = "HPS"

DEF_STAT_MINER960_INDEX_NAME_MINER960 = "MINER960"

DEF_STAT_MINER9600_INDEX_NAME_MINER9600 = "MINER9600"


DEF_nTargetSpacing = 180
DEF_targetadjustfreq = 86400
DEF_Interval = DEF_targetadjustfreq / DEF_nTargetSpacing
DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW = 1752000
DEF_BLOCKWINDOW_NODE_FACTOR_RATE = 0.7  
DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW = 700
DEF_BO_MAX = 60*60
DEF_GMT_KOR = 9
DEF_GMT_DATE_OFFSET = 25569 #1970,1,1
DEF_MINER_MORN_PCT = 0.05
    
class statHdac:    
    bLoadOk = False
    dataRaw = rawItems()
    
    itemsColInfo = []
    items = []
    
    diffItemsColInfo = []
    diffItems = []
    diffPer = []
    
    MINER960Items = []    
    MINER9600Items = []
    MINERMORN = []    
    
    numItems = 0
    numCol = 0
    colOffsetFrom = 0
    colOffsetTo = 0
    rowOffsetFrom = 0
    rowOffsetTo = 0
    
    # ///////////////////////////////////////////////////////////////////////
    
    def init(self):
        #print "statHdac : %s" % ("init")
        
        self.bLoadOk = False
        
        self.dataRaw.init()
            
        if (len(self.itemsColInfo)) :
            self.itemsColInfo[:]=[]
            
        if (len(self.diffItemsColInfo)) :
            self.diffItemsColInfo[:]=[]
        
        if (len(self.diffItems)) :
            self.diffItems[:]=[]
        
        if (len(self.diffPer)) :
            self.diffPer[:]=[]
            
        if (len(self.MINER960Items)) :
            self.MINER960Items[:]=[]
        
        if (len(self.MINER9600Items)) :
            self.MINER9600Items[:]=[]
            
        self.numItems = 0 
        self.numCol = 0
        self.colOffsetFrom = 0
        self.colOffsetTo = 0
        self.rowOffsetFrom = 0
        self.rowOffsetTo = 0
        
        self.db_init()
        
        return
    
    # ///////////////////////////////////////////////////////////////////////

    def db_init(self):
        #print "statHdac : %s" % ("db_init")
        
        colList=[]
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_DFINDEX)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_CNF)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_SNF)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_CWS)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_SWS)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_CCONT)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_SCONT)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_DIFF)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_mTIME)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_dChainW)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_TTxs)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS120B)
        colList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS480B)
        colLen = len(colList)
        
        for i in range(0, colLen, 1):
            itemsInfo = [colList[i] ,i]
            self.itemsColInfo.append(itemsInfo)            
        
        self.colOffsetTo = colLen-1
        self.numCol = colLen
        
        return
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getColIndex(self, name=""):
        #print "statHdac : %s" % ("getColIndex")
        if (name==""):
            return -1
        
        indexFounded = -1
        for i in range(self.numCol):
            if (self.itemsColInfo[i][0] == name):
                indexFounded = self.itemsColInfo[i][1]
        
        if (indexFounded < self.colOffsetFrom):
            return -1
        elif(indexFounded > self.colOffsetTo):
            return -1
        
        return indexFounded
             
    # ///////////////////////////////////////////////////////////////////////
  
    def checkIndexRange(self, index):
        #print "statHdac : %s : %d : %d ~ %d" % ("checkIndexRange",index,self.rowOffsetFrom,self.rowOffsetTo)
        
        if (index < self.rowOffsetFrom):
            return False
        elif(index > self.rowOffsetTo):
            return False
        
        return True
        
    # ///////////////////////////////////////////////////////////////////////
    
    def load(self, fname):
        #print "statHdac : load : %d" % (self.bLoadOk)
        
        if self.bLoadOk : 
            self.bLoadOk = False
        
        self.init()        
        
        self.dataRaw.load(fname)
        
        if self.dataRaw.bLoadOk:
            """
            tItems = []
            for i in range(self.numCol):
                tItems.append(0.)
            
            for i in range(self.dataRaw.numItems):
                self.items.append(tItems)
            
            num = len(self.items)
            if (num != self.dataRaw.numItems):
                return
                
            self.numItems = self.dataRaw.numItems
            self.rowOffsetFrom = 0
            self.rowOffsetTo = self.numItems - 1
            """
            
            self.bLoadOk = True

    # ///////////////////////////////////////////////////////////////////////
    def TraceToFile(self, info=""):
        fp = open(DEF_STAT_TRACE_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()
            
    # ///////////////////////////////////////////////////////////////////////
    
    def getNF(self, startI, depth=1, nfIString=""):
        #print "statHdac : %s : %d-%d" % ("getNF", startI, depth)
        
        if not self.bLoadOk : 
            return []
        
        if not self.dataRaw.checkIndexRange(startI):
            return []
            
        tIndex = 0
        tIndex = startI - depth + 1
        
        if not self.dataRaw.checkIndexRange(tIndex):
            return []
        
        if (nfIString==""):
            return []
        
        
        indexFrom = self.dataRaw.getColIndex(nfIString)
        if (indexFrom < 0):
            return []
        
        tList = []
        tNum = 0
        tNF = ""
        bStatus = True
        for i in range(depth):
            tNF = self.dataRaw.items[startI-i][indexFrom]
            tNum = len(tList)
            bStatus = True
            if (tNum > 0):
                for j in range(tNum):
                    if (tList[j] == tNF) : 
                        bStatus = False
            if bStatus:
                tList.append(tNF)        
          
        return tList
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getWS(self, bheight, nf=1):
        #print "statHdac : %s : %d : %d" % ("StatNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1.
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
        if (bheight < 1):
            return -1.

        tVal = 0.
        tValNew = 0.
        if (bheight > DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW):
            tVal = nf * DEF_BLOCKWINDOW_NODE_FACTOR_RATE
        else :
            tVal = bheight * nf * DEF_BLOCKWINDOW_NODE_FACTOR_RATE / DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW
        
        if (tVal > nf) :
            tVal = nf -1
        
        tValNew = float(tVal)  
        
        return tValNew
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getMAX(self, itemList=[]):
        tVal = len(itemList)
        if (tVal<1):
            return -1
        
        tMax = itemList[0]
        for i in range(1, tVal, 1):
            if (tMax < itemList[i]):
                tMax = itemList[i]
        
        return tMax
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getMIN(self, itemList=[]):
        tVal = len(itemList)
        if (tVal<1):
            return -1
        
        tMin = itemList[0]
        for i in range(1, tVal, 1):
            if (tMin > itemList[i]):
                tMin = itemList[i]
        
        return tMin
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getAVR(self, itemList=[]):
        tVal = len(itemList)
        if (tVal<1):
            return -1
        
        tAvr = itemList[0]
        for i in range(1, tVal, 1):
            tAvr += itemList[i]
        
        tAvr /= tVal
        
        return tAvr 

    # ///////////////////////////////////////////////////////////////////////
    
    def getTIME(self, time, refTime):
        newRefTime = refTime*3600
        timeToDate  = 60*60*24
        updatedTime = (time+newRefTime)/float(timeToDate)
        updatedTime += DEF_GMT_DATE_OFFSET
        return updatedTime
        
    # ///////////////////////////////////////////////////////////////////////
    
    # ///////////////////////////////////////////////////////////////////////
    # ///////////////////////////////////////////////////////////////////////
    
    # ///////////////////////////////////////////////////////////////////////
    
    def StatDFINDEX(self, indexRow):
        #print "statHdac : %s : %d" % ("StatDFINDEX", self.bLoadOk)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
            
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
        if (indexFrom < 0):
            return -1

        tVal = int(self.dataRaw.items[indexRow][indexFrom] / DEF_Interval)
        
        return tVal
        
    # ///////////////////////////////////////////////////////////////////////
    
    def StatCNF(self, indexRow):
        #print "statHdac : %s : %d : %d" % ("StatCNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1 
        
        #print "indexFrom = %d, indexTo = %d" % (indexFrom, indexTo)

        tList = []
        tList = self.getNF(indexRow,int(DEF_Interval), DEF_RAW_INDEX_NAME_BCADDR)
        tVal = len(tList)  
        
        return tVal
    
    # ///////////////////////////////////////////////////////////////////////

    def StatSNF(self, indexRow):
        #print "statHdac : %s : %d : %d" % ("StatCNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1 
        
        #print "indexFrom = %d, indexTo = %d" % (indexFrom, indexTo)

        tList = []
        tList = self.getNF(indexRow,int(DEF_Interval), DEF_RAW_INDEX_NAME_BSADDR)
        tVal = len(tList)  
        
        return tVal     

    # ///////////////////////////////////////////////////////////////////////
    
    def StatWS(self, indexRow, nf=1):
        #print "statHdac : %s : %d : %d" % ("StatNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1.
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1.
            
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
        if (indexFrom < 0):
            return -1.

        tVal = self.getWS(self.dataRaw.items[indexRow][indexFrom], nf)         
        return tVal

    # ///////////////////////////////////////////////////////////////////////
    
    def StatCCONT(self, indexRow, depth=0):
        #print "statHdac : %s : %d : %d" % ("StatNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
                    
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCADDR)
        if (indexFrom < 0):
            return -1

        indexTarget = indexRow - depth + 1
        if (indexTarget < 0):
            indexTarget = 0
            depth = indexRow - indexTarget
        
        if (indexRow == indexTarget) :
            return 1
        
        tMiner = self.dataRaw.items[indexRow][indexFrom]
        
        tVal = 1
        for i in range(indexRow, indexTarget-1, -1):
            if (tMiner == self.dataRaw.items[i][indexFrom]):
                tVal += 1
            else : 
                break 
        
        return tVal

    # ///////////////////////////////////////////////////////////////////////
    
    def StatSCONT(self, indexRow, depth=0):
        #print "statHdac : %s : %d : %d" % ("StatNF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
                    
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BSADDR)
        if (indexFrom < 0):
            return -1

        indexTarget = indexRow - depth + 1
        if (indexTarget < 0):
            indexTarget = 0
            depth = indexRow - indexTarget
        
        if (indexRow == indexTarget) :
            return 1
        
        tMiner = self.dataRaw.items[indexRow][indexFrom]
        
        tVal = 1
        for i in range(indexRow, indexTarget-1, -1):
            if (tMiner == self.dataRaw.items[i][indexFrom]):
                tVal += 1
            else : 
                break 
        
        return tVal

    # ///////////////////////////////////////////////////////////////////////
    
    def StatDIFF(self, indexRow):
        #print "statHdac : %s : %d : %d" % ("StatDIFF", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1.
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1.
            
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnBITS)
        if (indexFrom < 0):
            return -1.
        
        tVal = self.dataRaw.items[indexRow][indexFrom]
        diffMod = pydiff()
        tValDiff = diffMod.GetDifficulty(tVal, 0)
        
        #print "%s:%f" % (tVal, tValDiff)
        
        tValNew = float(tValDiff)  
        
        return tValNew

    # ///////////////////////////////////////////////////////////////////////
    
    def StatmTIME(self, indexRow, depth=1):
        #print "statHdac : %s : %d : %d" % ("StatmTIME", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
        
        if (depth < 1):
            return -1
        
        if (indexRow<1):
            return -1
        
        indexTarget = indexRow - depth
        if not self.dataRaw.checkIndexRange(indexTarget):
            return -1
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnTIME)
        if (indexFrom < 0):
            return -1
        
        if (depth==1):
            tVal = self.dataRaw.items[indexRow][indexFrom] - self.dataRaw.items[indexRow-1][indexFrom]
            if(tVal <= 0):
                if(indexRow<2):
                    return 0
                if(indexRow==self.rowOffsetTo):
                    return 0
            
                tList=[]
                tList.append(self.dataRaw.items[indexRow-1][indexFrom])
                tList.append(self.dataRaw.items[indexRow][indexFrom])
                tList.append(self.dataRaw.items[indexRow+1][indexFrom])
                tMax = self.getMAX(tList)
                tMin = self.getMIN(tList)
                if (tMax<=tMin):
                    return 0
                tVal = (tMax-tMin)/2
        else:
            tList = []
            for i in range(depth+1):
                tVal = self.dataRaw.items[indexRow-i][indexFrom]
                tList.append(tVal) 
        
            tMax = self.getMAX(tList)
            tMin = self.getMIN(tList)
            if (tMax<=tMin):
                return 0
            tVal = tMax-tMin
        
        tValNew = int(tVal)  
        
        return tValNew

    # ///////////////////////////////////////////////////////////////////////
    
    def StatdChainW(self, indexRow):
        #print "statHdac : %s : %d : %d" % ("StatmTIME", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCHAINWORK)
        if (indexFrom < 0):
            return -1
        
        if(indexRow<1):
            return -1
            
        tVal = self.dataRaw.items[indexRow][indexFrom] - self.dataRaw.items[indexRow-1][indexFrom] 
        
        return tVal
        
    # ///////////////////////////////////////////////////////////////////////
    
    def StatTTxs(self, indexRow):
        #print "statHdac : %s : %d : %d" % ("StatTTxs", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
            
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BTXS)
        if (indexFrom < 0):
            return -1
        
        indexTo = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_TTxs)
        if (indexTo < 0):
            return -1
        
        if (indexRow==0):
            tVal = self.dataRaw.items[indexRow][indexFrom]
            return tVal
        
        tVal = self.items[indexRow-1][indexTo] + self.dataRaw.items[indexRow][indexFrom]
        
        return tVal


    # ///////////////////////////////////////////////////////////////////////
    
    def StatHPS(self, indexRow, depth=1):
        #print "statHdac : %s : %d : %d" % ("StatHPS", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return -1
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return -1
        
        if (depth < 1):
            return -1
        
        indexFromNew = indexRow - depth
        if not self.dataRaw.checkIndexRange(indexFromNew):
            return -1
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCHAINWORK)
        if (indexFrom < 0):
            return -1
        
        if (indexRow == indexFromNew) :
            return 0
        
        tTime = self.StatmTIME(indexRow, depth)
        if (tTime <= 0):
            return -1
        
        tWork = self.dataRaw.items[indexRow][indexFrom] - self.dataRaw.items[indexFromNew][indexFrom]
        if (tTime <= 0):
            return -1
        
        tVal = tWork  / tTime
        
        tValNew = int(tVal)  
        
        return tValNew

    # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsGeneral(self, bOut=False):
        if not self.bLoadOk : 
            return False
        
        if bOut:
            self.TraceToFile("General")
            
            # raw
            """            
            tTitle = self.dataRaw.itemsColInfo[0][0]
            tStep = len(self.dataRaw.itemsColInfo)
            for i in range(1,tStep,1):
                tTitleStep = ",%s" % (self.dataRaw.itemsColInfo[i][0])
                tTitle += tTitleStep  
            """
            
            #stat
            tTitle = self.itemsColInfo[0][0]
            tStep = len(self.itemsColInfo)
            for i in range(tStep):
                tTitleStep = ",%s" % (self.itemsColInfo[i][0])
                tTitle += tTitleStep        
        
            self.TraceToFile(tTitle)
        
        for i in range(self.dataRaw.numItems):
            tTitle = ""
            
            #stat            
            listStat = []
            diffIndex = self.StatDFINDEX(i)
            listStat.append(diffIndex)
            tTitletStep = "%d" % (diffIndex)
            tTitle = tTitletStep
            
            Cnf = self.StatCNF(i)
            listStat.append(Cnf)
            tTitletStep = ",%d" % (Cnf)
            tTitle += tTitletStep
            
            Snf = self.StatSNF(i)
            listStat.append(Snf)
            tTitletStep = ",%d" % (Snf)
            tTitle += tTitletStep
            
            Cws = self.StatWS(i,Cnf)
            listStat.append(Cws)
            tTitletStep = ",%.3f" % (Cws)
            tTitle += tTitletStep
            
            Sws = self.StatWS(i,Snf)
            listStat.append(Sws)
            tTitletStep = ",%.3f" % (Sws)
            tTitle += tTitletStep
            
            Ccont = self.StatCCONT(i, DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW)
            listStat.append(Ccont)
            tTitletStep = ",%d" % (Ccont)
            tTitle += tTitletStep
            
            Scont = self.StatSCONT(i, DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW)
            listStat.append(Scont)
            tTitletStep = ",%d" % (Scont)
            tTitle += tTitletStep
            
            diff = self.StatDIFF(i)
            listStat.append(diff)
            tTitletStep = ",%.1f" % (diff)
            tTitle += tTitletStep
            
            mtime = self.StatmTIME(i,1)
            listStat.append(mtime)
            tTitletStep = ",%d" % (mtime)
            tTitle += tTitletStep
            
            dChainw = self.StatdChainW(i)
            listStat.append(dChainw)
            tTitletStep = ",%d" % (dChainw)
            tTitle += tTitletStep
            
            TTxs = self.StatTTxs(i)
            listStat.append(TTxs)
            tTitletStep = ",%d" % (TTxs)
            tTitle += tTitletStep
            
            hps = self.StatHPS(i,1)
            listStat.append(hps)
            tTitletStep = ",%d" % (hps)
            tTitle += tTitletStep
            
            hps120 = self.StatHPS(i,int(DEF_Interval/4))
            listStat.append(hps120)
            tTitletStep = ",%d" % (hps120)
            tTitle += tTitletStep
            
            hps480 = self.StatHPS(i,int(DEF_Interval))
            listStat.append(hps480)
            tTitletStep = ",%d" % (hps480)
            tTitle += tTitletStep
            
            self.items.append(listStat)
            
            if bOut:
                self.TraceToFile(tTitle)
            
            self.numItems += 1
            self.rowOffsetFrom = 0
            self.rowOffsetTo = self.numItems - 1
            
        return True

   # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsSamples(self, numItems=100, bOut=False):
        if not self.bLoadOk : 
            return False
        
        if (numItems < 1):
            return False
        
        if (numItems>=self.dataRaw.numItems):
            return False
        
        #numItems -= 1
                
        if bOut:
            self.TraceToFile("\n\nSamples")
            
            tList = []
            tList.append(DEF_RAW_INDEX_NAME_BINDEX)
            tList.append("LocalTime")
            tList.append(DEF_RAW_INDEX_NAME_BnTIME)
            tList.append(DEF_STAT_GENERAL_INDEX_NAME_TTxs)
            tList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS)
            tList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS120B)
            tList.append(DEF_STAT_GENERAL_INDEX_NAME_HPS480B)
        
            tTitle = tList[0]
            tStep = len(tList)
            for i in range(1,tStep,1):
                tTitleStep = ",%s" % (tList[i])
                tTitle += tTitleStep        
        
            self.TraceToFile(tTitle)
            
        nStep = int(self.dataRaw.numItems / numItems)
        nStart = self.dataRaw.numItems % numItems
        
        bStatus = True
                
        for i in range(nStart-1, self.dataRaw.numItems, nStep):
            tTitle = ""
            
            indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
            if (indexFrom < 0):
                bStatus = False
                break                
            bindex = self.dataRaw.items[i][indexFrom]
            tTitletStep = "%d" % (bindex)
            tTitle = tTitletStep
            
            indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnTIME)
            if (indexFrom < 0):
                bStatus = False
                break                
            nTime = self.dataRaw.items[i][indexFrom]            
            nNewTime = self.getTIME(nTime,DEF_GMT_KOR)
            tTitletStep = ",%lf,%d" % (nNewTime,nTime)
            tTitle += tTitletStep
            
            indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_TTxs)
            if (indexFrom < 0):
                bStatus = False
                break                
            TTxs = self.items[i][indexFrom]
            tTitletStep = ",%d" % (TTxs)
            tTitle += tTitletStep
            
            indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_HPS)
            if (indexFrom < 0):
                bStatus = False
                break                
            hps = self.items[i][indexFrom]
            tTitletStep = ",%d" % (hps)
            tTitle += tTitletStep
            
            indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_HPS120B)
            if (indexFrom < 0):
                bStatus = False
                break                
            hps120 = self.items[i][indexFrom]
            tTitletStep = ",%d" % (hps120)
            tTitle += tTitletStep
            
            indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_HPS480B)
            if (indexFrom < 0):
                bStatus = False
                break                
            hps480 = self.items[i][indexFrom]
            tTitletStep = ",%d" % (hps480)
            tTitle += tTitletStep
            
            if bOut:
                self.TraceToFile(tTitle)
            
        return


# ///////////////////////////////////////////////////////////////////////
    # tTitle = ["IDIFF","BINDEX","LOCALTIME","DIFF",DEF_STAT_DIFF_INDEX_NAME_ELAPSED,DEF_STAT_DIFF_INDEX_NAME_BTAVR,DEF_STAT_DIFF_INDEX_NAME_BR,DEF_STAT_DIFF_INDEX_NAME_BRF,DEF_STAT_DIFF_INDEX_NAME_BO,DEF_STAT_DIFF_INDEX_NAME_HPS]
    def getDIFFPSTAT(self, indexRow, diffInterval):
        #print "statHdac : %s : %d : %d" % ("getDIFFPSTAT", self.bLoadOk, indexRow)
        
        if not self.bLoadOk : 
            return []
        
        if not self.dataRaw.checkIndexRange(indexRow):
            return []
        
        if not self.dataRaw.checkIndexRange(indexRow+diffInterval-1):
            return []        
        
        if(diffInterval<=5):
            return []        
        
        listDiffStat = []
        
        indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_DFINDEX)
        if (indexFrom < 0):
            return []            
        dfindex = self.items[indexRow][indexFrom]
        if(dfindex!=self.items[indexRow+diffInterval-1][indexFrom]):
            return []
        
        tTitletStep = "%d" % (dfindex)
        listDiffStat.append(tTitletStep)            
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
        if (indexFrom < 0):
            return []  
        bindex = self.dataRaw.items[indexRow][indexFrom]
        tTitletStep = "%d" % (bindex)
        listDiffStat.append(tTitletStep) 
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnTIME)
        if (indexFrom < 0):
            return []                
        nTime = self.dataRaw.items[indexRow][indexFrom]            
        nNewTime = self.getTIME(nTime,DEF_GMT_KOR)
        tTitletStep = "%f" % (nNewTime)
        listDiffStat.append(tTitletStep)
        
        indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_DIFF)
        if (indexFrom < 0):
            return []  
        diff = self.items[indexRow][indexFrom]        
        tTitletStep = "%.1f" % (diff)
        listDiffStat.append(tTitletStep)
            
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnTIME)
        if (indexFrom < 0):
            return []
        elased = self.dataRaw.items[indexRow+diffInterval-1][indexFrom] - self.dataRaw.items[indexRow-1][indexFrom]
        tTitletStep = "%d" % (elased)
        listDiffStat.append(tTitletStep)
        
        tTitletStep = "%d" % (diffInterval)
        listDiffStat.append(tTitletStep)
        
        btavr = elased / float(diffInterval)
        tTitletStep = "%.1f" % (btavr)
        listDiffStat.append(tTitletStep)
        
        br = DEF_nTargetSpacing / float(btavr)
        tTitletStep = "%.3f" % (br)
        listDiffStat.append(tTitletStep)
        
        brf = br
        if(brf>4):
            brf = 4
        elif(brf<0.25):
            brf = 0.25
        tTitletStep = "%.3f" % (brf)
        listDiffStat.append(tTitletStep)
        
        bo = 0
        indexFrom = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_mTIME)
        if (indexFrom < 0):
            return []
            
        for i in range(diffInterval):            
            if(DEF_BO_MAX<self.items[indexRow+i][indexFrom]):
                bo += 1
        
        tTitletStep = "%d" % (bo)
        listDiffStat.append(tTitletStep)
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCHAINWORK)
        if (indexFrom < 0):
            return []
        
        hps = self.dataRaw.items[indexRow+diffInterval-1][indexFrom] - self.dataRaw.items[indexRow-1][indexFrom]
        hps /= float(elased)
        tTitletStep = "%d" % (int(hps))
        listDiffStat.append(tTitletStep)  
        
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BnBITS)
        BnBITS = self.dataRaw.items[indexRow][indexFrom]
        tempDiff = pydiff()
        diffCW = tempDiff.GetBlockProofTemp(BnBITS)
        tTitletStep = "%d" % (diffCW)
        listDiffStat.append(tTitletStep)  
        
        
        return listDiffStat
        
   # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsDiff(self, bOut=False):
        if not self.bLoadOk : 
            return False

        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
        if (indexFrom < 0):
            return False
        
        indexFrom2 = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_DFINDEX)
        if (indexFrom2 < 0):
            return False
        
        
        lastestPerCount = self.dataRaw.dataOffsetTo % DEF_Interval + 1
        lastestperStartOffset = self.dataRaw.rowOffsetTo - lastestPerCount + 1
        
        firstPerBIndex = int(self.dataRaw.dataOffsetFrom / DEF_Interval)
        firstPerBIndex += 1
        firstPerBIndex *= DEF_Interval
        
        remainTopCount = firstPerBIndex - self.dataRaw.dataOffsetFrom
        newDiffOffsetStart = self.dataRaw.rowOffsetFrom + remainTopCount
        
        newBIndex = self.dataRaw.items[newDiffOffsetStart][indexFrom]
        lenPer = (self.dataRaw.dataOffsetTo - newBIndex) / DEF_Interval
        
        for i in range(lenPer):
            tList = []
            tOffset = newDiffOffsetStart + i*DEF_Interval
            tList.append(tOffset)
            tList.append(tOffset + DEF_Interval-1)
            tList.append(DEF_Interval)
            self.diffPer.append(tList)
        
        if(lastestPerCount>0):
            tList = []
            tOffset = newDiffOffsetStart + lenPer*DEF_Interval
            tList.append(tOffset)
            tList.append(tOffset + lastestPerCount-1)
            tList.append(lastestPerCount)
            self.diffPer.append(tList)
        
        lenPer = len(self.diffPer)
        
        # ///////////////////////////////////////////////////////////////////////
        
        if bOut:
            self.TraceToFile("\n\nDiff")            
            tList = ["IDIFF","BINDEX","LOCALTIME","DIFF",DEF_STAT_DIFF_INDEX_NAME_ELAPSED,"ELAPSEDBI",DEF_STAT_DIFF_INDEX_NAME_BTAVR,DEF_STAT_DIFF_INDEX_NAME_BR,DEF_STAT_DIFF_INDEX_NAME_BRF,DEF_STAT_DIFF_INDEX_NAME_BO,DEF_STAT_DIFF_INDEX_NAME_HPS,"RChWk"]
            tTitle = ""
            for i in range(len(tList)):
                if (i==0):
                    tTitletStep = "%s" % (tList[i])
                else:
                    tTitletStep = ",%s" % (tList[i])
                tTitle += tTitletStep
            
            self.TraceToFile(tTitle)
        
        for i in range(lenPer):
            listDiffStat = []
            listDiffStat = self.getDIFFPSTAT(self.diffPer[i][0],self.diffPer[i][2])
            numlistDiffStat = len(listDiffStat)
            if (numlistDiffStat<1):
                return []
            
            tTitle = ""
            for j in range(numlistDiffStat):
                tTitletStep = ""
                if (j==0):
                    tTitletStep = "%s" % (listDiffStat[j])
                else:
                    tTitletStep = ",%s" % (listDiffStat[j])
                tTitle += tTitletStep
            
            if bOut:
                self.TraceToFile(tTitle)

        return True


   # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsMiner(self, bOut=False):
        if not self.bLoadOk : 
            return False
        
        if bOut:
            self.TraceToFile("\n\n")
            self.TraceToFile(DEF_STAT_MINER960_INDEX_NAME_MINER960)
        
        self.MINER960Items = self.getNF(self.rowOffsetTo,int(DEF_Interval)*2, DEF_RAW_INDEX_NAME_BCADDR)
        tNum = len(self.MINER960Items)
        if (tNum<1):
            self.MINER960Items[:] = []
            return False
                
        for i in range(tNum):
            tTitle = ""
            tTitle = "%s" % (self.MINER960Items[i])
            if bOut:
                self.TraceToFile(tTitle)        
        
        
        if bOut:
            self.TraceToFile("\n\n")
            self.TraceToFile(DEF_STAT_MINER9600_INDEX_NAME_MINER9600)
        
        #self.MINER9600Items = self.getNF(self.rowOffsetTo,int(DEF_Interval)*2*10, DEF_RAW_INDEX_NAME_BCADDR)
        self.MINER9600Items = self.getNF(self.rowOffsetTo,int(DEF_Interval)*5, DEF_RAW_INDEX_NAME_BCADDR)
        tNum = len(self.MINER9600Items)
        if (tNum<1):
            self.MINER9600Items[:] = []
            return False
                
        for i in range(tNum):
            tTitle = ""
            tTitle = "%s" % (self.MINER9600Items[i])
            if bOut:
                self.TraceToFile(tTitle)        
                        
        return True

    # ///////////////////////////////////////////////////////////////////////

    def getMinerCount(self, miner, indexRowStart, count):
        if not self.bLoadOk : 
            return 0

        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCADDR)
        if (indexFrom < 0):
            return 0
        
        if not self.dataRaw.checkIndexRange(indexRowStart):
            return 0
        
        if not self.dataRaw.checkIndexRange(indexRowStart+count-1):
            return 0
        
        if (miner==""):
            return 0

        countMiner = 0
        for i in range(indexRowStart,indexRowStart+count,1):
            if(self.dataRaw.items[i][indexFrom]==miner):
                countMiner += 1
        
        return countMiner

    # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsMinerStat(self, type=0, bOut=False):
        if not self.bLoadOk : 
            return False
        
        tNumMiner = len(self.MINER960Items)
        refPer = 1
            
        if (type==1):
            tNumMiner = len(self.MINER9600Items)
            refPer = 10
            if bOut:
                self.TraceToFile("\n\nMINERSTAT4800")
        else:
            tNumMiner = len(self.MINER960Items)
            refPer = 1
            if bOut:
                self.TraceToFile("\n\nMINERSTAT480")
        
        if (tNumMiner<1):
            return False
        
        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCADDR)
        if (indexFrom < 0):
            return False
        
        numPer = len(self.diffPer)
        if (numPer<1):
            return False
        
        if(refPer<numPer):
            refPer = numPer
        
        if bOut : 
            tTitle = "MINER"
            refCnt = 0
            for i in range(numPer):
                tTitletStep = ""
                tTitletStep = ",P%d," % (i)
                tTitle += tTitletStep
                    
            tTitle += ",P%d," % (refPer)
            self.TraceToFile(tTitle) 
            
            tTitle = "MINER"
            refCnt = 0
            for i in range(numPer):
                tTitletStep = ""
                tTitletStep = ",%d,1.00" % (self.diffPer[numPer-i-1][2])
                tTitle += tTitletStep
                if(i<refPer):
                    refCnt += self.diffPer[numPer-i-1][2]
                    
            tTitle += ",%d,1.00" % (refCnt)
            self.TraceToFile(tTitle) 
        
        
        for i in range(tNumMiner):
            tTitle = ""
            checkMiner = ""
            if (type==1):
                checkMiner = self.MINER9600Items[i]
            else:
                checkMiner = self.MINER960Items[i]
 
            tTitle += checkMiner
            refNum = 0
            refCnt = 0
            for j in range(numPer):
                tTitletStep = ""
                numMined = self.getMinerCount(checkMiner,self.diffPer[numPer-j-1][0],self.diffPer[numPer-j-1][2])
                numPct = 0
                if(j<refPer):
                    refNum += numMined
                    refCnt += self.diffPer[numPer-j-1][2]
                if(self.diffPer[numPer-j-1][2] > 0):
                    numPct = numMined / float(self.diffPer[numPer-j-1][2])
                    
                tTitletStep = ",%d,%.2f" % (numMined,numPct)
                tTitle += tTitletStep
            
            refPct = 0.
            if(refCnt>0):
                refPct = refNum / float(refCnt)
            
            tTitle += ",%d,%.2f" % (refNum,refPct)
            
            if(type==1) and (refPct>=DEF_MINER_MORN_PCT):
                tListMorn = []
                tListMorn.append(checkMiner)
                tListMorn.append(refNum)
                self.MINERMORN.append(tListMorn)
            
            if bOut : 
                self.TraceToFile(tTitle)             
                        
        return True

    # ///////////////////////////////////////////////////////////////////////
    
    def getStatWList(self, list=[], avr=0., stv=0.):
        lenList = len(list)
        if(lenList<1):
            return False
        steph5 = stv / 100.
        listStep = [10,20,30,40,50,60,70,80,90,100]
        listStvMax = []
        listStvMin = []
        listCnt = []
        lenlistStep = len(listStep)
        
        for i in range(lenlistStep):
            tMax = avr + steph5 * listStep[i]
            tMin = avr - steph5 * listStep[i]
            listStvMax.append(tMax)
            listStvMin.append(tMin)
        
        #print "getStatWList"
        #print avr
        #print stv
        #print steph5
        #print listStvMax
        #print listStvMin
        
        for i in range(lenlistStep):
            tCnt = 0
            for j in range(lenList):
                tInfo = list[j]        
                if ((tInfo <= listStvMax[i]) and (tInfo >= listStvMin[i])):
                    tCnt += 1
            listCnt.append(tCnt)
        
        tTitle = "\ngetStatWList : avr=%f and stv=%f" % (avr,stv)
        self.TraceToFile(tTitle) 
        
        tTitle = ""
        for i in range(lenlistStep):
            tTitle += "%d,," % (listStep[i])
        tTitle += "Remain Count,," 
        self.TraceToFile(tTitle) 
        
        tTitle = ""
        for i in range(lenlistStep):
            tTitle += "%d,%.2f," % (listCnt[i],listCnt[i]/float(lenList))
        tCnt = lenList - listCnt[lenlistStep-1]
        tTitle += "%d,%.2f" % (tCnt, tCnt / float(lenList))
        self.TraceToFile(tTitle) 
            
        return True
        
    # ///////////////////////////////////////////////////////////////////////

    def getDataAsMiner(self, miner="", indexRowStart = 0, count=0, bOut=False):
        if not self.bLoadOk : 
            return False

        indexFrom = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCADDR)
        if (indexFrom < 0):
            return 0
               
        if not self.dataRaw.checkIndexRange(indexRowStart):
            return 0
        
        if not self.dataRaw.checkIndexRange(indexRowStart+count-1):
            return 0
            
        if (miner==""):
            return 0
        
        if (count<1):
            return 0
            
        if bOut : 
            tTitle = "\n\nMINER ,%s,%d,%d" % (miner,indexRowStart,count)
            self.TraceToFile(tTitle) 
            tTitle = "%s,%s,%s,%s,%s,HPS" % (DEF_RAW_INDEX_NAME_BINDEX,DEF_RAW_INDEX_NAME_BCHAINWORK,DEF_STAT_GENERAL_INDEX_NAME_DIFF,DEF_STAT_GENERAL_INDEX_NAME_mTIME,DEF_STAT_GENERAL_INDEX_NAME_dChainW)
            self.TraceToFile(tTitle) 
            
        tListmTIME = []
        currentDiff=0.
        currentDiffIndex=0.
        for i in range(indexRowStart,indexRowStart+count,1):
            if(self.dataRaw.items[i][indexFrom]==miner):
                tTitle=""
                
                indexFromNew = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BINDEX)
                if (currentDiffIndex < 1):
                    currentDiffIndex = int(self.dataRaw.items[i][indexFromNew] / DEF_Interval)
                tTitletStep = "%d" % (self.dataRaw.items[i][indexFromNew])
                tTitle += tTitletStep
                
                indexFromNew = self.dataRaw.getColIndex(DEF_RAW_INDEX_NAME_BCHAINWORK)
                tTitletStep = ",%d" % (self.dataRaw.items[i][indexFromNew])
                tTitle += tTitletStep
                
                indexFromNew = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_DIFF)
                if (currentDiff==0.):
                    currentDiff = self.items[i][indexFromNew]
                tTitletStep = ",%.1f" % (self.items[i][indexFromNew])
                tTitle += tTitletStep
                
                indexFromNew = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_mTIME)
                mTIME = self.items[i][indexFromNew]
                tListmTIME.append(mTIME)
                tTitletStep = ",%d" % (mTIME)
                tTitle += tTitletStep
                
                indexFromNew = self.getColIndex(DEF_STAT_GENERAL_INDEX_NAME_dChainW)
                chainW = self.items[i][indexFromNew]
                tTitletStep = ",%d" % (chainW)
                tTitle += tTitletStep
                
                hps = 0
                if(mTIME>0):
                    hps = chainW / mTIME
                tTitletStep = ",%d" % (hps)
                tTitle += tTitletStep
                
                if bOut : 
                    self.TraceToFile(tTitle) 
        
        numListmTIME = len(tListmTIME)
        if(numListmTIME):            
            avrmTIME = sum(tListmTIME) / float(numListmTIME)
            
            vsum = 0
            for x in tListmTIME:
                vsum = vsum + (x - avrmTIME)**2
            varmTIME = vsum / float(numListmTIME)
            stdmTIME = math.sqrt(varmTIME)
            maxmTIME = max(tListmTIME)
            minmTIME = min(tListmTIME)
            
            if bOut : 
                tTitle = "\n\nLIST\n"
                
                self.TraceToFile(tTitle) 
            
                tTitle = "\nIdDIFF,DIFF,NUM,MEAN,MIN,MAX,VAR,STD,LIST"
                self.TraceToFile(tTitle) 
                tTitle = "%d,%.1f,%d,%.1f,%.1f,%.1f,%.1f,%.4f" % (currentDiffIndex,currentDiff,numListmTIME,avrmTIME,minmTIME,maxmTIME,varmTIME,stdmTIME)
                for i in range(numListmTIME):
                    tTitleStep = ""
                    tTitleStep = ",%d" % tListmTIME[i]
                    tTitle += tTitleStep
                
                self.TraceToFile(tTitle)                 
                self.getStatWList(tListmTIME,avrmTIME,stdmTIME)
        
        return True

    # ///////////////////////////////////////////////////////////////////////

    def StartStatisticsMinerMorn(self, bOut=False):
        if not self.bLoadOk : 
            return False
        
        tNumMiner = len(self.MINERMORN)
        if(tNumMiner<1):
            return False
                
        if bOut : 
            tTitle = "\n\nMINER,CNT"
            self.TraceToFile(tTitle) 
        """
        if bOut : 
            for i in range(tNumMiner):
                tTitle = "%s,%d" % (self.MINERMORN[i][0],self.MINERMORN[i][1])
                self.TraceToFile(tTitle)    
        
        self.TraceToFile("\n\n")    
        """
            
        for i in range(tNumMiner):
            refNum = self.MINERMORN[i][1]
            for j in range(i+1,tNumMiner,1):
                if(refNum<self.MINERMORN[j][1]):
                    tempMiner = []
                    tempMiner = self.MINERMORN[i]
                    self.MINERMORN[i] = self.MINERMORN[j]
                    self.MINERMORN[j] = tempMiner
                    refNum = self.MINERMORN[i][1]
            
        if bOut : 
            for i in range(tNumMiner):
                tTitle = "%s,%d" % (self.MINERMORN[i][0],self.MINERMORN[i][1])
                self.TraceToFile(tTitle)         
        
        # ///////////////////////////////////////////////////////////////////////
        
        lenPer = len(self.diffPer)
        
        #for i in range(tNumMiner):
        for i in range(1):
            tMIner = self.MINERMORN[i][0]
            #for j in range(lenPer):
            for j in range(lenPer):
                self.getDataAsMiner(tMIner,self.diffPer[j][0],self.diffPer[j][2], bOut)        
           
        return True
        
    # ///////////////////////////////////////////////////////////////////////

    def StartStatistics(self):
        if not self.bLoadOk : 
            return False
        
        self.StartStatisticsGeneral(False)
        self.StartStatisticsSamples(100, False)
        self.StartStatisticsDiff(False)
        self.StartStatisticsMiner(False)
        self.StartStatisticsMinerStat(0,False)
        self.StartStatisticsMinerStat(1,False)
        self.StartStatisticsMinerMorn(True)
        
        return True




















































# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////

import random
from random import shuffle

DEF_OVERALL_TRACE_FNAME = "bktest.txt"     



DEF_RANDOM_NUM_LIST_MAX = 4800
DEF_RANDOM_NUM_LIST_SAMPLE_MAX = 480

import numpy as np
def getGaussianRandom(mean, sigma):
    return np.random.normal(mean, sigma, 1)

   
from scipy.stats import truncnorm
def get_truncated_normal_Random(mean=0, sd=1, low=0, upp=10):
    return truncnorm(
        (low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)

        
def getRandomGaussianRange(tmin, tmax, tmean, tsigma):
    a = random.gauss(tmean,tsigma)
    bNoRange = True
    if(tmin<=a<=tmax):
        return a
    else:
        while bNoRange:
            a = random.gauss(tmean,tsigma)
            if(tmin<=a<=tmax):
                bNoRange = False
        
        return a


def getRandomGaussianRangeOuter(tmin, tmax, tminIN, tmaxIN, tmean, tsigma):
    a = random.gauss(tmean,tsigma)
    #print "tmin=%f, tmax=%f, tminIN=%f, tmaxIN=%f, a=%f" % (tmin, tmax, tminIN, tmaxIN, a)
    bNoRange = True
    if(tmin>=tminIN):#no left side
        if((tmaxIN<a) and (a<=tmax)):
            return a
        while bNoRange:
            a = random.gauss(tmean,tsigma)
            if((tmaxIN<a) and (a<=tmax)):
                bNoRange = False
        
        return a
    
    else:
        if ((tmin<=a) and (a<tminIN)):
            return a
        elif((tmaxIN<a) and (a<=max)):
            return a
            
        while bNoRange:
            a = random.gauss(tmean,tsigma)
            if ((tmin<=a) and (a<tminIN)):
                bNoRange = False
            elif((tmaxIN<a) and (a<=max)):
                bNoRange = False
        
        return a
        

def getRandomList(min, max, count):
    totList = []*DEF_RANDOM_HUN_LIST_MAX
    
    for i in range(count):
        testNum = random.randrange(min,max)
        totList.append(testNum)
    
    shuffle(totList)    
    return totList
    
    
def getRandomGaussianList(min, max, count, mean, sigma):
    if(count > DEF_RANDOM_NUM_LIST_MAX):
        return []
        
    totList = []*DEF_RANDOM_NUM_LIST_MAX
    
    for i in range(count):
        testNum = random.getRandomGaussianRange(min, max, mean, sigma)
        totList.append(testNum)
    
    shuffle(totList)    
    return totList


# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

DEF_powminimumbits = 22


class classPyDiff:
    powminimumbits = DEF_powminimumbits
    nTargetSpacing = DEF_nTargetSpacing
    targetadjustfreq = DEF_targetadjustfreq
    nTargetSpacingShort = targetadjustfreq / 4
    nTargetSpacingLong = targetadjustfreq * 4
    genesisNbits = 0x1E03FFFF
    maximumTarget = 0x00000000FFFF0000000000000000000000000000000000000000000000000000  
    maximumDiff = 0x0000FFFF
    nCompactProofOfWorkLimit = 0   
    nProofOfWorkLimit = 0
    
    def __init__(self):
        full_uint256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        self.nProofOfWorkLimit = full_uint256 >> self.powminimumbits
        self.nCompactProofOfWorkLimit = compact_from_uint256(self.nProofOfWorkLimit)
        self.nTargetSpacingShort = self.targetadjustfreq / 4
        self.nTargetSpacingLong = self.targetadjustfreq * 4
    
    #def GetBitsLimit(self):
        #print "          " + "{0:064x}".format(self.maximumTarget)
        #print "          " + "{0:0256b}".format(self.maximumTarget)
        
    def GetDifficulty(self, nBits = 0x00000000, bDisplay = 0):
        newBits = nBits & 0x00FFFFFF
        if newBits < 1:
            return 0
            
        nSize = (nBits >> 24) & 0xFF
        fmaximumDiff = float(self.maximumDiff)
        fnewBits = float(newBits)
        fdiff = fmaximumDiff / fnewBits        
        
        if nSize < 29:
            dup = 29 - nSize
            newDiff = 256**dup
            fdiff *= newDiff
        elif nSize > 29:
            dup = nSize - 29
            newDiff = 256**dup
            fdiff /= newDiff
        
        #if bDisplay :
        #    print "Current Difficulty : " + "%.8f"%fdiff + " <> "+ "%d"%newBits
        #    print "        Difficulty : " + "%.8f"%fdiff + " <> "+ "%d"%newBits
        
        return fdiff
    
    
    def GetNextWorkRequired(self, nBits = 0x00000000, tSpan = 86400):
        #print "Current nBits      : " + hex(nBits)
        #print "Current nBits      : 0x" + "{0:08x}".format(nBits) + " <> "+ "%d"%nBits
        #print "Time Span          : " + "%d"%tSpan
        currentCompact = uint256_from_compact(nBits)        
        #self.GetDifficulty(nBits, 1)                
        #print "                     " + "{0:08x}".format(nBits)
        #print "                     " + "{0:064x}".format(currentCompact)
        #print "                     " + "{0:0256b}".format(currentCompact)
        
        nTargetTimespan = tSpan
        
        if tSpan < self.nTargetSpacingShort:
            nTargetTimespan = self.nTargetSpacingShort
        
        if tSpan > self.nTargetSpacingLong:
            nTargetTimespan = self.nTargetSpacingLong
        
        nextCompact = int(currentCompact * nTargetTimespan / self.targetadjustfreq)
        
        if self.nProofOfWorkLimit < nextCompact : 
            nextCompact = self.nProofOfWorkLimit
        
        #print "Next nBits String  : " + "{0:0256b}".format(nextCompact)
        
        nextBits = compact_from_uint256(nextCompact)
        #print "Next nBits         : " + hex(nextBits)
        #print "Next nBits         : 0x" + "{0:08x}".format(nextBits)
        #self.GetDifficulty(nextBits, 1)
        return nextBits

    def GetBlockProof(self, nBits = 0x00000000, preWork = 0x0000000000000000000000000000000000000000000000000000000000000000):
        currentCompact = uint256_from_compact(nBits)
        work = 2**256
        work -= currentCompact - 1
        work /= (currentCompact+1)
        work += 1
        work += preWork
        #print "{0:064x}".format(work)
        #print work
        return work
        
    def GetBlockProofTemp(self, nBits = 0x00000000):
        currentCompact = uint256_from_compact(nBits)
        work = 2**256
        work -= currentCompact - 1
        work /= (currentCompact+1)
        work += 1
        return work




# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////


    
# make random list with 4800
# make std position 85% +- 0.03. get this with random rate
# make std list with std position
# make stdover list with position    
# shuffle
# get random time
# check position

DEF_STD_RATE = 0.85 #ref
DEF_STD_RATE_OPT = 0.15 # ref

DEF_UNSER_STD = 0.95 # ref
DEF_OVER_STD = 0.1 # ref
DEF_RATE_STD_RANGE = 0.05 # ref
DEF_OVER_STD_RANGE = 6.0 # ref
DEF_GHPS_DIVIDED = 1000000000

class MinerClass:
    timeList = []
    meanMiner = 0.
    sigmaMiner = 0.
    maxSigmaMiner = 0.
    currHPS = 0
    strSMiner = ""
    strCMiner = ""

# ///////////////////////////////////////////////////////////////////////

    def TraceToFile(self, info=""):
        fp = open(DEF_OVERALL_TRACE_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()

    
    def getRandom(self, tmin, tmax):
        random.seed()
        a = random.randrange(int(tmin),int(tmax))
        return a
    
    
    def getRandomOuter(self, tmin, tmax, tminInner, tmaxInner, tmean):
        random.seed()
        tmin = int(tmin)
        tmax = int(tmax)
        tminInner = int(tminInner)
        tmaxInner = int(tmaxInner)
        
        a = random.randrange(tmin,tmax)
        if(((a>=tmin) and (a<tminInner)) and ((a>tmaxInner) and (a<=tmax))):
            return a

        if(tmin>=tminInner):#no left side
            a = random.randrange(tmaxInner,tmax)
        else:
            type = 0
            if(a<=tmean):
                type = 0
            else:
                type = 1 
                
            random.seed() 
            if(type==0):
                a=random.randrange(tmin,tminInner)
            else:
                a=random.randrange(tmaxInner,tmax+1)
        
        return a
        

    def getRandomGaussianRange(self, tmin, tmax, tmean, tsigma):
        random.seed()
        #a = random.gauss(tmean,tsigma)
        a = random.normalvariate(tmean,tsigma)
        bNoRange = True
        if(tmin<=a<=tmax):
            return a
        else:
            """
            if(a<tmean):
                while bNoRange:
                    #a = random.gauss(tmean,tsigma)
                    a = random.normalvariate(tmean,tsigma)
                    if(tmin<=a<=tmean):
                        bNoRange = False
            else:
                while bNoRange:
                    #a = random.gauss(tmean,tsigma)
                    a = random.normalvariate(tmean,tsigma)
                    if(tmean<=a<tmax):
                        bNoRange = False
            """
            while bNoRange:
                    random.seed()
                    a = random.gauss(tmean,tsigma)
                    if(tmin<=a<=tmax):
                        bNoRange = False
            return a
        
        
    def getRandomGaussianRangeOuter(self, tmin, tmax, tminIN, tmaxIN, tmean, tsigma):
        random.seed()
        a = random.gauss(tmean,tsigma)
        #a=getGaussianRandom(tmean,tsigma)
        
        bNoRange = True
        if(tmin>=tminIN):#no left side
            if((tmaxIN<a) and (a<=tmax)):
                return a
            while bNoRange:
                a = random.gauss(tmean,tsigma)
                #a=getGaussianRandom(tmean,tsigma)
                if((tmaxIN<a) and (a<=tmax)):
                    bNoRange = False
         
            return a
    
        else:
            if ((tmin<=a) and (a<tminIN)):
                return a
            elif((tmaxIN<a) and (a<=tmax)):
                return a
            
            halfRange = tmax + tmaxIN
            halfRange /= 2
            
            if(a<=halfRange):
                while bNoRange:
                    random.seed()
                    a = random.gauss(tmean,tsigma)
                  
                    if ((tmin<=a) and (a<tminIN)):
                        bNoRange = False
                    elif((tmaxIN<a) and (a<=halfRange)):
                        bNoRange = False
            else:
                while bNoRange:
                    random.seed()
                    a = random.gauss(tmean,tsigma)
                  
                    if ((tmin<=a) and (a<tminIN)):
                        bNoRange = False
                    elif((halfRange<=a) and (a<=tmax)):
                        bNoRange = False
        
            return a
        
                    
    # ///////////////////////////////////////////////////////////////////////
    
    def init(self, hash, chainwork):
        #print "MinerClass : %f, %f" % (hash, chainwork)
        
        if((hash<=1) or (chainwork<=1)):
            return
 
        # get std count 
        tCountRate = DEF_UNSER_STD
        testNUM = random.randrange(0,DEF_RATE_STD_RANGE*1000*2)
        testNUM -= DEF_RATE_STD_RANGE*1000
        testNUM /= 1000
        tCountRate += testNUM
        #print "tCountRate : %f" % (tCountRate)
        nowStdMaxCount = int(DEF_RANDOM_NUM_LIST_MAX * tCountRate)
        nowStdMaxCountRemain = DEF_RANDOM_NUM_LIST_MAX - nowStdMaxCount
        #print "nowStdMaxCount : %d, nowStdMaxCountRemain : %d" % (nowStdMaxCount, nowStdMaxCountRemain)
        
        #get mean and sigma
        self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
        testNUM = random.randrange(0,DEF_STD_RATE_OPT*2000)
        testNUM -= DEF_STD_RATE_OPT*1000
        testNUM /= 1000.
        stdRate = DEF_STD_RATE
        stdRate += testNUM        
        self.sigmaMiner = self.meanMiner * stdRate
        self.maxSigmaMiner = 5
        #print "meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner)
        
        #get list
        sigmaMIN = self.meanMiner - self.sigmaMiner
        if(sigmaMIN<1):
            sigmaMIN = 1
        sigmaMAX = self.meanMiner + self.sigmaMiner        
        
        expectedMin = 1
        expectedMax = self.meanMiner + self.maxSigmaMiner * self.sigmaMiner
        
        
        tmax = 0
        tNewAvg = self.meanMiner * stdRate * stdRate
        #print "meanMiner : %f, meanMiner2 : %f" % (self.meanMiner, tNewAvg)
        #print "sigmaMIN : %d, sigmaMAX : %d" % (sigmaMIN, sigmaMAX)
        #print "expectedMin : %d, expectedMax : %d" % (expectedMin, expectedMax)
        
        bSampleList = False
        tStepRange = self.meanMiner * 0.05
        p#rint "expected TotAVg Ragne : %f : %f ~ %f" % (self.meanMiner, self.meanMiner-tStepRange, self.meanMiner+tStepRange)
        while not bSampleList:
            tList = []
            tValStd = 0
            tValStdCnt = 0
            tValTot = 0
            tValTotCnt = 0
        
            for i in range(DEF_RANDOM_NUM_LIST_MAX):
                if(i<nowStdMaxCount):
                    gauNum = self.getRandomGaussianRange(sigmaMIN,sigmaMAX,tNewAvg,self.sigmaMiner)
                    tValStd += gauNum
                    tValStdCnt += 1
                else:
                    gauNum = self.getRandomGaussianRangeOuter(expectedMin,expectedMax,sigmaMIN,sigmaMAX, self.meanMiner,self.sigmaMiner*5)
            
                tValTot += gauNum
                tValTotCnt += 1
                if(tmax<gauNum):
                    tmax = gauNum
                tList.append(gauNum)
            
            tCurrentMean = tValTot/tValTotCnt
            self.TraceToFile("inner : %f" % (tValStd/tValStdCnt))
            self.TraceToFile("Total : %f" % (tCurrentMean))
            
            if((tCurrentMean > (self.meanMiner-tStepRange)) and (tCurrentMean < (self.meanMiner+tStepRange))):
                bSampleList = True
        
        if(bSampleList):
            self.timeList = tList
            tValStd = 0
            for i in range(DEF_RANDOM_NUM_LIST_MAX):
                tValStd += self.timeList[i]
            tValStd /= DEF_RANDOM_NUM_LIST_MAX
            print("Total : %f, %f" % (tValStd, tStepRange))
            
        return
        
    # ///////////////////////////////////////////////////////////////////////
    
    def init2(self, hash, chainwork):
        #print "\n Get Miner Info with : hps = %f for chainwork=%f" % (hash, chainwork)
        
        if((hash<=1) or (chainwork<=1)):
            return
 
        # get std count 
        tCountRate = DEF_UNSER_STD
        testNUM = random.randrange(0,DEF_RATE_STD_RANGE*1000*2)
        testNUM -= DEF_RATE_STD_RANGE*1000
        testNUM /= 1000
        tCountRate += testNUM
        #print "\t tCountRate : %f" % (tCountRate)
        nowStdMaxCount = int(DEF_RANDOM_NUM_LIST_MAX * tCountRate)
        nowStdMaxCountRemain = DEF_RANDOM_NUM_LIST_MAX - nowStdMaxCount
        #print "\t nowStdMaxCount : %d, nowStdMaxCountRemain : %d" % (nowStdMaxCount, nowStdMaxCountRemain)
        
        #get mean and sigma
        self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
        testNUM = random.randrange(0,DEF_STD_RATE_OPT*2000)
        testNUM -= DEF_STD_RATE_OPT*1000
        testNUM /= 1000.
        stdRate = DEF_STD_RATE
        stdRate += testNUM        
        self.sigmaMiner = self.meanMiner * stdRate
        self.maxSigmaMiner = 5
        #print "\t meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner)
        
        
        if (self.meanMiner < 5):
            self.meanMiner = 5
            self.sigmaMiner = 3
            #print "\t NEW : meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner)
        
        
        #get list
        sigmaMIN = self.meanMiner - self.sigmaMiner
        if(sigmaMIN<1):
            sigmaMIN = 1
        sigmaMAX = self.meanMiner + self.sigmaMiner        
        
        expectedMin = 1
        expectedMax = self.meanMiner + self.maxSigmaMiner * self.sigmaMiner
        
        
        tmax = 0
        tNewAvg = self.meanMiner * stdRate * stdRate
        #print "\t meanMiner : %f, meanMiner2 : %f" % (self.meanMiner, tNewAvg)
        #print "\t sigmaMIN : %d, sigmaMAX : %d" % (sigmaMIN, sigmaMAX)
        #print "\t expectedMin : %d, expectedMax : %d" % (expectedMin, expectedMax)
        
        bSampleList = False
        tStepRange = self.meanMiner * 0.05
        #print "\t expected TotAVg Ragne : %f : %f ~ %f" % (self.meanMiner, self.meanMiner-tStepRange, self.meanMiner+tStepRange)
        while not bSampleList:
            tList = []
            tValStd = 0
            tValStdCnt = 0
            tValTot = 0
            tValTotCnt = 0
        
            for i in range(DEF_RANDOM_NUM_LIST_MAX):
                if(i<nowStdMaxCount):
                    gauNum = self.getRandomGaussianRange(sigmaMIN,sigmaMAX,tNewAvg,self.sigmaMiner)
                    #gauNum = self.getRandom(sigmaMIN,sigmaMAX)
                    #self.TraceToFile("inner : %f" % (gauNum))
                    #gauNum = int(gauNum)
                    tValStd += gauNum
                else:
                    gauNum = self.getRandomOuter(expectedMin,expectedMax,sigmaMIN,sigmaMAX,self.meanMiner)
                    #gauNum = int(gauNum)
                    #self.TraceToFile("outer : %f" % (gauNum))
            
                tValTot += gauNum
                tList.append(gauNum)
            
            tCurrentMean = tValTot/DEF_RANDOM_NUM_LIST_MAX
            tTitle = "\t inner : %f" % (tValStd/nowStdMaxCount)
            #self.TraceToFile(tTitle)
            #print tTitle
            tTitle = "\t Total : %f" % (tCurrentMean)
            #self.TraceToFile(tTitle)
            #print tTitle
            
            if((tCurrentMean > (self.meanMiner-tStepRange)) and (tCurrentMean < (self.meanMiner+tStepRange))):
                bSampleList = True
            
            time.sleep(1)
            #random.seed()
        
        if(bSampleList):
            self.timeList = tList
            tValStd = 0
            for i in range(DEF_RANDOM_NUM_LIST_MAX):
                tValStd += self.timeList[i]
            tValStd /= DEF_RANDOM_NUM_LIST_MAX
            print("\t Final : %f" % (tValStd))
            
        return       


    # ///////////////////////////////////////////////////////////////////////
    
    def initSimple(self, hash, chainwork):
        self.TraceToFile("\n Get Miner Info with : hps = %f for chainwork=%f" % (hash, chainwork))
        
        if((hash<=1) or (chainwork<=1)):
            return
        
        self.currHPS = hash
        
        # get std count 
        tCountRate = DEF_UNSER_STD
        testNUM = random.randrange(0,DEF_RATE_STD_RANGE*1000*2)
        testNUM -= DEF_RATE_STD_RANGE*1000
        testNUM /= 1000
        tCountRate += testNUM
        self.TraceToFile("\t tCountRate : %f" % (tCountRate))
        nowStdMaxCount = int(DEF_RANDOM_NUM_LIST_MAX * tCountRate)
        nowStdMaxCountRemain = DEF_RANDOM_NUM_LIST_MAX - nowStdMaxCount
        self.TraceToFile("\t nowStdMaxCount : %d, nowStdMaxCountRemain : %d" % (nowStdMaxCount, nowStdMaxCountRemain))
        
        #get mean and sigma
        self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
        testNUM = random.randrange(0,DEF_STD_RATE_OPT*2000)
        testNUM -= DEF_STD_RATE_OPT*1000
        testNUM /= 1000.
        stdRate = DEF_STD_RATE
        stdRate += testNUM        
        self.sigmaMiner = self.meanMiner * stdRate
        self.maxSigmaMiner = 5
        self.TraceToFile("\t meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner))
        
        if (self.meanMiner < 5):
            self.meanMiner = 5
            self.sigmaMiner = 3
            self.TraceToFile("\t NEW : meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner))
        
        #get list
        sigmaMIN = self.meanMiner - self.sigmaMiner
        if(sigmaMIN<1):
            sigmaMIN = 1
        sigmaMAX = self.meanMiner + self.sigmaMiner        
        
        expectedMin = 1
        expectedMax = self.meanMiner + self.maxSigmaMiner * self.sigmaMiner
        
        
        tmax = 0
        tNewAvg = self.meanMiner * stdRate * stdRate
        self.TraceToFile("\t meanMiner : %f, meanMiner2 : %f" % (self.meanMiner, tNewAvg))
        self.TraceToFile("\t sigmaMIN : %d, sigmaMAX : %d" % (sigmaMIN, sigmaMAX))
        self.TraceToFile("\t expectedMin : %d, expectedMax : %d" % (expectedMin, expectedMax))
        tStepRange = self.meanMiner * 0.05
        self.TraceToFile("\t expected TotAVg Ragne : %f : %f ~ %f" % (self.meanMiner, self.meanMiner-tStepRange, self.meanMiner+tStepRange))
        
        tList = []
        tValStd = 0
        tValStdCnt = 0
        tValTot = 0
        tValTotCnt = 0
    
        for i in range(DEF_RANDOM_NUM_LIST_MAX):
            if(i<nowStdMaxCount):
                gauNum = self.getRandomGaussianRange(sigmaMIN,sigmaMAX,tNewAvg,self.sigmaMiner)
                #gauNum = self.getRandom(sigmaMIN,sigmaMAX)
                #self.TraceToFile("inner : %f" % (gauNum))
                #gauNum = int(gauNum)
                tValStd += gauNum
            else:
                gauNum = self.getRandomOuter(expectedMin,expectedMax,sigmaMIN,sigmaMAX,self.meanMiner)
                #gauNum = int(gauNum)
                #self.TraceToFile("outer : %f" % (gauNum))
        
            tValTot += gauNum
            tList.append(gauNum)
        
        tCurrentMean = tValTot/DEF_RANDOM_NUM_LIST_MAX
        tTitle = "\t inner : %f" % (tValStd/nowStdMaxCount)
        self.TraceToFile(tTitle)
        #print tTitle
        tTitle = "\t Total : %f" % (tCurrentMean)
        self.TraceToFile(tTitle)
        #print tTitle        
        
        self.timeList = tList
        tValStd = 0
        for i in range(DEF_RANDOM_NUM_LIST_MAX):
            tValStd += self.timeList[i]
        tValStd /= DEF_RANDOM_NUM_LIST_MAX
        self.TraceToFile("\t Final : %f" % (tValStd))       
            
        return       
    
    
    def setMinerName(self, sMiner, cMiner):
        self.strSMiner = sMiner
        self.strCMiner = cMiner
     
    def getMinerName(self, type=0):
        if(type==0):
            return self.strSMiner
        else:
            return self.strCMiner
    
    def getCurrHPS(self):
        return float(self.currHPS)
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getTimeList(self):
        return self.timeList

    def getTime(self):
        index = random.randrange(0,DEF_RANDOM_NUM_LIST_MAX)
        index %= DEF_RANDOM_NUM_LIST_MAX
        return (self.timeList[index])

    def getTimeInt(self):
        index = random.randrange(0,DEF_RANDOM_NUM_LIST_MAX)
        index %= DEF_RANDOM_NUM_LIST_MAX
        return int(self.timeList[index])
# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////

class statBlock:
    tBlock = []
    nIndex = 0
    nTime = 0
    nBits = 0x00000000
    signMiner = ""
    coinMiner = ""
    
    def init(self,nIndex, nTime, nBits, signMiner, coinMiner):
        self.tBlock.append(nIndex)
        self.tBlock.append(nTime)
        self.tBlock.append(nBits)
        self.tBlock.append(signMiner)
        self.tBlock.append(coinMiner)
        
        self.nIndex = nIndex
        self.nTime = nTime
        self.nBits = nBits
        self.signMiner = signMiner
        self.coinMiner = coinMiner
    
    def getBlockList(self):
        return tBlock
    
    def getItemsAsIndex(self, index):
        if (index>5 or index < 0):
            return -1
            
        return tBlock[index]


   
DEF_BLOCK_TEST_MAX = 2000

class blockTest:
    dbBlock = []
    listMiner = []
    listMinerModule = []
    dbBlockCount = 0
    listMinerInfoCount = 0
    bInitOk = False
    
    def __init__(self):
        newblock = statBlock()
        newblock.init(0,1526653949,0x1b4b0f40,"HGoH4m78d17sXLia4C8Ee3R3FTtCCuaPKs","HGoH4m78d17sXLia4C8Ee3R3FTtCCuaPKs")
        self.dbBlock.append(newblock)
        self.dbBlockCount = len(self.dbBlock)
        
        #print("GENESIS : %d,%d,%s,%s,%s") % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner)
        
        tlistMiner = ["aa","aa",3000.0]
        self.listMiner.append(tlistMiner)
        tlistMiner = ["bb","bb",1000.0]
        self.listMiner.append(tlistMiner)
        tlistMiner = ["cc","cc",1000.0]
        self.listMiner.append(tlistMiner)
        tlistMiner = ["dd","dd",500.0]
        self.listMiner.append(tlistMiner)        
        tlistMiner = ["ee","ee",300.0]
        self.listMiner.append(tlistMiner)        
        tlistMiner = ["ff","ff",300.0]
        self.listMiner.append(tlistMiner)        
        
        self.listMinerInfoCount = len(self.listMiner)        
        
        self.bInitOk = True
        
    def TraceToFile(self, info=""):
        fp = open(DEF_OVERALL_TRACE_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()        
        
    def getdifficulty(self, nBits):
        tModule = classPyDiff()
        diff = tModule.GetDifficulty(nBits, 0)
        return 
        
        
    def GetNextWorkRequired(self, tipHeight):
        if not self.bInitOk:
            return 0

        height = len(self.dbBlock)
        if(height != self.dbBlockCount):
            #print "ABNORMAL CASE : blockTest : makeNewBlock : %d" % (self.dbBlock)
            return 0
        
        height -= 1
        tipBlock = self.dbBlock[height]
        nBits = tipBlock.nBits
        
        tIndex = (tipHeight + 1) % DEF_Interval
        if (tIndex> 0):
            return tipBlock.nBits
        
        self.TraceToFile("\ncheck here")
        self.TraceToFile("height = %d" % (height))
        self.TraceToFile("tipBlock.nIndex = %d" % (tipBlock.nIndex))
        self.TraceToFile("tipBlock.nTimenTime = %d" % (tipBlock.nTime))
        
        firstBlock = self.dbBlock[int(height+1-DEF_Interval)]
        
        self.TraceToFile("firstBlock.nIndex = %d" % (firstBlock.nIndex))
        self.TraceToFile("firstBlock.nTimenTime = %d" % (firstBlock.nTime))
        
        nActualTimespan = tipBlock.nTime - firstBlock.nTime
        
        tModule = classPyDiff()
        nBits = tModule.GetNextWorkRequired(tipBlock.nBits, nActualTimespan)
        
        return nBits
    
    
    def GetChainwork(self, nBits):
        if not self.bInitOk:
            return 0
            
        tModule = classPyDiff()
        diffCW = tModule.GetBlockProofTemp(nBits)
        
        return diffCW
    
    def GetTip(self):
        if not self.bInitOk:
            return 0
        
        tipBlock = self.dbBlock[self.dbBlockCount-1]
        return tipBlock
    
    # ///////////////////////////////////////////////////////////////////////

    def initMinerWithCW(self, chainwork):
        if not self.bInitOk:
            return False
        
        #print "\n INIT Miner Info : START"
        
        self.listMinerModule[:] = []
        
        for i in range(self.listMinerInfoCount):            
            tMinerModule = MinerClass()
            tMinerModule.setMinerName(self.listMiner[i][0], self.listMiner[i][1])
            tMinerModule.initSimple(self.listMiner[i][2], chainwork)
            
            self.listMinerModule.append(tMinerModule)
        
        #print " INIT Miner Info : END\n"
        
        return True


    def GetMinerAndTimeForChainwork(self, chainwork):
        if not self.bInitOk:
            return False
        
        tValList = []
        for i in range(self.listMinerInfoCount):
            tMiner = self.listMinerModule[i]
            tList = []
            tList.append(tMiner.getMinerName(0))
            tList.append(tMiner.getMinerName(1))
            tList.append(tMiner.getCurrHPS())
            tList.append(tMiner.getTime())
            tValList.append(tList)            
            self.TraceToFile("%s,%s,%f,%f"%(tList[0],tList[1],tList[2],tList[3]))
        
        #shuffle(tValList)
        
        for i in range(self.listMinerInfoCount):
            for j in range(i, self.listMinerInfoCount, 1):
                if(tValList[i][3]>tValList[j][3]):
                    tStoreList = tValList[i]
                    tValList[i]= tValList[j]
                    tValList[j] = tStoreList
        
        for i in range(self.listMinerInfoCount):
            self.TraceToFile("%s,%s,%f,%f"%(tValList[i][0],tValList[i][1],tValList[i][2],tValList[i][3]))            
        return tValList

    def makeNewBlock(self, nTime, nBits, signMiner, coinMiner):
        if not self.bInitOk:
            return ""
            
        height = len(self.dbBlock)
        if(height != self.dbBlockCount):
            #print "ABNORMAL CASE : blockTest : makeNewBlock : %d" % (self.dbBlock)
            return ""
        
        height -= 1
        tipBlock = self.dbBlock[height]
        newIndex = tipBlock.nIndex + 1 
        nTime += tipBlock.nTime
        self.TraceToFile("new block : %d,%s,%s,%s"%(nTime,int2hex(nBits),signMiner,coinMiner))
        newblock = statBlock()        
        newblock.init(newIndex, nTime, nBits, signMiner, coinMiner)
        
        return newblock
    
    def addNewBlock(self, newBlock):
        if not self.bInitOk:
            return False
        
        height = len(self.dbBlock)
        if(height != self.dbBlockCount):
            #print "ABNORMAL CASE : blockTest : addNewBlock : %d" % (self.dbBlock)
            return False
        
        height -= 1
        if (height>=newBlock.nIndex):
            return False
        
        self.dbBlock.append(newblock)
        self.dbBlockCount = len(self.dbBlock)
        
        return True

    # ///////////////////////////////////////////////////////////////////////
    
    def GetMiningDepth(self,miner):
        if not self.bInitOk:
            return -1

        miningDepth = -1
        maxDepth = DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        maxDepth = min(maxDepth, tipHeight)
        
        for i in range(maxDepth):
            checkBlock = self.dbBlock[tipHeight-i]
            if(checkBlock.coinMiner == miner):
                miningDepth = i
        
        self.TraceToFile("GetMiningDepth : miningDepth : %d"%(miningDepth))
        
        return miningDepth


    def GetMiningContinuity(self,miner):
        if not self.bInitOk:
            return -1
        
        miningContinuity = 0
        maxDepth = DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        maxDepth = min(maxDepth, tipHeight)

        for i in range(maxDepth):
            checkBlock = self.dbBlock[tipHeight-i]
            if(checkBlock.coinMiner == miner):
                miningContinuity += 1
            else:
                break;
        
        self.TraceToFile("GetMiningContinuity : miningContinuity : %d"%(miningContinuity))
        
        return miningContinuity


    def GetNodeFactor(self,depth):
        if not self.bInitOk:
            return -1
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        
        depth = min(depth, tipHeight)
        
        tList = []
        for i in range(depth):
            checkBlock = self.dbBlock[tipHeight-i]
            miner = checkBlock.coinMiner
            
            bNew = True
            tNum = len(tList)
            if(tNum):
                bNew = True
                for j in range(tNum):
                    if(miner==tList[j]):
                        bNew = False
                        break;
            if  bNew: 
                tList.append(miner)  
        
        self.TraceToFile("GetNodeFactor: nf : %d"%(len(tList)))
                
        return len(tList)       

    
    def GetBlockWindowSize(self,miner):
        if not self.bInitOk:
            return -1
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        
        blockWz = 0
        depth = 480
        
        depth = min(depth, tipHeight)
        
        mxBlkWz = DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW
        nf = self.GetNodeFactor(depth);
        x = tipHeight
        
        if(x>DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW):
            x = DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW
            blockWz = x * DEF_BLOCKWINDOW_NODE_FACTOR_RATE
        else:
            blockWz = DEF_BLOCKWINDOW_NODE_FACTOR_RATE * x * nf / float(DEF_BLOCK_NUM_OF_MAX_BLOCKWINDOW)
        
        blockWz = int(blockWz)
        
        if(blockWz>=nf):
            blockWz = nf -1
        
        self.TraceToFile("GetBlockWindowSize : blockWz = %f"%(blockWz))
        
        return blockWz        


    def CheckBlockWindow(self,miner):
        if not self.bInitOk:
            return -1

        miningDepth = self.GetMiningDepth(miner);
        wz = self.GetBlockWindowSize(miner);
        
        if(miningDepth<0):
            return True

        if(wz>miningDepth):
            return False

        return True


    def VerifyBlockWindow(self,newblock):
        self.TraceToFile("VerifyBlockWindow : coinMiner : %s"%(newblock.coinMiner))
        return self.CheckBlockWindow(newblock.coinMiner)
        
    # ///////////////////////////////////////////////////////////////////////

    def doTest(self):
        if not self.bInitOk:
            return False
        
        print("\n INIT ###################################################")
        self.TraceToFile("\n INIT ###################################################")
        
        nPreBits = self.GetNextWorkRequired(0)
        nPrechainwork = self.GetChainwork(nPreBits)
        
        #print "\n START ###################################################"
        self.TraceToFile("\n START ###################################################")
        
        bStatus = self.initMinerWithCW(nPrechainwork)
        if not bStatus:
            return
        
        #print "%s" % (int2hex(nPreBits))
        self.TraceToFile("cur nbits : %s" % (int2hex(nPreBits)))
        
        for i in range(DEF_BLOCK_TEST_MAX):#DEF_BLOCK_TEST_MAX
            tipblock = self.GetTip()
            tipHeight = tipblock.nIndex
            nNewBits = self.GetNextWorkRequired(tipHeight)
            #print "%s" % (int2hex(nNewBits))
            
            if(nNewBits==nPreBits):
                tValList = self.GetMinerAndTimeForChainwork(nPrechainwork)
                if(len(tValList)<1):
                    #print "strange. break"
                    break
            
            else:
                nPreBits = nNewBits
                nPrechainwork = self.GetChainwork(nPreBits)
                bStatus = self.initMinerWithCW(nPrechainwork)
                if not bStatus:
                    #print "strange. break"
                    break
                
                tValList = self.GetMinerAndTimeForChainwork(nPrechainwork)
                if(len(tValList)<1):
                    #print "strange. break"
                    break
                    
                self.TraceToFile("updated nbits : %s" % (int2hex(nPreBits)))
                
            bFound = False 
            bCont = True
            j = 0
            newblock = self.makeNewBlock(tValList[j][3],nNewBits,tValList[j][0],tValList[j][1])
            while (not bFound and bCont):
                print("TRY : %d,%d,%s,%s,%s" % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
                self.TraceToFile("\nTRY : %d,%d,%s,%s,%s" % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
                if self.VerifyBlockWindow(newblock):
                    bFound = True
                    
                j += 1
                if (j >= len(tValList)):
                    bCont = False
                
            if(bFound):
                self.dbBlock.append(newblock)
                self.dbBlockCount = len(self.dbBlock)
                print("FOUND : %d,%d,%s,%s,%s" % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
                self.TraceToFile("FOUND : %d,%d,%s,%s,%s" % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
            
            time.sleep(0.1)


        #print "\n END ###################################################"




# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////
# Test
def Test():
    #myStat = DiffStatistics()
    #myStat.load()
    #myStat.getNFList()
    
    num = 0
    for i in range(200):
        num = get_truncated_normal_Random(5,1,0,10)
        #print "%.2f" % (num.rvs())
        #num = getGaussianRandom(5, 0.5)
        #print "%.2f" % (num)
    return

def Test2():
    time_start = time.time()
    mydata = statHdac()
    #mydata.load(DEF_RAW_FNAME_TEST)
    mydata.load(DEF_RAW_FNAME)
    mydata.StartStatistics()
    time_end = time.time()
    time_diff = time_end - time_start
    #print "TEST Ended. during %d seconds" % (time_diff)


def Test3():
    time_start = time.time()
    newTest = blockTest()
    newTest.doTest()
    
    time_end = time.time()
    time_diff = time_end - time_start
    #print "TEST Ended. during %d seconds" % (time_diff)
    


    
# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////
# Main
def main():
    Test3()
    return


# ////////////////////////////////////////////////////////////////////////
# Main END
# ////////////////////////////////////////////////////////////////////////

if __name__ == "__main__":
    main()
