
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

import struct

import numpy as np

import random
from random import shuffle


# ///////////////////////////////////////////////////////////////////////
# DEF ///////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

DEF_powminimumbits = 22
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
DEF_RANDOM_NUM_LIST_MAX = 4800
DEF_RANDOM_NUM_LIST_SAMPLE_MAX = 480


DEF_STD_RATE = 0.85 #ref
DEF_STD_RATE_OPT = 0.15 # ref

DEF_UNSER_STD = 0.95 # ref
DEF_OVER_STD = 0.1 # ref
DEF_RATE_STD_RANGE = 0.05 # ref
DEF_OVER_STD_RANGE = 6.0 # ref
DEF_GHPS_DIVIDED = 1000000000

DEF_TEST_HPS_MIM = 1
DEF_TEST_HPS_MAX = 30

DEF_BLOCK_TEST_MAX = 1000

DEF_BLOCK_ARRAY_MAX = 1600
DEF_BLOCK_ARRAY_LIMIT = 800
DEF_BLOCK_ARRAY_RATE = 0.6

DEF_OVERALL_TRACE_FNAME = "trace.txt"
DEF_OVERALL_RESULT_FNAME = "result.txt"
DEF_OVERALL_RESULT_FNAME2 = "result2.txt"
DEF_MINERLIST = "minerlist.txt"

# ///////////////////////////////////////////////////////////////////////

def TraceToFile(type=0, info=""):
    if (type==1):
        fp = open(DEF_OVERALL_TRACE_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()
    elif (type==2):
        fp = open(DEF_OVERALL_RESULT_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()
    elif (type==3):
        fp = open(DEF_OVERALL_RESULT_FNAME2, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()
    else:
        print(info)
        fp = open(DEF_OVERALL_TRACE_FNAME, 'a')
        t_str = "%s\n" % (info)
        fp.write(t_str)
        fp.close()

# ///////////////////////////////////////////////////////////////////////

def uint256_from_str(s):
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r

# ///////////////////////////////////////////////////////////////////////

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

# ///////////////////////////////////////////////////////////////////////

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

# ///////////////////////////////////////////////////////////////////////

def uint256_to_str(u):
    r = b""
    for i in range(8):
        r += struct.pack('<I', u >> (i * 32) & 0xffffffff)
    return r

# ///////////////////////////////////////////////////////////////////////

def uint256_to_shortstr(u):
    s = "%064x" % (u,)
    return s[:16]

# ///////////////////////////////////////////////////////////////////////

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

# ///////////////////////////////////////////////////////////////////////

def bits2target_int(bits_bytes):
    exp = bin2int(bits_bytes[: 1]) # exponent is the first byte
    mult = bin2int(bits_bytes[1:]) # multiplier is all but the first byte
    return mult * (2 ** (8 * (exp - 3)))

# ///////////////////////////////////////////////////////////////////////

def int2hex(intval):
    hex_str = hex(intval)[2:]
    if hex_str[-1] == "L":
        hex_str = hex_str[: -1]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return hex_str

# ///////////////////////////////////////////////////////////////////////

def hex2int(hex_str):
    return int(hex_str, 16)

# ///////////////////////////////////////////////////////////////////////

def hex2bin(hex_str):
    return binascii.a2b_hex(hex_str)

# ///////////////////////////////////////////////////////////////////////

def int2bin(val, pad_length = False):
    hexval = int2hex(val)
    if pad_length: # specified in bytes
        hexval = hexval.zfill(2 * pad_length)
    return hex2bin(hexval)

# ///////////////////////////////////////////////////////////////////////

def bin2hex(binary):
    # convert raw binary data to a hex string. also accepts ascii chars (0 - 255)
    return binascii.b2a_hex(binary)

# ///////////////////////////////////////////////////////////////////////

def getGaussianRandom(mean, sigma):
    return np.random.normal(mean, sigma, 1)

# ///////////////////////////////////////////////////////////////////////
        
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
        
# ///////////////////////////////////////////////////////////////////////

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
        
# ///////////////////////////////////////////////////////////////////////

def getRandomList(min, max, count):
    totList = []*DEF_RANDOM_HUN_LIST_MAX
    
    for i in range(count):
        testNum = random.randrange(min,max)
        totList.append(testNum)
    
    shuffle(totList)    
    return totList

# ///////////////////////////////////////////////////////////////////////    
    
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
# class /////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

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
    
    # ////////////////////////////////////////////////////////////////////////
    
    """
    def GetBitsLimit(self):
        print "          " + "{0:064x}".format(self.maximumTarget)
        print "          " + "{0:0256b}".format(self.maximumTarget)
    """
    
    # ////////////////////////////////////////////////////////////////////////
        
    def GetDifficulty(self, nBits = 0x00000000):
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
        
        return fdiff
    
    # ////////////////////////////////////////////////////////////////////////
    
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
    
    # ////////////////////////////////////////////////////////////////////////
    
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
    
    # ////////////////////////////////////////////////////////////////////////
        
    def GetBlockProofTemp(self, nBits = 0x00000000):
        currentCompact = uint256_from_compact(nBits)
        work = 2**256
        work -= currentCompact - 1
        work /= (currentCompact+1)
        work += 1
        return work

# ///////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////

class classMiner:
    timeList = []
    meanMiner = 0.
    sigmaMiner = 0.
    maxSigmaMiner = 0.
    currHPS = 0
    strSMiner = ""
    strCMiner = ""
    bUseJustRandom = True

    # ///////////////////////////////////////////////////////////////////////
    
    def getRandom(self, tmin, tmax):
        random.seed()
        a = random.randrange(int(tmin),int(tmax))
        return a
    
    # ///////////////////////////////////////////////////////////////////////
    
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
        
    # ///////////////////////////////////////////////////////////////////////
    
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
        
    # ///////////////////////////////////////////////////////////////////////
        
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
    
    def initSimple(self, hash, chainwork, limit=0):
        if((hash<=1) or (chainwork<=1)):
            return
        
        if self.bUseJustRandom :
            self.initSimpleNew(hash, chainwork, limit)
        else:
            self.initSimpleOld(hash, chainwork, limit)
        
        return
        
    # ///////////////////////////////////////////////////////////////////////
    
    def initSimpleNew(self, hash, chainwork, limit=0):
        self.currHPS = hash # multiply with 1000
        
        #mean_time = mean_hashes / (hashrate * 1e15)
        #time = int(block_time(mean_time) + 0.5)
        
        self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
        self.meanMiner += 1        
        
        if(limit>0):
            if(hash>limit):
                tRate = DEF_nTargetSpacing / self.meanMiner
                if(tRate<DEF_BLOCK_ARRAY_RATE):
                    TraceToFile(1, "[scenario] DOWN in scenario %d [%.2f]" % (limit,tRate))
                    hash /= 100 
                    self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
                    self.meanMiner += 1
                else:
                    TraceToFile(1, "[scenario] NORMAL in scenario %d [%.2f]" % (limit,tRate))
        
        TraceToFile(1, "\t %s : %s : setted_hps=%d : retrieved_mean=%d" % (self.strSMiner,self.strCMiner,hash,self.meanMiner))
    
    
    # ///////////////////////////////////////////////////////////////////////
     
    def initSimpleOld(self, hash, chainwork, limit=0):
        TraceToFile(1, "\n Get Miner Info with : hps = %f for chainwork=%f" % (hash, chainwork))
        
        if((hash<=1) or (chainwork<=1)):
            return
        
        self.currHPS = hash
        
        # get std count 
        tCountRate = DEF_UNSER_STD
        testNUM = random.randrange(0,DEF_RATE_STD_RANGE*1000*2)
        testNUM -= DEF_RATE_STD_RANGE*1000
        testNUM /= 1000
        tCountRate += testNUM
        TraceToFile(1, "\t tCountRate : %f" % (tCountRate))
        nowStdMaxCount = int(DEF_RANDOM_NUM_LIST_MAX * tCountRate)
        nowStdMaxCountRemain = DEF_RANDOM_NUM_LIST_MAX - nowStdMaxCount
        TraceToFile(1, "\t nowStdMaxCount : %d, nowStdMaxCountRemain : %d" % (nowStdMaxCount, nowStdMaxCountRemain))
        
        #get mean and sigma
        self.meanMiner = chainwork / (hash * DEF_GHPS_DIVIDED)
        testNUM = random.randrange(0,DEF_STD_RATE_OPT*2000)
        testNUM -= DEF_STD_RATE_OPT*1000
        testNUM /= 1000.
        stdRate = DEF_STD_RATE
        stdRate += testNUM        
        self.sigmaMiner = self.meanMiner * stdRate
        self.maxSigmaMiner = 5
        TraceToFile(1, "\t meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner))
        
        if (self.meanMiner < 5):
            self.meanMiner = 5
            self.sigmaMiner = 3
            TraceToFile(1, "\t NEW : meanMiner : %f, sigmaMiner : %f" % (self.meanMiner, self.sigmaMiner))
        
        #get list
        sigmaMIN = self.meanMiner - self.sigmaMiner
        if(sigmaMIN<1):
            sigmaMIN = 1
        sigmaMAX = self.meanMiner + self.sigmaMiner        
        
        expectedMin = 1
        expectedMax = self.meanMiner + self.maxSigmaMiner * self.sigmaMiner
        
        
        tmax = 0
        tNewAvg = self.meanMiner * stdRate * stdRate
        TraceToFile(1, "\t meanMiner : %f, meanMiner2 : %f" % (self.meanMiner, tNewAvg))
        TraceToFile(1, "\t sigmaMIN : %d, sigmaMAX : %d" % (sigmaMIN, sigmaMAX))
        TraceToFile(1, "\t expectedMin : %d, expectedMax : %d" % (expectedMin, expectedMax))
        tStepRange = self.meanMiner * 0.05
        TraceToFile(1, "\t expected TotAVg Ragne : %f : %f ~ %f" % (self.meanMiner, self.meanMiner-tStepRange, self.meanMiner+tStepRange))
        
        tList = []
        tValStd = 0
        tValStdCnt = 0
        tValTot = 0
        tValTotCnt = 0
    
        for i in range(DEF_RANDOM_NUM_LIST_MAX):
            if(i<nowStdMaxCount):
                gauNum = self.getRandomGaussianRange(sigmaMIN,sigmaMAX,tNewAvg,self.sigmaMiner)
                #gauNum = self.getRandom(sigmaMIN,sigmaMAX)
                #TraceToFile(1, "inner : %f" % (gauNum))
                #gauNum = int(gauNum)
                tValStd += gauNum
            else:
                gauNum = self.getRandomOuter(expectedMin,expectedMax,sigmaMIN,sigmaMAX,self.meanMiner)
                #gauNum = int(gauNum)
                #TraceToFile(1, "outer : %f" % (gauNum))
        
            tValTot += gauNum
            tList.append(gauNum)
        
        tCurrentMean = tValTot/DEF_RANDOM_NUM_LIST_MAX
        tTitle = "\t inner : %f" % (tValStd/nowStdMaxCount)
        TraceToFile(1, tTitle)
        #print tTitle
        tTitle = "\t Total : %f" % (tCurrentMean)
        TraceToFile(1, tTitle)
        #print tTitle        
        
        self.timeList = tList
        tValStd = 0
        for i in range(DEF_RANDOM_NUM_LIST_MAX):
            tValStd += self.timeList[i]
        tValStd /= DEF_RANDOM_NUM_LIST_MAX
        TraceToFile(1, "\t Final : %f" % (tValStd))       
            
        return       
    
    # ///////////////////////////////////////////////////////////////////////
    
    def setMinerName(self, sMiner, cMiner):
        self.strSMiner = sMiner
        self.strCMiner = cMiner
    
    # ///////////////////////////////////////////////////////////////////////
     
    def getMinerName(self, type=0):
        if(type==0):
            return self.strSMiner
        else:
            return self.strCMiner
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getCurrHPS(self):
        return float(self.currHPS)
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getTimeList(self):
        return self.timeList

    # ///////////////////////////////////////////////////////////////////////
    
    def getTime(self):
        nTime = 0.
        if self.bUseJustRandom :
            if(self.meanMiner>0):
                sample = random.random()
                lmbda = 1 / float(self.meanMiner)
                nTime = math.log(1 - sample) / -lmbda
                nTime += 1 
                return nTime
            else:
                return 9999
        else:
            index = random.randrange(0,DEF_RANDOM_NUM_LIST_MAX)
            index %= DEF_RANDOM_NUM_LIST_MAX
            nTime = self.timeList[index]
            nTime += 1
            return nTime
        
    # ///////////////////////////////////////////////////////////////////////
    
    def getTimeInt(self):
        return int(self.getTime())            

# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////

class classBlock:
    tBlock = []
    nIndex = 0
    nTime = 0
    nBits = 0x00000000
    signMiner = ""
    coinMiner = ""
    
    # ///////////////////////////////////////////////////////////////////////
    
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
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getBlockList(self):
        return tBlock
    
    # ///////////////////////////////////////////////////////////////////////
    
    def getItemsAsIndex(self, index):
        if (index>5 or index < 0):
            return -1
            
        return tBlock[index]


# ////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////


class blockTest:
    dbBlock = []
    listMiner = []
    listMinerModule = []
    dbBlockCount = 0
    listMinerInfoCount = 0
    fileListMiner = []
    fileListMinerCount = 0
    bUseFileListMiner = True
    nBIndexOffsetVsArray = 0
    bInitOk = False
    
    # ////////////////////////////////////////////////////////////////////////
    
    def __init__(self):
        newblock = classBlock()
        newblock.init(0,1526653949,0x1b4b0f40,"HGoH4m78d17sXLia4C8Ee3R3FTtCCuaPKs","HGoH4m78d17sXLia4C8Ee3R3FTtCCuaPKs")
        self.dbBlock.append(newblock)
        self.dbBlockCount = len(self.dbBlock)
        
        self.nBIndexOffsetVsArray = 0
        
        TraceToFile(1, ("GENESIS : %d,%d,%s,%s,%s") % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
        
        if self.bUseFileListMiner:
            bStatus = self.loadcsv(DEF_MINERLIST) 
            if not bStatus:
                TraceToFile(0, "Critical error in __INIT__")
                return    
        else:
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
        
    # ///////////////////////////////////////////////////////////////////////
    
    def read_csv(self, fname="", load=False):
        if(fname==""):
            return
        
        num  = 0
        with open(fname, 'r') as raw:
            wrapper = csv.reader(raw)
            for record in wrapper:
                if record:
                    items = []*2
                    items.append(record[0])
                    items.append(record[1])
                    
                    num += 1
                    
                    if load :
                        self.fileListMiner.append(items)
                        self.fileListMinerCount = num
        
        
        return num
    
    # ///////////////////////////////////////////////////////////////////////
    
    def loadcsv(self, fname):
        numItems = 0
        numItems = self.read_csv(fname, False)
        
        if (numItems < 1):
            return False
        
        numItems = self.read_csv(fname, True)
        
        newList = [] * numItems
        
        #set random hps, unit 1000
        # 0.1 ~ 10 T
        # 1 ~ 100, and multiply with 100
        
        for i in range(numItems):
            tList = []
            tList.append(self.fileListMiner[i][0])
            tList.append(self.fileListMiner[i][1])
            tNum = random.randrange(DEF_TEST_HPS_MIM,DEF_TEST_HPS_MAX)
            tNum *= 100
            tList.append(tNum)
            newList.append(tList)
        
        self.fileListMiner = []
        self.fileListMinerCount = 0
        
        self.fileListMiner = newList
        self.fileListMinerCount = len(self.fileListMiner)
        
        return True
        
    # ////////////////////////////////////////////////////////////////////////
    
    def getdifficulty(self, nBits):
        tModule = classPyDiff()
        return tModule.GetDifficulty(nBits)
        
        
    # ////////////////////////////////////////////////////////////////////////
    
    def GetNextWorkRequired(self):
        if not self.bInitOk:
            return 0
        
        tipBlock = self.GetTip()
        nBits = tipBlock.nBits
        
        tIndex = (tipBlock.nIndex + 1) % DEF_Interval
        if (tIndex> 0):
            return tipBlock.nBits
        
        TraceToFile(1, "\ncheck here")
        TraceToFile(1, "tipBlock.nIndex = %d" % (tipBlock.nIndex))
        TraceToFile(1, "tipBlock.nTimenTime = %d" % (tipBlock.nTime))
        
        arrayHeight = tipBlock.nIndex - self.nBIndexOffsetVsArray        
        
        firstBlock = self.dbBlock[int(arrayHeight + 1 -DEF_Interval)]
        
        TraceToFile(1, "firstBlock.nIndex = %d" % (firstBlock.nIndex))
        TraceToFile(1, "firstBlock.nTimenTime = %d" % (firstBlock.nTime))
        
        nActualTimespan = tipBlock.nTime - firstBlock.nTime
        
        tModule = classPyDiff()
        nBits = tModule.GetNextWorkRequired(tipBlock.nBits, int(nActualTimespan))
        
        return nBits
    
    
    # ////////////////////////////////////////////////////////////////////////
    
    def GetChainwork(self, nBits):
        if not self.bInitOk:
            return 0
            
        tModule = classPyDiff()
        diffCW = tModule.GetBlockProofTemp(nBits)
        
        return diffCW
    
    # ////////////////////////////////////////////////////////////////////////
    
    def GetTip(self):
        if not self.bInitOk:
            return 0
        
        tNum = len(self.dbBlock)
        tipBlock = self.dbBlock[tNum-1]
        return tipBlock
    
    # ///////////////////////////////////////////////////////////////////////

    def initMinerWithCW(self, chainwork, limit=0):
        if not self.bInitOk:
            return False
        
        TraceToFile(0,"\n INIT Miner Info : START")
        
        self.listMinerModule[:] = []
        
        if self.bUseFileListMiner:
            for i in range(self.fileListMinerCount):
                tMinerModule = classMiner()
                tMinerModule.setMinerName(self.fileListMiner[i][0], self.fileListMiner[i][1])
                tMinerModule.initSimple(self.fileListMiner[i][2], chainwork, limit)
                self.listMinerModule.append(tMinerModule)
        else:
            for i in range(self.listMinerInfoCount):
                tMinerModule = classMiner()
                tMinerModule.setMinerName(self.listMiner[i][0], self.listMiner[i][1])
                tMinerModule.initSimple(self.listMiner[i][2], chainwork, limit)
                self.listMinerModule.append(tMinerModule)
        
        TraceToFile(0," INIT Miner Info : END\n")
        
        return True

    # ////////////////////////////////////////////////////////////////////////
    
    def GetMinerAndTimeForChainwork(self, chainwork):
        if not self.bInitOk:
            return False
        
        tValList = []
        
        if self.bUseFileListMiner:
            for i in range(self.fileListMinerCount):
                tMiner = self.listMinerModule[i]
                tList = []
                tList.append(tMiner.getMinerName(0))
                tList.append(tMiner.getMinerName(1))
                tList.append(tMiner.getCurrHPS())
                tList.append(tMiner.getTime())
                tValList.append(tList)            
                #TraceToFile(1, "%s,%s,%f,%f"%(tList[0],tList[1],tList[2],tList[3]))
                
            for i in range(self.fileListMinerCount):
                for j in range(i, self.fileListMinerCount, 1):
                    if(tValList[i][3]>tValList[j][3]):
                        tStoreList = tValList[i]
                        tValList[i]= tValList[j]
                        tValList[j] = tStoreList
            
            for i in range(self.fileListMinerCount):
                TraceToFile(1, "%s,%s,%f,%f"%(tValList[i][0],tValList[i][1],tValList[i][2],tValList[i][3]))            
                
        else:
            for i in range(self.listMinerInfoCount):
                tMiner = self.listMinerModule[i]
                tList = []
                tList.append(tMiner.getMinerName(0))
                tList.append(tMiner.getMinerName(1))
                tList.append(tMiner.getCurrHPS())
                tList.append(tMiner.getTime())
                tValList.append(tList)            
                #TraceToFile(1, "%s,%s,%f,%f"%(tList[0],tList[1],tList[2],tList[3]))
            
            for i in range(self.listMinerInfoCount):
                for j in range(i, self.listMinerInfoCount, 1):
                    if(tValList[i][3]>tValList[j][3]):
                        tStoreList = tValList[i]
                        tValList[i]= tValList[j]
                        tValList[j] = tStoreList
            
            for i in range(self.listMinerInfoCount):
                TraceToFile(1, "%s,%s,%f,%f"%(tValList[i][0],tValList[i][1],tValList[i][2],tValList[i][3]))            
        
        
        return tValList

    # ////////////////////////////////////////////////////////////////////////
    
    def makeNewBlock(self, nTime, nBits, signMiner, coinMiner):
        if not self.bInitOk:
            return ""
        
        tipBlock = self.GetTip()
        newIndex = tipBlock.nIndex + 1 
        nTime += tipBlock.nTime
        TraceToFile(1, "new block : %d,%s,%s,%s"%(nTime,int2hex(nBits),signMiner,coinMiner))
        newblock = classBlock()        
        newblock.init(newIndex, nTime, nBits, signMiner, coinMiner)
        
        return newblock
    
    # ////////////////////////////////////////////////////////////////////////
    
    def acceptNewBlock(self, newBlock):
        if not self.bInitOk:
            return False
        
        tipblock = self.GetTip()
        if(newBlock.nIndex<=tipblock.nIndex):
            TraceToFile(0,"ABNORMAL CASE : blockTest : addNewBlock : %d vs %d" % (newBlock.nIndex, tipblock.nIndex))
            return False
        
        self.dbBlock.append(newBlock)
        TraceToFile(0, "ACCEPT")
        
        tDiff = self.getdifficulty(newBlock.nBits)
        tChainwork = self.GetChainwork(newBlock.nBits)
        tTime = newBlock.nTime - tipblock.nTime
        TraceToFile(2, "%d,%d,%s,%s,%s,%.2f,%d,%d" % (newBlock.nIndex,newBlock.nTime,int2hex(newBlock.nBits),newBlock.signMiner,newBlock.coinMiner,tDiff,tChainwork,tTime))
        
        tLen = len(self.dbBlock)
        if (tLen>=DEF_BLOCK_ARRAY_MAX):
            tNewBlock = []
            for i in range(DEF_BLOCK_ARRAY_LIMIT,DEF_BLOCK_ARRAY_MAX,1):
                tNewBlock.append(self.dbBlock[i])
            
            self.dbBlock = []
            self.dbBlock = tNewBlock
            self.nBIndexOffsetVsArray += DEF_BLOCK_ARRAY_LIMIT
            TraceToFile(1, "block db updated, index offset = %d" % (self.nBIndexOffsetVsArray))
            TraceToFile(1, "start index = %d" % (self.dbBlock[0].nIndex))
            TraceToFile(1, "start index = %d" % (self.dbBlock[DEF_BLOCK_ARRAY_LIMIT-1].nIndex))
            
            
        return True

    # ///////////////////////////////////////////////////////////////////////
    
    def GetMiningDepth(self,miner):
        if not self.bInitOk:
            return -1

        miningDepth = -1
        maxDepth = DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        maxDepth = min(maxDepth, tipHeight-self.nBIndexOffsetVsArray)
        
        for i in range(maxDepth):
            checkBlock = self.dbBlock[tipHeight-self.nBIndexOffsetVsArray-i]
            if(checkBlock.coinMiner == miner):
                miningDepth = i
        
        TraceToFile(1, "GetMiningDepth : miningDepth : %d"%(miningDepth))
        
        return miningDepth

    # ////////////////////////////////////////////////////////////////////////
    
    def GetMiningContinuity(self,miner):
        if not self.bInitOk:
            return -1
        
        miningContinuity = 0
        maxDepth = DEF_MAX_MINING_DEPTH_OF_BLOCKWINDOW
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        maxDepth = min(maxDepth, tipHeight-self.nBIndexOffsetVsArray)

        for i in range(maxDepth):
            checkBlock = self.dbBlock[tipHeight-self.nBIndexOffsetVsArray-i]
            if(checkBlock.coinMiner == miner):
                miningContinuity += 1
            else:
                break;
        
        TraceToFile(1, "GetMiningContinuity : miningContinuity : %d"%(miningContinuity))
        
        return miningContinuity

    # ////////////////////////////////////////////////////////////////////////
    
    def GetNodeFactor(self,depth):
        if not self.bInitOk:
            return -1
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        
        depth = min(depth, tipHeight-self.nBIndexOffsetVsArray)
        
        tList = []
        for i in range(depth):
            checkBlock = self.dbBlock[tipHeight-self.nBIndexOffsetVsArray-i]
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
        
        TraceToFile(1, "GetNodeFactor: nf : %d"%(len(tList)))
                
        return len(tList)       

    # ////////////////////////////////////////////////////////////////////////
    
    def GetBlockWindowSize(self,miner):
        if not self.bInitOk:
            return -1
        
        tipblock = self.GetTip()
        tipHeight = tipblock.nIndex
        
        blockWz = 0
        depth = 480
        
        depth = min(depth, tipHeight-self.nBIndexOffsetVsArray)
        
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
        
        TraceToFile(1, "GetBlockWindowSize : blockWz = %f"%(blockWz))
        
        return blockWz        

    # ////////////////////////////////////////////////////////////////////////
    
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

    # ////////////////////////////////////////////////////////////////////////
    
    def VerifyBlockWindow(self,newblock):
        TraceToFile(1, "VerifyBlockWindow : coinMiner : %s"%(newblock.coinMiner))
        return self.CheckBlockWindow(newblock.coinMiner)
        
    # ///////////////////////////////////////////////////////////////////////

    def doTest(self, testMax=1000, indexLimit=9999, hpsLimit=0):
        if not self.bInitOk:
            return False
        
        TraceToFile(0, "\n INIT ###################################################")
        
        nPreBits = self.GetNextWorkRequired()
        nPrechainwork = self.GetChainwork(nPreBits)
        
        TraceToFile(0, "\n START ###################################################")
        
        bStatus = self.initMinerWithCW(nPrechainwork)
        if not bStatus:
            return
        
        TraceToFile(0, "cur nbits : %s" % (int2hex(nPreBits)))
        
        for i in range(testMax):#DEF_BLOCK_TEST_MAX
            tipblock = self.GetTip()
            tipHeight = tipblock.nIndex
            nNewBits = self.GetNextWorkRequired()
            #print "%s" % (int2hex(nNewBits))
            
            if(nNewBits==nPreBits):
                tValList = self.GetMinerAndTimeForChainwork(nPrechainwork)
                if(len(tValList)<1):
                    print ("strange. break")
                    break
            
            else:
                nPreBits = nNewBits
                nPrechainwork = self.GetChainwork(nPreBits)
                if (indexLimit<tipblock.nIndex):
                    TraceToFile(0, "\n\n[scenario]Go with Scenario : %d, %d \n\n" % (indexLimit, hpsLimit))
                    bStatus = self.initMinerWithCW(nPrechainwork, hpsLimit)
                    if not bStatus:
                        print("strange. break")
                        break
                else:
                    bStatus = self.initMinerWithCW(nPrechainwork, 0)
                    if not bStatus:
                        print("strange. break")
                        break
                        
                tValList = self.GetMinerAndTimeForChainwork(nPrechainwork)
                if(len(tValList)<1):
                    print("strange. break")
                    break
                    
                TraceToFile(0, "updated nbits : %s" % (int2hex(nPreBits)))
                
            bFound = False 
            bCont = True
            j = 0
            newblock = self.makeNewBlock(tValList[j][3],nNewBits,tValList[j][0],tValList[j][1])
            while (not bFound and bCont):
                TraceToFile(0, "\nTRY : %d,%d,%s,%s,%s" % (newblock.nIndex,newblock.nTime,int2hex(newblock.nBits),newblock.signMiner,newblock.coinMiner))
                if self.VerifyBlockWindow(newblock):
                    bFound = True
                else:
                    TraceToFile(0, "REJECT")
                j += 1
                if (j >= len(tValList)):
                    bCont = False
                
            if(bFound):
                self.acceptNewBlock(newblock)
            
            time.sleep(0.05)

        TraceToFile(0, "\n END ###################################################") 


# ///////////////////////////////////////////////////////////////////////
# Test //////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////
# Test
def Test(testMax=1000, index=9999, hps=0):
    time_start = time.time()
    
    newTest = blockTest()
    newTest.doTest(testMax, index, hps)
    
    time_end = time.time()
    time_diff = time_end - time_start
    
    TraceToFile(0,"\n TEST Ended. during %d seconds" % (time_diff))
    
# ///////////////////////////////////////////////////////////////////////
# main //////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////
# Main
def main():
    Test(150000, 100000, 1000)
    return


# ////////////////////////////////////////////////////////////////////////
# Main END
# ////////////////////////////////////////////////////////////////////////

if __name__ == "__main__":
    main()
