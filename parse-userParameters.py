#!/usr/bin/python
#
# UserParameters (TSProperties) AD encoded blob decoder
#
# original PS version by HarmJ0y:
# https://gist.github.com/HarmJ0y/08ee1824aa555598cff5efa4c5c96cf0
#

import sys
import re
import json
from struct import unpack

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/15f8b01d-900d-4f89-a3fa-1681e55f383d
class UserParameters:
    params = {}

    _attribGroup1 = ["CtxCfgPresent", "CtxCfgFlags1", "CtxCallBack", "CtxKeyboardLayout", "CtxMinEncryptionLevel",
                     "CtxNWLogonServer", "CtxMaxConnectionTime", "CtxMaxDisconnectionTime", "CtxMaxIdleTime",
                     "CtxShadow", "CtxMinEncryptionLevel"]
    _attribGroup2 = ["CtxWFHomeDirDrive", "CtxWFHomeDir", "CtxWFHomeDrive", "CtxInitialProgram", "CtxWFProfilePath",
                     "CtxWorkDirectory", "CtxCallbackNumber"]

    # values from https://msdn.microsoft.com/en-us/library/ff635169.aspx
    _ctxCfgFlagsBitValues = {
        'INHERITCALLBACK': 0x08000000,
        'INHERITCALLBACKNUMBER': 0x04000000,
        'INHERITSHADOW': 0x02000000,
        'INHERITMAXSESSIONTIME': 0x01000000,
        'INHERITMAXDISCONNECTIONTIME': 0x00800000,
        'INHERITMAXIDLETIME': 0x00400000,
        'INHERITAUTOCLIENT': 0x00200000,
        'INHERITSECURITY': 0x00100000,
        'PROMPTFORPASSWORD': 0x00080000,
        'RESETBROKEN': 0x00040000,
        'RECONNECTSAME': 0x00020000,
        'LOGONDISABLED': 0x00010000,
        'AUTOCLIENTDRIVES': 0x00008000,
        'AUTOCLIENTLPTS': 0x00004000,
        'FORCECLIENTLPTDEF': 0x00002000,
        'DISABLEENCRYPTION': 0x00001000,
        'HOMEDIRECTORYMAPROOT': 0x00000800,
        'USEDEFAULTGINA': 0x00000400,
        'DISABLECPM': 0x00000200,
        'DISABLECDM': 0x00000100,
        'DISABLECCM': 0x00000080,
        'DISABLELPT': 0x00000040,
        'DISABLECLIP': 0x00000020,
        'DISABLEEXE': 0x00000010,
        'WALLPAPERDISABLED': 0x00000008,
        'DISABLECAM': 0x00000004
    }
    
    def __init__(self, blob, verbose=False):
        self._verbose = verbose
        self._populate(blob)

    def _log(self, msg):
        if(self._verbose):
            print(msg)
        
    def _populate(self, blob):
        # [0-95] -> reserved
        # [96-97] -> 2 bytes signature (==80)
        self.params['signature'] = unpack('<H', blob[96:98])[0]
        if(self.params['signature'] == 80):
            self._log("[*] Signature match")
        else:
            self._log("[!] Signature error")

        # [98-99] -> number of attributes
        numAttribs = unpack('<H', blob[98:100])[0]
        self._log("[+] Number of attributes found in blob: %d" % numAttribs)
        
        # parse attributes
        p = 100
        #numAttribs = 1 # debug
        for i in range(numAttribs):
            nameLength = unpack('<H', blob[p:p+2])[0]
            p += 2
            self._log("[+] NameLength: %d" % nameLength)
            valueLength = unpack('<H', blob[p:p+2])[0]
            p += 2
            self._log("[+] ValueLength: %d" % valueLength)
            typeValue = unpack('<H', blob[p:p+2])[0]
            p += 2
            self._log("[+] Type: %d" % typeValue)
            attributeName = blob[p:p+nameLength].decode('utf16')
            p += nameLength
            self._log("[+] AttributeName: %s" % attributeName)
            attributeData = blob[p:p+valueLength]
            p += valueLength
            if attributeName in self._attribGroup1:
                if valueLength == 8:
                    s = "<I"
                elif valueLength == 2:
                    s = "<B"
                attributeValue = unpack(s, bytes.fromhex(attributeData.decode()))[0]
                if(attributeName == "CtxShadow"):
                    switcher = {
                        0x0: 'Disable',
                        0x1: 'EnableInputNotify',
                        0x2: 'EnableInputNoNotify',
                        0x3: 'EnableNoInputNotify',
                        0x4: 'EnableNoInputNoNotify'
                    }
                    attributeValue = switcher.get(attributeValue, attributeValue)
                elif(attributeName == "CtxCfgFlags1"):
                    attributeValueArray = []
                    for key in self._ctxCfgFlagsBitValues:
                        if((attributeValue & self._ctxCfgFlagsBitValues[key]) == self._ctxCfgFlagsBitValues[key]):
                            attributeValueArray.append(key)
                    attributeValue = attributeValueArray
                else:
                    attributeValue = hex(attributeValue)
            elif attributeName in self._attribGroup2:
                attributeValue = bytes.fromhex(attributeData.decode()).decode()

            self.params[attributeName] = attributeValue
            self._log("[+] AttributeValue: %s" % attributeValue)
                
if __name__ == "__main__":
    b = []
    for line in sys.stdin:
        b.extend(re.findall(r" ([0-9a-fA-F][0-9a-fA-F])", line.rstrip())[:16])

    blob = bytes.fromhex(''.join(b))

    myObj = UserParameters(blob, verbose=False)
    print(json.dumps(myObj.params, indent=2))

