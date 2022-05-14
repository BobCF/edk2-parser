## @file
# Common routines used by all tools
#
# Copyright (c) 2007 - 2019, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

##
# Import Modules
#
import string
import re
from random import sample
import uuid
import subprocess
from collections import OrderedDict

import Common.LongFilePathOs as os
from Common import EdkLogger as EdkLogger
from Common import GlobalData as GlobalData
from Common.DataType import (
    TAB_UINT8,
    TAB_UINT16,
    TAB_UINT32,
    TAB_UINT64,
    TAB_VOID,
    TAB_GUID,
    TAB_VALUE_SPLIT,
    TAB_PRINTCHAR_VT,
    TAB_PRINTCHAR_NUL,
    TAB_PRINTCHAR_BS,
    MAX_VAL_TYPE
)
from Common.BuildToolError import (
    FORMAT_INVALID,
    FILE_TYPE_MISMATCH,
    FILE_NOT_FOUND,
    FILE_CASE_MISMATCH
)
from CommonDataClass.DataClass import (
    MODEL_PCD_DYNAMIC_EX_DEFAULT,
    MODEL_PCD_DYNAMIC_DEFAULT,
    MODEL_PCD_FEATURE_FLAG,
    MODEL_PCD_DYNAMIC_VPD,
    MODEL_PCD_DYNAMIC_EX_VPD,
    MODEL_PCD_DYNAMIC_EX_HII,
    MODEL_PCD_DYNAMIC_HII,
    MODEL_PCD_FIXED_AT_BUILD,
    MODEL_PCD_PATCHABLE_IN_MODULE
)
from Common.MultipleWorkspace import MultipleWorkspace as mws
from CommonDataClass.Exceptions import BadExpression
import struct

StructPattern = re.compile(r'[_a-zA-Z][0-9A-Za-z_]*$')

## Convert GUID string in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx style to C structure style
#
#   @param      Guid    The GUID string
#
#   @retval     string  The GUID string in C structure style
#
def GuidStringToGuidStructureString(Guid):
    GuidList = Guid.split('-')
    Result = '{'
    for Index in range(0, 3, 1):
        Result = Result + '0x' + GuidList[Index] + ', '
    Result = Result + '{0x' + GuidList[3][0:2] + ', 0x' + GuidList[3][2:4]
    for Index in range(0, 12, 2):
        Result = Result + ', 0x' + GuidList[4][Index:Index + 2]
    Result += '}}'
    return Result

## Convert GUID structure in byte array to xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
#
#   @param      GuidValue   The GUID value in byte array
#
#   @retval     string      The GUID value in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format
#
def GuidStructureByteArrayToGuidString(GuidValue):
    guidValueString = GuidValue.lower().replace("{", "").replace("}", "").replace(" ", "").replace(";", "")
    guidValueList = guidValueString.split(",")
    if len(guidValueList) != 16:
        return ''
        #EdkLogger.error(None, None, "Invalid GUID value string %s" % GuidValue)
    try:
        return "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
                int(guidValueList[3], 16),
                int(guidValueList[2], 16),
                int(guidValueList[1], 16),
                int(guidValueList[0], 16),
                int(guidValueList[5], 16),
                int(guidValueList[4], 16),
                int(guidValueList[7], 16),
                int(guidValueList[6], 16),
                int(guidValueList[8], 16),
                int(guidValueList[9], 16),
                int(guidValueList[10], 16),
                int(guidValueList[11], 16),
                int(guidValueList[12], 16),
                int(guidValueList[13], 16),
                int(guidValueList[14], 16),
                int(guidValueList[15], 16)
                )
    except:
        return ''

## Convert GUID string in C structure style to xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
#
#   @param      GuidValue   The GUID value in C structure format
#
#   @retval     string      The GUID value in xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format
#
def GuidStructureStringToGuidString(GuidValue):
    if not GlobalData.gGuidCFormatPattern.match(GuidValue):
        return ''
    guidValueString = GuidValue.lower().replace("{", "").replace("}", "").replace(" ", "").replace(";", "")
    guidValueList = guidValueString.split(",")
    if len(guidValueList) != 11:
        return ''
        #EdkLogger.error(None, None, "Invalid GUID value string %s" % GuidValue)
    try:
        return "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % (
                int(guidValueList[0], 16),
                int(guidValueList[1], 16),
                int(guidValueList[2], 16),
                int(guidValueList[3], 16),
                int(guidValueList[4], 16),
                int(guidValueList[5], 16),
                int(guidValueList[6], 16),
                int(guidValueList[7], 16),
                int(guidValueList[8], 16),
                int(guidValueList[9], 16),
                int(guidValueList[10], 16)
                )
    except:
        return ''

## Convert GUID string in C structure style to xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx
#
#   @param      GuidValue   The GUID value in C structure format
#
#   @retval     string      The GUID value in xxxxxxxx_xxxx_xxxx_xxxx_xxxxxxxxxxxx format
#
def GuidStructureStringToGuidValueName(GuidValue):
    guidValueString = GuidValue.lower().replace("{", "").replace("}", "").replace(" ", "")
    guidValueList = guidValueString.split(",")
    if len(guidValueList) != 11:
        EdkLogger.error(None, FORMAT_INVALID, "Invalid GUID value string [%s]" % GuidValue)
    return "%08x_%04x_%04x_%02x%02x_%02x%02x%02x%02x%02x%02x" % (
            int(guidValueList[0], 16),
            int(guidValueList[1], 16),
            int(guidValueList[2], 16),
            int(guidValueList[3], 16),
            int(guidValueList[4], 16),
            int(guidValueList[5], 16),
            int(guidValueList[6], 16),
            int(guidValueList[7], 16),
            int(guidValueList[8], 16),
            int(guidValueList[9], 16),
            int(guidValueList[10], 16)
            )

def AnalyzePcdExpression(Setting):
    RanStr = ''.join(sample(string.ascii_letters + string.digits, 8))
    Setting = Setting.replace('\\\\', RanStr).strip()
    # There might be escaped quote in a string: \", \\\" , \', \\\'
    Data = Setting
    # There might be '|' in string and in ( ... | ... ), replace it with '-'
    NewStr = ''
    InSingleQuoteStr = False
    InDoubleQuoteStr = False
    Pair = 0
    for Index, ch in enumerate(Data):
        if ch == '"' and not InSingleQuoteStr:
            if Data[Index - 1] != '\\':
                InDoubleQuoteStr = not InDoubleQuoteStr
        elif ch == "'" and not InDoubleQuoteStr:
            if Data[Index - 1] != '\\':
                InSingleQuoteStr = not InSingleQuoteStr
        elif ch == '(' and not (InSingleQuoteStr or InDoubleQuoteStr):
            Pair += 1
        elif ch == ')' and not (InSingleQuoteStr or InDoubleQuoteStr):
            Pair -= 1

        if (Pair > 0 or InSingleQuoteStr or InDoubleQuoteStr) and ch == TAB_VALUE_SPLIT:
            NewStr += '-'
        else:
            NewStr += ch
    FieldList = []
    StartPos = 0
    while True:
        Pos = NewStr.find(TAB_VALUE_SPLIT, StartPos)
        if Pos < 0:
            FieldList.append(Setting[StartPos:].strip())
            break
        FieldList.append(Setting[StartPos:Pos].strip())
        StartPos = Pos + 1
    for i, ch in enumerate(FieldList):
        if RanStr in ch:
            FieldList[i] = ch.replace(RanStr,'\\\\')
    return FieldList

def ParseFieldValue (Value):
    def ParseDevPathValue (Value):
        if '\\' in Value:
            Value.replace('\\', '/').replace(' ', '')

        Cmd = 'DevicePath ' + '"' + Value + '"'
        try:
            p = subprocess.Popen(Cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            out, err = p.communicate()
        except Exception as X:
            raise BadExpression("DevicePath: %s" % (str(X)) )
        finally:
            subprocess._cleanup()
            p.stdout.close()
            p.stderr.close()
        if err:
            raise BadExpression("DevicePath: %s" % str(err))
        out = out.decode()
        Size = len(out.split())
        out = ','.join(out.split())
        return '{' + out + '}', Size

    if "{CODE(" in Value:
        return Value, len(Value.split(","))
    if isinstance(Value, type(0)):
        return Value, (Value.bit_length() + 7) // 8
    if not isinstance(Value, type('')):
        raise BadExpression('Type %s is %s' %(Value, type(Value)))
    Value = Value.strip()
    if Value.startswith(TAB_UINT8) and Value.endswith(')'):
        Value, Size = ParseFieldValue(Value.split('(', 1)[1][:-1])
        if Size > 1:
            raise BadExpression('Value (%s) Size larger than %d' %(Value, Size))
        return Value, 1
    if Value.startswith(TAB_UINT16) and Value.endswith(')'):
        Value, Size = ParseFieldValue(Value.split('(', 1)[1][:-1])
        if Size > 2:
            raise BadExpression('Value (%s) Size larger than %d' %(Value, Size))
        return Value, 2
    if Value.startswith(TAB_UINT32) and Value.endswith(')'):
        Value, Size = ParseFieldValue(Value.split('(', 1)[1][:-1])
        if Size > 4:
            raise BadExpression('Value (%s) Size larger than %d' %(Value, Size))
        return Value, 4
    if Value.startswith(TAB_UINT64) and Value.endswith(')'):
        Value, Size = ParseFieldValue(Value.split('(', 1)[1][:-1])
        if Size > 8:
            raise BadExpression('Value (%s) Size larger than %d' % (Value, Size))
        return Value, 8
    if Value.startswith(TAB_GUID) and Value.endswith(')'):
        Value = Value.split('(', 1)[1][:-1].strip()
        if Value[0] == '{' and Value[-1] == '}':
            TmpValue = GuidStructureStringToGuidString(Value)
            if not TmpValue:
                raise BadExpression("Invalid GUID value string %s" % Value)
            Value = TmpValue
        if Value[0] == '"' and Value[-1] == '"':
            Value = Value[1:-1]
        try:
            Value = uuid.UUID(Value).bytes_le
            ValueL, ValueH = struct.unpack('2Q', Value)
            Value = (ValueH << 64 ) | ValueL

        except ValueError as Message:
            raise BadExpression(Message)
        return Value, 16
    if Value.startswith('L"') and Value.endswith('"'):
        # Unicode String
        # translate escape character
        Value = Value[1:]
        try:
            Value = eval(Value)
        except:
            Value = Value[1:-1]
        List = list(Value)
        List.reverse()
        Value = 0
        for Char in List:
            Value = (Value << 16) | ord(Char)
        return Value, (len(List) + 1) * 2
    if Value.startswith('"') and Value.endswith('"'):
        # ASCII String
        # translate escape character
        try:
            Value = eval(Value)
        except:
            Value = Value[1:-1]
        List = list(Value)
        List.reverse()
        Value = 0
        for Char in List:
            Value = (Value << 8) | ord(Char)
        return Value, len(List) + 1
    if Value.startswith("L'") and Value.endswith("'"):
        # Unicode Character Constant
        # translate escape character
        Value = Value[1:]
        try:
            Value = eval(Value)
        except:
            Value = Value[1:-1]
        List = list(Value)
        if len(List) == 0:
            raise BadExpression('Length %s is %s' % (Value, len(List)))
        List.reverse()
        Value = 0
        for Char in List:
            Value = (Value << 16) | ord(Char)
        return Value, len(List) * 2
    if Value.startswith("'") and Value.endswith("'"):
        # Character constant
        # translate escape character
        try:
            Value = eval(Value)
        except:
            Value = Value[1:-1]
        List = list(Value)
        if len(List) == 0:
            raise BadExpression('Length %s is %s' % (Value, len(List)))
        List.reverse()
        Value = 0
        for Char in List:
            Value = (Value << 8) | ord(Char)
        return Value, len(List)
    if Value.startswith('{') and Value.endswith('}'):
        # Byte array
        Value = Value[1:-1]
        List = [Item.strip() for Item in Value.split(',')]
        List.reverse()
        Value = 0
        RetSize = 0
        for Item in List:
            ItemValue, Size = ParseFieldValue(Item)
            RetSize += Size
            for I in range(Size):
                Value = (Value << 8) | ((ItemValue >> 8 * I) & 0xff)
        return Value, RetSize
    if Value.startswith('DEVICE_PATH(') and Value.endswith(')'):
        Value = Value.replace("DEVICE_PATH(", '').rstrip(')')
        Value = Value.strip().strip('"')
        return ParseDevPathValue(Value)
    if Value.lower().startswith('0x'):
        try:
            Value = int(Value, 16)
        except:
            raise BadExpression("invalid hex value: %s" % Value)
        if Value == 0:
            return 0, 1
        return Value, (Value.bit_length() + 7) // 8
    if Value[0].isdigit():
        Value = int(Value, 10)
        if Value == 0:
            return 0, 1
        return Value, (Value.bit_length() + 7) // 8
    if Value.lower() == 'true':
        return 1, 1
    if Value.lower() == 'false':
        return 0, 1
    return Value, 1

## AnalyzeDscPcd
#
#  Analyze DSC PCD value, since there is no data type info in DSC
#  This function is used to match functions (AnalyzePcdData) used for retrieving PCD value from database
#  1. Feature flag: TokenSpace.PcdCName|PcdValue
#  2. Fix and Patch:TokenSpace.PcdCName|PcdValue[|VOID*[|MaxSize]]
#  3. Dynamic default:
#     TokenSpace.PcdCName|PcdValue[|VOID*[|MaxSize]]
#     TokenSpace.PcdCName|PcdValue
#  4. Dynamic VPD:
#     TokenSpace.PcdCName|VpdOffset[|VpdValue]
#     TokenSpace.PcdCName|VpdOffset[|MaxSize[|VpdValue]]
#  5. Dynamic HII:
#     TokenSpace.PcdCName|HiiString|VariableGuid|VariableOffset[|HiiValue]
#  PCD value needs to be located in such kind of string, and the PCD value might be an expression in which
#    there might have "|" operator, also in string value.
#
#  @param Setting: String contain information described above with "TokenSpace.PcdCName|" stripped
#  @param PcdType: PCD type: feature, fixed, dynamic default VPD HII
#  @param DataType: The datum type of PCD: VOID*, UNIT, BOOL
#  @retval:
#    ValueList: A List contain fields described above
#    IsValid:   True if conforming EBNF, otherwise False
#    Index:     The index where PcdValue is in ValueList
#
def AnalyzeDscPcd(Setting, PcdType, DataType=''):
    FieldList = AnalyzePcdExpression(Setting)

    IsValid = True
    if PcdType in (MODEL_PCD_FIXED_AT_BUILD, MODEL_PCD_PATCHABLE_IN_MODULE, MODEL_PCD_DYNAMIC_DEFAULT, MODEL_PCD_DYNAMIC_EX_DEFAULT):
        Value = FieldList[0]
        Size = ''
        if len(FieldList) > 1 and FieldList[1]:
            DataType = FieldList[1]
            if FieldList[1] != TAB_VOID and StructPattern.match(FieldList[1]) is None:
                IsValid = False
        if len(FieldList) > 2:
            Size = FieldList[2]
        if IsValid:
            if DataType == "":
                IsValid = (len(FieldList) <= 1)
            else:
                IsValid = (len(FieldList) <= 3)

        if Size:
            try:
                int(Size, 16) if Size.upper().startswith("0X") else int(Size)
            except:
                IsValid = False
                Size = -1
        return [str(Value), DataType, str(Size)], IsValid, 0
    elif PcdType == MODEL_PCD_FEATURE_FLAG:
        Value = FieldList[0]
        Size = ''
        IsValid = (len(FieldList) <= 1)
        return [Value, DataType, str(Size)], IsValid, 0
    elif PcdType in (MODEL_PCD_DYNAMIC_VPD, MODEL_PCD_DYNAMIC_EX_VPD):
        VpdOffset = FieldList[0]
        Value = Size = ''
        if not DataType == TAB_VOID:
            if len(FieldList) > 1:
                Value = FieldList[1]
        else:
            if len(FieldList) > 1:
                Size = FieldList[1]
            if len(FieldList) > 2:
                Value = FieldList[2]
        if DataType == "":
            IsValid = (len(FieldList) <= 1)
        else:
            IsValid = (len(FieldList) <= 3)
        if Size:
            try:
                int(Size, 16) if Size.upper().startswith("0X") else int(Size)
            except:
                IsValid = False
                Size = -1
        return [VpdOffset, str(Size), Value], IsValid, 2
    elif PcdType in (MODEL_PCD_DYNAMIC_HII, MODEL_PCD_DYNAMIC_EX_HII):
        IsValid = (3 <= len(FieldList) <= 5)
        HiiString = FieldList[0]
        Guid = Offset = Value = Attribute = ''
        if len(FieldList) > 1:
            Guid = FieldList[1]
        if len(FieldList) > 2:
            Offset = FieldList[2]
        if len(FieldList) > 3:
            Value = FieldList[3]
        if len(FieldList) > 4:
            Attribute = FieldList[4]
        return [HiiString, Guid, Offset, Value, Attribute], IsValid, 3
    return [], False, 0

## AnalyzePcdData
#
#  Analyze the pcd Value, Datum type and TokenNumber.
#  Used to avoid split issue while the value string contain "|" character
#
#  @param[in] Setting:  A String contain value/datum type/token number information;
#
#  @retval   ValueList: A List contain value, datum type and toke number.
#
def AnalyzePcdData(Setting):
    ValueList = ['', '', '']

    ValueRe = re.compile(r'^\s*L?\".*\|.*\"')
    PtrValue = ValueRe.findall(Setting)

    ValueUpdateFlag = False

    if len(PtrValue) >= 1:
        Setting = re.sub(ValueRe, '', Setting)
        ValueUpdateFlag = True

    TokenList = Setting.split(TAB_VALUE_SPLIT)
    ValueList[0:len(TokenList)] = TokenList

    if ValueUpdateFlag:
        ValueList[0] = PtrValue[0]

    return ValueList

## check format of PCD value against its the datum type
#
# For PCD value setting
#
def CheckPcdDatum(Type, Value):
    if Type == TAB_VOID:
        ValueRe = re.compile(r'\s*L?\".*\"\s*$')
        if not (((Value.startswith('L"') or Value.startswith('"')) and Value.endswith('"'))
                or (Value.startswith('{') and Value.endswith('}')) or (Value.startswith("L'") or Value.startswith("'") and Value.endswith("'"))
               ):
            return False, "Invalid value [%s] of type [%s]; must be in the form of {...} for array"\
                          ", \"...\" or \'...\' for string, L\"...\" or L\'...\' for unicode string" % (Value, Type)
        elif ValueRe.match(Value):
            # Check the chars in UnicodeString or CString is printable
            if Value.startswith("L"):
                Value = Value[2:-1]
            else:
                Value = Value[1:-1]
            Printset = set(string.printable)
            Printset.remove(TAB_PRINTCHAR_VT)
            Printset.add(TAB_PRINTCHAR_BS)
            Printset.add(TAB_PRINTCHAR_NUL)
            if not set(Value).issubset(Printset):
                PrintList = sorted(Printset)
                return False, "Invalid PCD string value of type [%s]; must be printable chars %s." % (Type, PrintList)
    elif Type == 'BOOLEAN':
        if Value not in ['TRUE', 'True', 'true', '0x1', '0x01', '1', 'FALSE', 'False', 'false', '0x0', '0x00', '0']:
            return False, "Invalid value [%s] of type [%s]; must be one of TRUE, True, true, 0x1, 0x01, 1"\
                          ", FALSE, False, false, 0x0, 0x00, 0" % (Value, Type)
    elif Type in [TAB_UINT8, TAB_UINT16, TAB_UINT32, TAB_UINT64]:
        if Value.startswith('0') and not Value.lower().startswith('0x') and len(Value) > 1 and Value.lstrip('0'):
            Value = Value.lstrip('0')
        try:
            if Value and int(Value, 0) < 0:
                return False, "PCD can't be set to negative value[%s] for datum type [%s]" % (Value, Type)
            Value = int(Value, 0)
            if Value > MAX_VAL_TYPE[Type]:
                return False, "Too large PCD value[%s] for datum type [%s]" % (Value, Type)
        except:
            return False, "Invalid value [%s] of type [%s];"\
                          " must be a hexadecimal, decimal or octal in C language format." % (Value, Type)
    else:
        return True, "StructurePcd"

    return True, ""

def CommonPath(PathList):
    P1 = min(PathList).split(os.path.sep)
    P2 = max(PathList).split(os.path.sep)
    for Index in range(min(len(P1), len(P2))):
        if P1[Index] != P2[Index]:
            return os.path.sep.join(P1[:Index])
    return os.path.sep.join(P1)

class PathClass(object):
    def __init__(self, File='', Root='', AlterRoot='', Type='', IsBinary=False,
                 Arch='COMMON', ToolChainFamily='', Target='', TagName='', ToolCode=''):
        self.Arch = Arch
        self.File = str(File)
        if os.path.isabs(self.File):
            self.Root = ''
            self.AlterRoot = ''
        else:
            self.Root = str(Root)
            self.AlterRoot = str(AlterRoot)

        # Remove any '.' and '..' in path
        if self.Root:
            self.Root = mws.getWs(self.Root, self.File)
            self.Path = os.path.normpath(os.path.join(self.Root, self.File))
            self.Root = os.path.normpath(CommonPath([self.Root, self.Path]))
            # eliminate the side-effect of 'C:'
            if self.Root[-1] == ':':
                self.Root += os.path.sep
            # file path should not start with path separator
            if self.Root[-1] == os.path.sep:
                self.File = self.Path[len(self.Root):]
            else:
                self.File = self.Path[len(self.Root) + 1:]
        else:
            self.Path = os.path.normpath(self.File)

        self.SubDir, self.Name = os.path.split(self.File)
        self.BaseName, self.Ext = os.path.splitext(self.Name)

        if self.Root:
            if self.SubDir:
                self.Dir = os.path.join(self.Root, self.SubDir)
            else:
                self.Dir = self.Root
        else:
            self.Dir = self.SubDir

        if IsBinary:
            self.Type = Type
        else:
            self.Type = self.Ext.lower()

        self.IsBinary = IsBinary
        self.Target = Target
        self.TagName = TagName
        self.ToolCode = ToolCode
        self.ToolChainFamily = ToolChainFamily
        self.OriginalPath = self

    ## Convert the object of this class to a string
    #
    #  Convert member Path of the class to a string
    #
    #  @retval string Formatted String
    #
    def __str__(self):
        return self.Path

    ## Override __eq__ function
    #
    # Check whether PathClass are the same
    #
    # @retval False The two PathClass are different
    # @retval True  The two PathClass are the same
    #
    def __eq__(self, Other):
        return self.Path == str(Other)

    ## Override __cmp__ function
    #
    # Customize the comparison operation of two PathClass
    #
    # @retval 0     The two PathClass are different
    # @retval -1    The first PathClass is less than the second PathClass
    # @retval 1     The first PathClass is Bigger than the second PathClass
    def __cmp__(self, Other):
        OtherKey = str(Other)

        SelfKey = self.Path
        if SelfKey == OtherKey:
            return 0
        elif SelfKey > OtherKey:
            return 1
        else:
            return -1

    ## Override __hash__ function
    #
    # Use Path as key in hash table
    #
    # @retval string Key for hash table
    #
    def __hash__(self):
        return hash(self.Path)

    @property
    def Key(self):
        return self.Path.upper()

    @property
    def TimeStamp(self):
        return os.stat(self.Path)[8]

    def Validate(self, Type='', CaseSensitive=True):
        def RealPath2(File, Dir='', OverrideDir=''):
            NewFile = None
            if OverrideDir:
                NewFile = GlobalData.gAllFiles[os.path.normpath(os.path.join(OverrideDir, File))]
                if NewFile:
                    if OverrideDir[-1] == os.path.sep:
                        return NewFile[len(OverrideDir):], NewFile[0:len(OverrideDir)]
                    else:
                        return NewFile[len(OverrideDir) + 1:], NewFile[0:len(OverrideDir)]
            if GlobalData.gAllFiles:
                NewFile = GlobalData.gAllFiles[os.path.normpath(os.path.join(Dir, File))]
            if not NewFile:
                NewFile = os.path.normpath(os.path.join(Dir, File))
                if not os.path.exists(NewFile):
                    return None, None
            if NewFile:
                if Dir:
                    if Dir[-1] == os.path.sep:
                        return NewFile[len(Dir):], NewFile[0:len(Dir)]
                    else:
                        return NewFile[len(Dir) + 1:], NewFile[0:len(Dir)]
                else:
                    return NewFile, ''

            return None, None

        if GlobalData.gCaseInsensitive:
            CaseSensitive = False
        if Type and Type.lower() != self.Type:
            return FILE_TYPE_MISMATCH, '%s (expect %s but got %s)' % (self.File, Type, self.Type)

        RealFile, RealRoot = RealPath2(self.File, self.Root, self.AlterRoot)
        if not RealRoot and not RealFile:
            RealFile = self.File
            if self.AlterRoot:
                RealFile = os.path.join(self.AlterRoot, self.File)
            elif self.Root:
                RealFile = os.path.join(self.Root, self.File)
            if len (mws.getPkgPath()) == 0:
                return FILE_NOT_FOUND, os.path.join(self.AlterRoot, RealFile)
            else:
                return FILE_NOT_FOUND, "%s is not found in packages path:\n\t%s" % (self.File, '\n\t'.join(mws.getPkgPath()))

        ErrorCode = 0
        ErrorInfo = ''
        if RealRoot != self.Root or RealFile != self.File:
            if CaseSensitive and (RealFile != self.File or (RealRoot != self.Root and RealRoot != self.AlterRoot)):
                ErrorCode = FILE_CASE_MISMATCH
                ErrorInfo = self.File + '\n\t' + RealFile + " [in file system]"

            self.SubDir, self.Name = os.path.split(RealFile)
            self.BaseName, self.Ext = os.path.splitext(self.Name)
            if self.SubDir:
                self.Dir = os.path.join(RealRoot, self.SubDir)
            else:
                self.Dir = RealRoot
            self.File = RealFile
            self.Root = RealRoot
            self.Path = os.path.join(RealRoot, RealFile)
        return ErrorCode, ErrorInfo



## DeepCopy dict/OrderedDict recusively
#
#   @param      ori_dict    a nested dict or ordereddict
#
#   @retval     new dict or orderdict
#
def CopyDict(ori_dict):
    dict_type = ori_dict.__class__
    if dict_type not in (dict,OrderedDict):
        return ori_dict
    new_dict = dict_type()
    for key in ori_dict:
        if isinstance(ori_dict[key],(dict,OrderedDict)):
            new_dict[key] = CopyDict(ori_dict[key])
        else:
            new_dict[key] = ori_dict[key]
    return new_dict
