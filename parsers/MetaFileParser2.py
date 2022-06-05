## @file
# This file is used to parse meta files
#
# Copyright (c) 2008 - 2018, Intel Corporation. All rights reserved.<BR>
# (C) Copyright 2015-2018 Hewlett Packard Enterprise Development LP<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

##
# Import Modules
#

from hashlib import md5
import re
from collections import defaultdict
import Common.GlobalData as GlobalData
from Common.BuildToolError import (
    FORMAT_INVALID,
    FORMAT_UNKNOWN_ERROR,
    FILE_READ_FAILURE,
    ERROR_STATEMENT
)
from Common import EdkLogger as EdkLogger
import CommonDataClass.DataClass as DC
import Common.DataType as DT

from Common.StringUtils import (
    GetSplitValueList,
    ReplaceMacro,
    CleanString,
    CleanString2,
    NormPath
) 
from Common.Misc import (
    GuidStructureStringToGuidString,
    CheckPcdDatum,
    PathClass,
    AnalyzeDscPcd,
    AnalyzePcdExpression,
    StructPattern
)
from Common.Expression import ValueExpression, ValueExpressionEx, ReplaceExprMacro, BuildOptionValue
from CommonDataClass.Exceptions import *
from .MetaFileStore import MetaFileStorage
from .MetaFileCommentParser import CheckInfComment

## RegEx for finding file versions
hexVersionPattern = re.compile(r'0[xX][\da-f-A-F]{5,8}')
decVersionPattern = re.compile(r'\d+\.\d+')
CODEPattern = re.compile(r"{CODE\([a-fA-F0-9Xx\{\},\s]*\)}")

## A decorator used to parse macro definition
def ParseMacro(Parser):
    def MacroParser(self):
        Match = GlobalData.gMacroDefPattern.match(self._CurrentLine)
        if not Match:
            # Not 'DEFINE/EDK_GLOBAL' statement, call decorated method
            Parser(self)
            return

        TokenList = GetSplitValueList(self._CurrentLine[Match.end(1):], DT.TAB_EQUAL_SPLIT, 1)
        # Syntax check
        if not TokenList[0]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No macro name given",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        if len(TokenList) < 2:
            TokenList.append('')

        Type = Match.group(1)
        Name, Value = TokenList
        # Global macros can be only defined via environment variable
        if Name in GlobalData.gGlobalDefines:
            EdkLogger.error('Parser', FORMAT_INVALID, "%s can only be defined via environment variable" % Name,
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        # Only upper case letters, digit and '_' are allowed
        if not GlobalData.gMacroNamePattern.match(Name):
            EdkLogger.error('Parser', FORMAT_INVALID, "The macro name must be in the pattern [A-Z][A-Z0-9_]*",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        Value = ReplaceMacro(Value, self._Macros)
        if Type in self.DataType:
            self._ItemType = self.DataType[Type]
        else:
            self._ItemType = DC.MODEL_META_DATA_DEFINE
        # DEFINE defined macros
        if Type == DT.TAB_DSC_DEFINES_DEFINE:
            #
            # First judge whether this DEFINE is in conditional directive statements or not.
            #
            if isinstance(self, DscParser) and self._InDirective > -1:
                pass
            else:
                if isinstance(self, DecParser):
                    if DC.MODEL_META_DATA_HEADER in self._SectionType:
                        self._FileLocalMacros[Name] = Value
                    else:
                        self._ConstructSectionMacroDict(Name, Value)
                elif self._SectionType == DC.MODEL_META_DATA_HEADER:
                    self._FileLocalMacros[Name] = Value
                else:
                    self._ConstructSectionMacroDict(Name, Value)

        # EDK_GLOBAL defined macros
        elif not isinstance(self, DscParser):
            EdkLogger.error('Parser', FORMAT_INVALID, "EDK_GLOBAL can only be used in .dsc file",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        elif self._SectionType != DC.MODEL_META_DATA_HEADER:
            EdkLogger.error('Parser', FORMAT_INVALID, "EDK_GLOBAL can only be used under [Defines] section",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        elif (Name in self._FileLocalMacros) and (self._FileLocalMacros[Name] != Value):
            EdkLogger.error('Parser', FORMAT_INVALID, "EDK_GLOBAL defined a macro with the same name and different value as one defined by 'DEFINE'",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        self._ValueList = [Type, Name, Value]

    return MacroParser

## Base class of parser
#
#  This class is used for derivation purpose. The specific parser for one kind
# type file must derive this class and implement some public interfaces.
#
#   @param      FilePath        The path of platform description file
#   @param      FileType        The raw data of DSC file
#   @param      Table           Database used to retrieve module/package information
#   @param      Macros          Macros used for replacement in file
#   @param      Owner           Owner ID (for sub-section parsing)
#   @param      From            ID from which the data comes (for !INCLUDE directive)
#
class MetaFileParser(object):
    # data type (file content) for specific file type
    DataType = {}

    # Parser objects used to implement singleton
    MetaFiles = {}

    ## Factory method
    #
    # One file, one parser object. This factory method makes sure that there's
    # only one object constructed for one meta file.
    #
    #   @param  cls           class object of real AutoGen class
    #                           (InfParser, DecParser or DscParser)
    #   @param  FilePath        The path of meta file
    #   @param  *args           The specific class related parameters
    #   @param  **kwargs        The specific class related dict parameters
    #
    def __new__(cls, FilePath, *args, **kwargs):
        if FilePath in cls.MetaFiles:
            return cls.MetaFiles[FilePath]
        else:
            ParserObject = super(MetaFileParser, cls).__new__(cls)
            cls.MetaFiles[FilePath] = ParserObject
            return ParserObject

    def GetTableID(self):
        return (10**7)

    ## Constructor of MetaFileParser
    #
    #  Initialize object of MetaFileParser
    #
    #   @param      FilePath        The path of platform description file
    #   @param      FileType        The raw data of DSC file
    #   @param      Arch            Default Arch value for filtering sections
    #   @param      Table           Database used to retrieve module/package information
    #   @param      Owner           Owner ID (for sub-section parsing)
    #   @param      From            ID from which the data comes (for !INCLUDE directive)
    #
    def __init__(self, FilePath, FileType, Arch, Table, Owner= -1, From= -1):
        Table.ID = self.GetTableID()
        self._Table = Table
        self._RawTable = Table
        self._Arch = Arch
        self._FileType = FileType
        self.MetaFile = FilePath
        self._FileDir = self.MetaFile.Dir
        self._Defines = {}
        self._Packages = []
        self._FileLocalMacros = {}
        self._SectionsMacroDict = defaultdict(dict)

        # for recursive parsing
        self._Owner = [Owner]
        self._From = From

        # parsr status for parsing
        self._ValueList = ['', '', '', '', '']
        self._Scope = []
        self._LineIndex = 0
        self._CurrentLine = ''
        self._SectionType = DC.MODEL_UNKNOWN
        self._SectionName = ''
        self._InSubsection = False
        self._SubsectionType = DC.MODEL_UNKNOWN
        self._SubsectionName = ''
        self._ItemType = DC.MODEL_UNKNOWN
        self._LastItem = -1
        self._Enabled = True
        self._Finished = False
        self._PostProcessed = False
        # Different version of meta-file has different way to parse.
        self._Version = 0
        self._GuidDict = {}  # for Parser PCD value {GUID(gTokeSpaceGuidName)}

        self._PcdCodeValue = ""
        self._PcdDataTypeCODE = False
        self._CurrentPcdName = ""

    ## Store the parsed data in table
    def _Store(self, *Args):
        return self._Table.Insert(*Args)

    ## Virtual method for starting parse
    def Start(self):
        raise NotImplementedError

    ## Notify a post-process is needed
    def DoPostProcess(self):
        self._PostProcessed = False

    ## Set parsing complete flag in both class and table
    def _Done(self):
        self._Finished = True
        self._Table.SetEndFlag()

    def _PostProcess(self):
        self._PostProcessed = True

    ## Get the parse complete flag
    @property
    def Finished(self):
        return self._Finished

    ## Set the complete flag
    @Finished.setter
    def Finished(self, Value):
        self._Finished = Value

    ## Remove records that do not match given Filter Arch
    def _FilterRecordList(self, RecordList, FilterArch):
        NewRecordList = []
        for Record in RecordList:
            Arch = Record.Scope1
            if Arch == DT.TAB_ARCH_COMMON or Arch == FilterArch:
                NewRecordList.append(Record)
        return NewRecordList

    ## Use [] style to query data in table, just for readability
    #
    #   DataInfo = [data_type, scope1(arch), scope2(platform/moduletype)]
    #
    def __getitem__(self, DataInfo):
        if not isinstance(DataInfo, type(())):
            DataInfo = (DataInfo,)

        # Parse the file first, if necessary
        self.StartParse()

        # No specific ARCH or Platform given, use raw data
        if self._RawTable and (len(DataInfo) == 1 or DataInfo[1] is None):
            return self._FilterRecordList(self._RawTable.Query(*DataInfo), self._Arch)

        # Do post-process if necessary
        if not self._PostProcessed:
            self._PostProcess()

        return self._FilterRecordList(self._Table.Query(*DataInfo), DataInfo[1])

    def StartParse(self):
        if not self._Finished:
            if self._RawTable.IsIntegrity():
                self._Finished = True
            else:
                self._Table = self._RawTable
                self._PostProcessed = False
                self.Start()
    ## Data parser for the common format in different type of file
    #
    #   The common format in the meatfile is like
    #
    #       xxx1 | xxx2 | xxx3
    #
    @ParseMacro
    def _CommonParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        self._ValueList[0:len(TokenList)] = TokenList

    ## Data parser for the format in which there's path
    #
    #   Only path can have macro used. So we need to replace them before use.
    #
    @ParseMacro
    def _PathParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        self._ValueList[0:len(TokenList)] = TokenList
        # Don't do macro replacement for dsc file at this point
        if not isinstance(self, DscParser):
            Macros = self._Macros
            self._ValueList = [ReplaceMacro(Value, Macros) for Value in self._ValueList]

    ## Skip unsupported data
    def _Skip(self):
        EdkLogger.warn("Parser", "Unrecognized content", File=self.MetaFile,
                        Line=self._LineIndex + 1, ExtraData=self._CurrentLine);
        self._ValueList[0:1] = [self._CurrentLine]

    ## Skip unsupported data for UserExtension Section
    def _SkipUserExtension(self):
        self._ValueList[0:1] = [self._CurrentLine]

    ## Section header parser
    #
    #   The section header is always in following format:
    #
    #       [section_name.arch<.platform|module_type>]
    #
    def _SectionHeaderParser(self):
        self._Scope = []
        self._SectionName = ''
        ArchList = set()
        for Item in GetSplitValueList(self._CurrentLine[1:-1], DT.TAB_COMMA_SPLIT):
            if Item == '':
                continue
            ItemList = GetSplitValueList(Item, DT.TAB_SPLIT, 3)
            # different section should not mix in one section
            if self._SectionName != '' and self._SectionName != ItemList[0].upper():
                EdkLogger.error('Parser', FORMAT_INVALID, "Different section names in the same section",
                                File=self.MetaFile, Line=self._LineIndex + 1, ExtraData=self._CurrentLine)
            self._SectionName = ItemList[0].upper()
            if self._SectionName in self.DataType:
                self._SectionType = self.DataType[self._SectionName]
                # Check if the section name is valid
                if self._SectionName not in DT.SECTIONS_HAVE_ITEM_AFTER_ARCH_SET and len(ItemList) > 3:
                    EdkLogger.error("Parser", FORMAT_UNKNOWN_ERROR, "%s is not a valid section name" % Item,
                                    self.MetaFile, self._LineIndex + 1, self._CurrentLine)
            elif self._Version >= 0x00010005:
                EdkLogger.error("Parser", FORMAT_UNKNOWN_ERROR, "%s is not a valid section name" % Item,
                                self.MetaFile, self._LineIndex + 1, self._CurrentLine)
            else:
                self._SectionType = DC.MODEL_UNKNOWN

            # S1 is always Arch
            if len(ItemList) > 1:
                S1 = ItemList[1].upper()
            else:
                S1 = DT.TAB_ARCH_COMMON
            S1 = ReplaceMacro(S1, self._Macros)
            ArchList.add(S1)

            # S2 may be Platform or ModuleType
            if len(ItemList) > 2:
                if self._SectionName.upper() in DT.SECTIONS_HAVE_ITEM_PCD_SET:
                    S2 = ItemList[2]
                else:
                    S2 = ItemList[2].upper()
            else:
                S2 = DT.TAB_COMMON
            if len(ItemList) > 3:
                S3 = ItemList[3]
            else:
                S3 = DT.TAB_COMMON
            self._Scope.append([S1, S2, S3])

        # 'COMMON' must not be used with specific ARCHs at the same section
        if DT.TAB_ARCH_COMMON in ArchList and len(ArchList) > 1:
            EdkLogger.error('Parser', FORMAT_INVALID, "'common' ARCH must not be used with specific ARCHs",
                            File=self.MetaFile, Line=self._LineIndex + 1, ExtraData=self._CurrentLine)
        # If the section information is needed later, it should be stored in database
        self._ValueList[0] = self._SectionName

    ## [packages] section parser
    @ParseMacro
    def _PackageParser(self):
        self._CurrentLine = CleanString(self._CurrentLine)
        self._Packages.append(self._CurrentLine)
        self._ValueList[0] = self._CurrentLine

    ## [defines] section parser
    @ParseMacro
    def _DefineParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        self._ValueList[1:len(TokenList)] = TokenList
        if not self._ValueList[1]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No name specified",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        if not self._ValueList[2]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No value specified",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        self._ValueList = [ReplaceMacro(Value, self._Macros) for Value in self._ValueList]
        Name, Value = self._ValueList[1], self._ValueList[2]
        MacroUsed = GlobalData.gMacroRefPattern.findall(Value)
        if len(MacroUsed) != 0:
            for Macro in MacroUsed:
                if Macro in GlobalData.gGlobalDefines:
                    EdkLogger.error("Parser", FORMAT_INVALID, "Global macro %s is not permitted." % (Macro), ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
            else:
                EdkLogger.error("Parser", FORMAT_INVALID, "%s not defined" % (Macro), ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        # Sometimes, we need to make differences between EDK and EDK2 modules
        if Name == 'INF_VERSION':
            if hexVersionPattern.match(Value):
                self._Version = int(Value, 0)
            elif decVersionPattern.match(Value):
                ValueList = Value.split('.')
                Major = int(ValueList[0], 0)
                Minor = int(ValueList[1], 0)
                if Major > 0xffff or Minor > 0xffff:
                    EdkLogger.error('Parser', FORMAT_INVALID, "Invalid version number",
                                    ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
                self._Version = int('0x{0:04x}{1:04x}'.format(Major, Minor), 0)
            else:
                EdkLogger.error('Parser', FORMAT_INVALID, "Invalid version number",
                                ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        if isinstance(self, InfParser) and self._Version < 0x00010005:
            # EDK module allows using defines as macros
            self._FileLocalMacros[Name] = Value
        self._Defines[Name] = Value

    ## [BuildOptions] section parser
    @ParseMacro
    def _BuildOptionParser(self):
        self._CurrentLine = CleanString(self._CurrentLine, BuildOption=True)
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        TokenList2 = GetSplitValueList(TokenList[0], ':', 1)
        if len(TokenList2) == 2:
            self._ValueList[0] = TokenList2[0]              # toolchain family
            self._ValueList[1] = TokenList2[1]              # keys
        else:
            self._ValueList[1] = TokenList[0]
        if len(TokenList) == 2 and not isinstance(self, DscParser): # value
            self._ValueList[2] = ReplaceMacro(TokenList[1], self._Macros)

        if self._ValueList[1].count('_') != 4:
            EdkLogger.error(
                'Parser',
                FORMAT_INVALID,
                "'%s' must be in format of <TARGET>_<TOOLCHAIN>_<ARCH>_<TOOL>_FLAGS" % self._ValueList[1],
                ExtraData=self._CurrentLine,
                File=self.MetaFile,
                Line=self._LineIndex + 1
                )
    def GetValidExpression(self, TokenSpaceGuid, PcdCName):
        return self._Table.GetValidExpression(TokenSpaceGuid, PcdCName)

    @property
    def _Macros(self):
        Macros = {}
        Macros.update(self._FileLocalMacros)
        Macros.update(self._GetApplicableSectionMacro())
        return Macros

    ## Construct section Macro dict
    def _ConstructSectionMacroDict(self, Name, Value):
        ScopeKey = [(Scope[0], Scope[1], Scope[2]) for Scope in self._Scope]
        ScopeKey = tuple(ScopeKey)
        #
        # DecParser SectionType is a list, will contain more than one item only in Pcd Section
        # As Pcd section macro usage is not allowed, so here it is safe
        #
        if isinstance(self, DecParser):
            SectionDictKey = self._SectionType[0], ScopeKey
        else:
            SectionDictKey = self._SectionType, ScopeKey

        self._SectionsMacroDict[SectionDictKey][Name] = Value

    ## Get section Macros that are applicable to current line, which may come from other sections
    ## that share the same name while scope is wider
    def _GetApplicableSectionMacro(self):
        Macros = {}

        ComComMacroDict = {}
        ComSpeMacroDict = {}
        SpeSpeMacroDict = {}

        ActiveSectionType = self._SectionType
        if isinstance(self, DecParser):
            ActiveSectionType = self._SectionType[0]

        for (SectionType, Scope) in self._SectionsMacroDict:
            if SectionType != ActiveSectionType:
                continue

            for ActiveScope in self._Scope:
                Scope0, Scope1, Scope2= ActiveScope[0], ActiveScope[1], ActiveScope[2]
                if(Scope0, Scope1, Scope2) not in Scope:
                    break
            else:
                SpeSpeMacroDict.update(self._SectionsMacroDict[(SectionType, Scope)])

            for ActiveScope in self._Scope:
                Scope0, Scope1, Scope2 = ActiveScope[0], ActiveScope[1], ActiveScope[2]
                if(Scope0, Scope1, Scope2) not in Scope and (Scope0, DT.TAB_COMMON, DT.TAB_COMMON) not in Scope and (DT.TAB_COMMON, Scope1, DT.TAB_COMMON) not in Scope:
                    break
            else:
                ComSpeMacroDict.update(self._SectionsMacroDict[(SectionType, Scope)])

            if (DT.TAB_COMMON, DT.TAB_COMMON, DT.TAB_COMMON) in Scope:
                ComComMacroDict.update(self._SectionsMacroDict[(SectionType, Scope)])

        Macros.update(ComComMacroDict)
        Macros.update(ComSpeMacroDict)
        Macros.update(SpeSpeMacroDict)

        return Macros

    def ProcessMultipleLineCODEValue(self,Content):
        CODEBegin = False
        CODELine = ""
        continuelinecount = 0
        newContent = []
        for Index in range(0, len(Content)):
            Line = Content[Index]
            if CODEBegin:
                CODELine = CODELine + Line
                continuelinecount +=1
                if ")}" in Line:
                    newContent.append(CODELine)
                    for _ in range(continuelinecount):
                        newContent.append("")
                    CODEBegin = False
                    CODELine = ""
                    continuelinecount = 0
            else:
                if not Line:
                    newContent.append(Line)
                    continue
                if "{CODE(" not in Line:
                    newContent.append(Line)
                    continue
                elif CODEPattern.findall(Line):
                    newContent.append(Line)
                    continue
                else:
                    CODEBegin = True
                    CODELine = Line

        return newContent

    _SectionParser = {}

## INF file parser class
#
#   @param      FilePath        The path of platform description file
#   @param      FileType        The raw data of DSC file
#   @param      Table           Database used to retrieve module/package information
#   @param      Macros          Macros used for replacement in file
#
class InfParser(MetaFileParser):
    # INF file supported data types (one type per section)
    DataType = {
        DT.TAB_UNKNOWN.upper() : DC.MODEL_UNKNOWN,
        DT.TAB_INF_DEFINES.upper() : DC.MODEL_META_DATA_HEADER,
        DT.TAB_DSC_DEFINES_DEFINE : DC.MODEL_META_DATA_DEFINE,
        DT.TAB_BUILD_OPTIONS.upper() : DC.MODEL_META_DATA_BUILD_OPTION,
        DT.TAB_INCLUDES.upper() : DC.MODEL_EFI_INCLUDE,
        DT.TAB_LIBRARIES.upper() : DC.MODEL_EFI_LIBRARY_INSTANCE,
        DT.TAB_LIBRARY_CLASSES.upper() : DC.MODEL_EFI_LIBRARY_CLASS,
        DT.TAB_PACKAGES.upper() : DC.MODEL_META_DATA_PACKAGE,
        DT.TAB_NMAKE.upper() : DC.MODEL_META_DATA_NMAKE,
        DT.TAB_INF_FIXED_PCD.upper() : DC.MODEL_PCD_FIXED_AT_BUILD,
        DT.TAB_INF_PATCH_PCD.upper() : DC.MODEL_PCD_PATCHABLE_IN_MODULE,
        DT.TAB_INF_FEATURE_PCD.upper() : DC.MODEL_PCD_FEATURE_FLAG,
        DT.TAB_INF_PCD_EX.upper() : DC.MODEL_PCD_DYNAMIC_EX,
        DT.TAB_INF_PCD.upper() : DC.MODEL_PCD_DYNAMIC,
        DT.TAB_SOURCES.upper() : DC.MODEL_EFI_SOURCE_FILE,
        DT.TAB_GUIDS.upper() : DC.MODEL_EFI_GUID,
        DT.TAB_PROTOCOLS.upper() : DC.MODEL_EFI_PROTOCOL,
        DT.TAB_PPIS.upper() : DC.MODEL_EFI_PPI,
        DT.TAB_DEPEX.upper() : DC.MODEL_EFI_DEPEX,
        DT.TAB_BINARIES.upper() : DC.MODEL_EFI_BINARY_FILE,
        DT.TAB_USER_EXTENSIONS.upper() : DC.MODEL_META_DATA_USER_EXTENSION
    }

    ## Constructor of InfParser
    #
    #  Initialize object of InfParser
    #
    #   @param      FilePath        The path of module description file
    #   @param      FileType        The raw data of DSC file
    #   @param      Arch            Default Arch value for filtering sections
    #   @param      Table           Database used to retrieve module/package information
    #
    def __init__(self, FilePath, FileType, Arch, Table):
        # prevent re-initialization
        if hasattr(self, "_Table"):
            return
        MetaFileParser.__init__(self, FilePath, FileType, Arch, Table)
        self.PcdsDict = {}

    ## Parser starter
    def Start(self):
        NmakeLine = ''
        Content = ''
        try:
            with open(str(self.MetaFile), 'r') as File:
                Content = File.readlines()
        except:
            EdkLogger.error("Parser", FILE_READ_FAILURE, ExtraData=self.MetaFile)

        # parse the file line by line
        IsFindBlockComment = False
        GetHeaderComment = False
        TailComments = []
        SectionComments = []
        Comments = []

        for Index in range(0, len(Content)):
            # skip empty, commented, block commented lines
            Line, Comment = CleanString2(Content[Index], AllowCppStyleComment=True)
            NextLine = ''
            if Index + 1 < len(Content):
                NextLine, NextComment = CleanString2(Content[Index + 1])
            if Line == '':
                if Comment:
                    Comments.append((Comment, Index + 1))
                elif GetHeaderComment:
                    SectionComments.extend(Comments)
                    Comments = []
                continue
            if Line.find(DT.TAB_COMMENT_EDK_START) > -1:
                IsFindBlockComment = True
                continue
            if Line.find(DT.TAB_COMMENT_EDK_END) > -1:
                IsFindBlockComment = False
                continue
            if IsFindBlockComment:
                continue

            self._LineIndex = Index
            self._CurrentLine = Line

            # section header
            if Line[0] == DT.TAB_SECTION_START and Line[-1] == DT.TAB_SECTION_END:
                if not GetHeaderComment:
                    for Cmt, LNo in Comments:
                        self._Store(DC.MODEL_META_DATA_HEADER_COMMENT, Cmt, '', '', DT.TAB_COMMON,
                                    DT.TAB_COMMON, self._Owner[-1], LNo, -1, LNo, -1, True)
                    GetHeaderComment = True
                else:
                    TailComments.extend(SectionComments + Comments)
                Comments = []
                self._SectionHeaderParser()
                # Check invalid sections
                if self._Version < 0x00010005:
                    if self._SectionType in [DC.MODEL_META_DATA_BUILD_OPTION,
                                             DC.MODEL_EFI_LIBRARY_CLASS,
                                             DC.MODEL_META_DATA_PACKAGE,
                                             DC.MODEL_PCD_FIXED_AT_BUILD,
                                             DC.MODEL_PCD_PATCHABLE_IN_MODULE,
                                             DC.MODEL_PCD_FEATURE_FLAG,
                                             DC.MODEL_PCD_DYNAMIC_EX,
                                             DC.MODEL_PCD_DYNAMIC,
                                             DC.MODEL_EFI_GUID,
                                             DC.MODEL_EFI_PROTOCOL,
                                             DC.MODEL_EFI_PPI,
                                             DC.MODEL_META_DATA_USER_EXTENSION]:
                        EdkLogger.error('Parser', FORMAT_INVALID,
                                        "Section [%s] is not allowed in inf file without version" % (self._SectionName),
                                        ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
                elif self._SectionType in [DC.MODEL_EFI_INCLUDE,
                                           DC.MODEL_EFI_LIBRARY_INSTANCE,
                                           DC.MODEL_META_DATA_NMAKE]:
                    EdkLogger.error('Parser', FORMAT_INVALID,
                                    "Section [%s] is not allowed in inf file with version 0x%08x" % (self._SectionName, self._Version),
                                    ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
                continue
            # merge two lines specified by '\' in section NMAKE
            elif self._SectionType == DC.MODEL_META_DATA_NMAKE:
                if Line[-1] == '\\':
                    if NextLine == '':
                        self._CurrentLine = NmakeLine + Line[0:-1]
                        NmakeLine = ''
                    else:
                        if NextLine[0] == DT.TAB_SECTION_START and NextLine[-1] == DT.TAB_SECTION_END:
                            self._CurrentLine = NmakeLine + Line[0:-1]
                            NmakeLine = ''
                        else:
                            NmakeLine = NmakeLine + ' ' + Line[0:-1]
                            continue
                else:
                    self._CurrentLine = NmakeLine + Line
                    NmakeLine = ''

            # section content
            self._ValueList = ['', '', '']
            # parse current line, result will be put in self._ValueList
            self._SectionParser[self._SectionType](self)
            if self._ValueList is None or self._ItemType == DC.MODEL_META_DATA_DEFINE:
                self._ItemType = -1
                Comments = []
                continue
            if Comment:
                Comments.append((Comment, Index + 1))
            if GlobalData.gOptions and GlobalData.gOptions.CheckUsage:
                CheckInfComment(self._SectionType, Comments, str(self.MetaFile), Index + 1, self._ValueList)
            #
            # Model, Value1, Value2, Value3, Arch, Platform, BelongsToItem=-1,
            # LineBegin=-1, ColumnBegin=-1, LineEnd=-1, ColumnEnd=-1, Enabled=True
            #
            for Arch, Platform, _ in self._Scope:
                LastItem = self._Store(self._SectionType,
                            self._ValueList[0],
                            self._ValueList[1],
                            self._ValueList[2],
                            Arch,
                            Platform,
                            self._Owner[-1],
                            self._LineIndex + 1,
                            - 1,
                            self._LineIndex + 1,
                            - 1,
                            True 
                            )
                for Comment, LineNo in Comments:
                    self._Store(DC.MODEL_META_DATA_COMMENT, Comment, '', '', Arch, Platform,
                                LastItem, LineNo, -1, LineNo, -1, True)
            Comments = []
            SectionComments = []
        TailComments.extend(SectionComments + Comments)
        if IsFindBlockComment:
            EdkLogger.error("Parser", FORMAT_INVALID, "Open block comments (starting with /*) are expected to end with */",
                            File=self.MetaFile)

        # If there are tail comments in INF file, save to database whatever the comments are
        for Comment in TailComments:
            self._Store(DC.MODEL_META_DATA_TAIL_COMMENT, Comment[0], '', '', DT.TAB_COMMON,
                                DT.TAB_COMMON, self._Owner[-1], -1, -1, -1, -1, True)
        self._Done()

    ## Data parser for the format in which there's path
    #
    #   Only path can have macro used. So we need to replace them before use.
    #
    def _IncludeParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        self._ValueList[0:len(TokenList)] = TokenList
        Macros = self._Macros
        if Macros:
            for Index in range(0, len(self._ValueList)):
                Value = self._ValueList[Index]
                if not Value:
                    continue
                self._ValueList[Index] = ReplaceMacro(Value, Macros)

    ## Parse [Sources] section
    #
    #   Only path can have macro used. So we need to replace them before use.
    #
    @ParseMacro
    def _SourceFileParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        self._ValueList[0:len(TokenList)] = TokenList
        Macros = self._Macros
        # For Acpi tables, remove macro like ' TABLE_NAME=Sata1'
        if 'COMPONENT_TYPE' in Macros:
            if self._Defines['COMPONENT_TYPE'].upper() == 'ACPITABLE':
                self._ValueList[0] = GetSplitValueList(self._ValueList[0], ' ', 1)[0]
        if self._Defines['BASE_NAME'] == 'Microcode':
            pass
        self._ValueList = [ReplaceMacro(Value, Macros) for Value in self._ValueList]

    ## Parse [Binaries] section
    #
    #   Only path can have macro used. So we need to replace them before use.
    #
    @ParseMacro
    def _BinaryFileParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT, 2)
        if len(TokenList) < 2:
            EdkLogger.error('Parser', FORMAT_INVALID, "No file type or path specified",
                            ExtraData=self._CurrentLine + " (<FileType> | <FilePath> [| <Target>])",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if not TokenList[0]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No file type specified",
                            ExtraData=self._CurrentLine + " (<FileType> | <FilePath> [| <Target>])",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if not TokenList[1]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No file path specified",
                            ExtraData=self._CurrentLine + " (<FileType> | <FilePath> [| <Target>])",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        self._ValueList[0:len(TokenList)] = TokenList
        self._ValueList[1] = ReplaceMacro(self._ValueList[1], self._Macros)

    ## [nmake] section parser (Edk.x style only)
    def _NmakeParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        self._ValueList[0:len(TokenList)] = TokenList
        # remove macros
        self._ValueList[1] = ReplaceMacro(self._ValueList[1], self._Macros)
        # remove self-reference in macro setting
        #self._ValueList[1] = ReplaceMacro(self._ValueList[1], {self._ValueList[0]:''})

    ## [FixedPcd], [FeaturePcd], [PatchPcd], [Pcd] and [PcdEx] sections parser
    @ParseMacro
    def _PcdParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT, 1)
        ValueList = GetSplitValueList(TokenList[0], DT.TAB_SPLIT)
        if len(ValueList) != 2:
            EdkLogger.error('Parser', FORMAT_INVALID, "Illegal token space GUID and PCD name format",
                            ExtraData=self._CurrentLine + " (<TokenSpaceGuidCName>.<PcdCName>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        self._ValueList[0:1] = ValueList
        if len(TokenList) > 1:
            self._ValueList[2] = TokenList[1]
        if self._ValueList[0] == '' or self._ValueList[1] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No token space GUID or PCD name specified",
                            ExtraData=self._CurrentLine + " (<TokenSpaceGuidCName>.<PcdCName>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)

        # if value are 'True', 'true', 'TRUE' or 'False', 'false', 'FALSE', replace with integer 1 or 0.
        if self._ValueList[2] != '':
            InfPcdValueList = GetSplitValueList(TokenList[1], DT.TAB_VALUE_SPLIT, 1)
            if InfPcdValueList[0] in ['True', 'true', 'TRUE']:
                self._ValueList[2] = TokenList[1].replace(InfPcdValueList[0], '1', 1)
            elif InfPcdValueList[0] in ['False', 'false', 'FALSE']:
                self._ValueList[2] = TokenList[1].replace(InfPcdValueList[0], '0', 1)
            elif isinstance(InfPcdValueList[0], str) and InfPcdValueList[0].find('$(') >= 0:
                Value = ReplaceExprMacro(InfPcdValueList[0],self._Macros)
                if Value != '0':
                    self._ValueList[2] = Value
        if (self._ValueList[0], self._ValueList[1]) not in self.PcdsDict:
            self.PcdsDict[self._ValueList[0], self._ValueList[1]] = self._SectionType
        elif self.PcdsDict[self._ValueList[0], self._ValueList[1]] != self._SectionType:
            EdkLogger.error('Parser', FORMAT_INVALID, "It is not permissible to list a specified PCD in different PCD type sections.",
                            ExtraData=self._CurrentLine + " (<TokenSpaceGuidCName>.<PcdCName>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)

    ## [depex] section parser
    @ParseMacro
    def _DepexParser(self):
        self._ValueList[0:1] = [self._CurrentLine]

    _SectionParser = {
        DC.MODEL_UNKNOWN                   :   MetaFileParser._Skip,
        DC.MODEL_META_DATA_HEADER          :   MetaFileParser._DefineParser,
        DC.MODEL_META_DATA_BUILD_OPTION    :   MetaFileParser._BuildOptionParser,
        DC.MODEL_EFI_INCLUDE               :   _IncludeParser, # for Edk.x modules
        DC.MODEL_EFI_LIBRARY_INSTANCE      :   MetaFileParser._CommonParser, # for Edk.x modules
        DC.MODEL_EFI_LIBRARY_CLASS         :   MetaFileParser._PathParser,
        DC.MODEL_META_DATA_PACKAGE         :   MetaFileParser._PathParser,
        DC.MODEL_META_DATA_NMAKE           :   _NmakeParser, # for Edk.x modules
        DC.MODEL_PCD_FIXED_AT_BUILD        :   _PcdParser,
        DC.MODEL_PCD_PATCHABLE_IN_MODULE   :   _PcdParser,
        DC.MODEL_PCD_FEATURE_FLAG          :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_EX            :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC               :   _PcdParser,
        DC.MODEL_EFI_SOURCE_FILE           :   _SourceFileParser,
        DC.MODEL_EFI_GUID                  :   MetaFileParser._CommonParser,
        DC.MODEL_EFI_PROTOCOL              :   MetaFileParser._CommonParser,
        DC.MODEL_EFI_PPI                   :   MetaFileParser._CommonParser,
        DC.MODEL_EFI_DEPEX                 :   _DepexParser,
        DC.MODEL_EFI_BINARY_FILE           :   _BinaryFileParser,
        DC.MODEL_META_DATA_USER_EXTENSION  :   MetaFileParser._SkipUserExtension,
    }

## DSC file parser class
#
#   @param      FilePath        The path of platform description file
#   @param      FileType        The raw data of DSC file
#   @param      Table           Database used to retrieve module/package information
#   @param      Macros          Macros used for replacement in file
#   @param      Owner           Owner ID (for sub-section parsing)
#   @param      From            ID from which the data comes (for !INCLUDE directive)
#
class DscParser(MetaFileParser):
    # DSC file supported data types (one type per section)
    DataType = {
        DT.TAB_SKUIDS.upper()                          :   DC.MODEL_EFI_SKU_ID,
        DT.TAB_DEFAULT_STORES.upper()                  :   DC.MODEL_EFI_DEFAULT_STORES,
        DT.TAB_LIBRARIES.upper()                       :   DC.MODEL_EFI_LIBRARY_INSTANCE,
        DT.TAB_LIBRARY_CLASSES.upper()                 :   DC.MODEL_EFI_LIBRARY_CLASS,
        DT.TAB_BUILD_OPTIONS.upper()                   :   DC.MODEL_META_DATA_BUILD_OPTION,
        DT.TAB_PACKAGES.upper()                        :   DC.MODEL_META_DATA_PACKAGE,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_FIXED_AT_BUILD.upper()        :   DC.MODEL_PCD_FIXED_AT_BUILD,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_PATCHABLE_IN_MODULE.upper()   :   DC.MODEL_PCD_PATCHABLE_IN_MODULE,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_FEATURE_FLAG.upper()          :   DC.MODEL_PCD_FEATURE_FLAG,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_DEFAULT.upper()       :   DC.MODEL_PCD_DYNAMIC_DEFAULT,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_HII.upper()           :   DC.MODEL_PCD_DYNAMIC_HII,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_VPD.upper()           :   DC.MODEL_PCD_DYNAMIC_VPD,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_EX_DEFAULT.upper()    :   DC.MODEL_PCD_DYNAMIC_EX_DEFAULT,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_EX_HII.upper()        :   DC.MODEL_PCD_DYNAMIC_EX_HII,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_EX_VPD.upper()        :   DC.MODEL_PCD_DYNAMIC_EX_VPD,
        DT.TAB_COMPONENTS.upper()                      :   DC.MODEL_META_DATA_COMPONENT,
        DT.TAB_DSC_DEFINES.upper()                     :   DC.MODEL_META_DATA_HEADER,
        DT.TAB_DSC_DEFINES_DEFINE                      :   DC.MODEL_META_DATA_DEFINE,
        DT.TAB_DSC_DEFINES_EDKGLOBAL                   :   DC.MODEL_META_DATA_GLOBAL_DEFINE,
        DT.TAB_INCLUDE.upper()                         :   DC.MODEL_META_DATA_INCLUDE,
        DT.TAB_IF.upper()                              :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF,
        DT.TAB_IF_DEF.upper()                          :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFDEF,
        DT.TAB_IF_N_DEF.upper()                        :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF,
        DT.TAB_ELSE_IF.upper()                         :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSEIF,
        DT.TAB_ELSE.upper()                            :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSE,
        DT.TAB_END_IF.upper()                          :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ENDIF,
        DT.TAB_USER_EXTENSIONS.upper()                 :   DC.MODEL_META_DATA_USER_EXTENSION,
        DT.TAB_ERROR.upper()                           :   DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ERROR,
    }

    # Valid names in define section
    DefineKeywords = [
        "DSC_SPECIFICATION",
        "PLATFORM_NAME",
        "PLATFORM_GUID",
        "PLATFORM_VERSION",
        "SKUID_IDENTIFIER",
        "PCD_INFO_GENERATION",
        "PCD_VAR_CHECK_GENERATION",
        "SUPPORTED_ARCHITECTURES",
        "BUILD_TARGETS",
        "OUTPUT_DIRECTORY",
        "FLASH_DEFINITION",
        "BUILD_NUMBER",
        "RFC_LANGUAGES",
        "ISO_LANGUAGES",
        "TIME_STAMP_FILE",
        "VPD_TOOL_GUID",
        "FIX_LOAD_TOP_MEMORY_ADDRESS",
        "PREBUILD",
        "POSTBUILD"
    ]

    SubSectionDefineKeywords = [
        "FILE_GUID"
    ]

    SymbolPattern = ValueExpression.SymbolPattern

    IncludedFiles = set()

    ## Constructor of DscParser
    #
    #  Initialize object of DscParser
    #
    #   @param      FilePath        The path of platform description file
    #   @param      FileType        The raw data of DSC file
    #   @param      Arch            Default Arch value for filtering sections
    #   @param      Table           Database used to retrieve module/package information
    #   @param      Owner           Owner ID (for sub-section parsing)
    #   @param      From            ID from which the data comes (for !INCLUDE directive)
    #
    def __init__(self, FilePath, FileType, Arch, Table, Owner= -1, From= -1):
        # prevent re-initialization
        if hasattr(self, "_Table") and self._Table is Table:
            return
        MetaFileParser.__init__(self, FilePath, FileType, Arch, Table, Owner, From)
        self._Version = 0x00010005  # Only EDK2 dsc file is supported
        # to store conditional directive evaluation result
        self._DirectiveStack = []
        self._DirectiveEvalStack = []
        self._Enabled = True

        #
        # Specify whether current line is in uncertain condition
        #
        self._InDirective = -1

        # Final valid replacable symbols
        self._Symbols = {}
        #
        #  Map the ID between the original table and new table to track
        #  the owner item
        #
        self._IdMapping = {-1:-1}

        self._Content = None

    def GetTableID(self):
        return (len(self.IncludedFiles) + 1) * (10**7)
    ## Parser starter
    def Start(self):
        Content = ''
        try:
            with open(str(self.MetaFile), 'r') as File:
                Content = File.readlines()
        except:
            EdkLogger.error("Parser", FILE_READ_FAILURE, ExtraData=self.MetaFile)

        OwnerId = {}

        Content = self.ProcessMultipleLineCODEValue(Content)

        for Index in range(0, len(Content)):
            Line,comments = CleanString2(Content[Index])
            # skip empty line
            if Line == '':
                if comments:
                    #print(Index, comments, self.MetaFile.Path)
                    pass
                continue
            else:
                if comments:
                    print(Index,self.MetaFile.Path, "xxxxxxxxxxxxxxxxxxx", comments)

            self._CurrentLine = Line
            self._LineIndex = Index
            if self._InSubsection and self._Owner[-1] == -1:
                self._Owner.append(self._LastItem)

            # section header
            if Line[0] == DT.TAB_SECTION_START and Line[-1] == DT.TAB_SECTION_END:
                self._SectionType = DC.MODEL_META_DATA_SECTION_HEADER
            # subsection ending
            elif Line[0] == '}' and self._InSubsection:
                self._InSubsection = False
                self._SubsectionType = DC.MODEL_UNKNOWN
                self._SubsectionName = ''
                self._Owner[-1] = -1
                OwnerId.clear()
                continue
            # subsection header
            elif Line[0] == DT.TAB_OPTION_START and Line[-1] == DT.TAB_OPTION_END:
                self._SubsectionType = DC.MODEL_META_DATA_SUBSECTION_HEADER
            # directive line
            elif Line[0] == '!':
                TokenList = GetSplitValueList(Line, ' ', 1)
                if TokenList[0] == DT.TAB_INCLUDE:
                    for Arch, ModuleType, DefaultStore in self._Scope:
                        if self._SubsectionType != DC.MODEL_UNKNOWN and Arch in OwnerId:
                            self._Owner[-1] = OwnerId[Arch]
                        self._DirectiveParser()
                else:
                    self._DirectiveParser()
                continue
            if Line[0] == DT.TAB_OPTION_START and not self._InSubsection:
                EdkLogger.error("Parser", FILE_READ_FAILURE, "Missing the '{' before %s in Line %s" % (Line, Index+1), ExtraData=self.MetaFile)

            if self._InSubsection:
                SectionType = self._SubsectionType
            else:
                SectionType = self._SectionType
            self._ItemType = SectionType

            self._ValueList = ['', '', '']
            # "SET pcd = pcd_expression" syntax is not supported in Dsc file.
            if self._CurrentLine.upper().strip().startswith("SET "):
                EdkLogger.error('Parser', FORMAT_INVALID, '''"SET pcd = pcd_expression" syntax is not support in Dsc file''',
                                ExtraData=self._CurrentLine,
                                File=self.MetaFile, Line=self._LineIndex + 1)
            self._SectionParser[SectionType](self)
            if self._ValueList is None:
                continue
            #
            # Model, Value1, Value2, Value3, Arch, ModuleType, BelongsToItem=-1, BelongsToFile=-1,
            # LineBegin=-1, ColumnBegin=-1, LineEnd=-1, ColumnEnd=-1, Enabled=-1
            #
            for Arch, ModuleType, DefaultStore in self._Scope:
                Owner = self._Owner[-1]
                if self._SubsectionType != DC.MODEL_UNKNOWN and Arch in OwnerId:
                    Owner = OwnerId[Arch]
                self._LastItem = self._Store(
                                        self._ItemType,
                                        self._ValueList[0],
                                        self._ValueList[1],
                                        self._ValueList[2],
                                        Arch,
                                        ModuleType,
                                        DefaultStore,
                                        Owner,
                                        self._From,
                                        self._LineIndex + 1,
                                        - 1,
                                        self._LineIndex + 1,
                                        - 1,
                                        "",
                                        "",
                                        "",
                                        self._Enabled
                                        )
                if self._SubsectionType == DC.MODEL_UNKNOWN and self._InSubsection:
                    OwnerId[Arch] = self._LastItem

        if self._DirectiveStack:
            _, Line, Text = self._DirectiveStack[-1]
            EdkLogger.error('Parser', FORMAT_INVALID, "No matching '!endif' found",
                            ExtraData=Text, File=self.MetaFile, Line=Line)
        self._Done()

    ## <subsection_header> parser
    def _SubsectionHeaderParser(self):
        self._SubsectionName = self._CurrentLine[1:-1].upper()
        if self._SubsectionName in self.DataType:
            self._SubsectionType = self.DataType[self._SubsectionName]
        else:
            self._SubsectionType = DC.MODEL_UNKNOWN
            EdkLogger.warn("Parser", "Unrecognized sub-section", File=self.MetaFile,
                           Line=self._LineIndex + 1, ExtraData=self._CurrentLine)
        self._ValueList[0] = self._SubsectionName

    ## Directive statement parser
    def _DirectiveParser(self):
        self._ValueList = ['', '', '']
        TokenList = GetSplitValueList(self._CurrentLine, ' ', 1)
        self._ValueList[0:len(TokenList)] = TokenList

        # Syntax check
        DirectiveName = self._ValueList[0].upper()
        if DirectiveName not in self.DataType:
            EdkLogger.error("Parser", FORMAT_INVALID, "Unknown directive [%s]" % DirectiveName,
                            File=self.MetaFile, Line=self._LineIndex + 1)

        if DirectiveName in ['!IF', '!IFDEF', '!IFNDEF']:
            self._InDirective += 1

        if DirectiveName in ['!ENDIF']:
            self._InDirective -= 1

        if DirectiveName in ['!IF', '!IFDEF', '!INCLUDE', '!IFNDEF', '!ELSEIF'] and self._ValueList[1] == '':
            EdkLogger.error("Parser", FORMAT_INVALID, "Missing expression",
                            File=self.MetaFile, Line=self._LineIndex + 1,
                            ExtraData=self._CurrentLine)

        ItemType = self.DataType[DirectiveName]
        Scope = [[DT.TAB_COMMON, DT.TAB_COMMON, DT.TAB_COMMON]]
        if ItemType == DC.MODEL_META_DATA_INCLUDE:
            Scope = self._Scope
        elif ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ERROR:
            Scope = self._Scope
        if ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ENDIF:
            # Remove all directives between !if and !endif, including themselves
            while self._DirectiveStack:
                # Remove any !else or !elseif
                DirectiveInfo = self._DirectiveStack.pop()
                if DirectiveInfo[0] in [DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF,
                                        DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFDEF,
                                        DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF]:
                    break
            else:
                EdkLogger.error("Parser", FORMAT_INVALID, "Redundant '!endif'",
                                File=self.MetaFile, Line=self._LineIndex + 1,
                                ExtraData=self._CurrentLine)
        elif ItemType not in {DC.MODEL_META_DATA_INCLUDE, DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ERROR}:
            # Break if there's a !else is followed by a !elseif
            if ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSEIF and \
               self._DirectiveStack and \
               self._DirectiveStack[-1][0] == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSE:
                EdkLogger.error("Parser", FORMAT_INVALID, "'!elseif' after '!else'",
                                File=self.MetaFile, Line=self._LineIndex + 1,
                                ExtraData=self._CurrentLine)
            self._DirectiveStack.append((ItemType, self._LineIndex + 1, self._CurrentLine))

        #
        # Model, Value1, Value2, Value3, Arch, ModuleType, BelongsToItem=-1, BelongsToFile=-1,
        # LineBegin=-1, ColumnBegin=-1, LineEnd=-1, ColumnEnd=-1, Enabled=-1
        #
        for Arch, ModuleType, DefaultStore in Scope:
            self._LastItem = self._Store(
                                    ItemType,
                                    self._ValueList[0],
                                    self._ValueList[1],
                                    self._ValueList[2],
                                    Arch,
                                    ModuleType,
                                    DefaultStore,
                                    self._Owner[-1],
                                    self._From,
                                    self._LineIndex + 1,
                                    - 1,
                                    self._LineIndex + 1,
                                    - 1,
                                    "",
                                    "",
                                    "",
                                    True 
                                    )

    ## [defines] section parser
    @ParseMacro
    def _DefineParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        self._ValueList[1:len(TokenList)] = TokenList

        # Syntax check
        if not self._ValueList[1]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No name specified",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        if not self._ValueList[2]:
            EdkLogger.error('Parser', FORMAT_INVALID, "No value specified",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        if (not self._ValueList[1] in self.DefineKeywords and
            (self._InSubsection and self._ValueList[1] not in self.SubSectionDefineKeywords)):
            EdkLogger.error('Parser', FORMAT_INVALID,
                            "Unknown keyword found: %s. "
                            "If this is a macro you must "
                            "add it as a DEFINE in the DSC" % self._ValueList[1],
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        if not self._InSubsection:
            self._Defines[self._ValueList[1]] = self._ValueList[2]
        self._ItemType = self.DataType[DT.TAB_DSC_DEFINES.upper()]

    @ParseMacro
    def _SkuIdParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        if len(TokenList) not in (2, 3):
            EdkLogger.error('Parser', FORMAT_INVALID, "Correct format is '<Number>|<UiName>[|<UiName>]'",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        self._ValueList[0:len(TokenList)] = TokenList
    @ParseMacro
    def _DefaultStoresParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        if len(TokenList) != 2:
            EdkLogger.error('Parser', FORMAT_INVALID, "Correct format is '<Number>|<UiName>'",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
        self._ValueList[0:len(TokenList)] = TokenList

    ## Parse Edk style of library modules
    @ParseMacro
    def _LibraryInstanceParser(self):
        self._ValueList[0] = self._CurrentLine


    def _DecodeCODEData(self):
        pass
    ## PCD sections parser
    #
    #   [PcdsFixedAtBuild]
    #   [PcdsPatchableInModule]
    #   [PcdsFeatureFlag]
    #   [PcdsDynamicEx
    #   [PcdsDynamicExDefault]
    #   [PcdsDynamicExVpd]
    #   [PcdsDynamicExHii]
    #   [PcdsDynamic]
    #   [PcdsDynamicDefault]
    #   [PcdsDynamicVpd]
    #   [PcdsDynamicHii]
    #
    @ParseMacro
    def _PcdParser(self):
        if self._PcdDataTypeCODE:
            self._PcdCodeValue = self._PcdCodeValue + "\n " + self._CurrentLine
            if self._CurrentLine.endswith(")}"):
                self._CurrentLine = "|".join((self._CurrentPcdName, self._PcdCodeValue))
                self._PcdDataTypeCODE = False
                self._PcdCodeValue = ""
            else:
                self._ValueList = None
                return
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT, 1)
        self._CurrentPcdName = TokenList[0]
        if len(TokenList) == 2 and TokenList[1].strip().startswith("{CODE"):
            self._PcdDataTypeCODE = True
            self._PcdCodeValue = TokenList[1].strip()

        if self._PcdDataTypeCODE:
            if self._CurrentLine.endswith(")}"):
                self._PcdDataTypeCODE = False
                self._PcdCodeValue = ""
            else:
                self._ValueList = None
                return
        self._ValueList[0:1] = GetSplitValueList(TokenList[0], DT.TAB_SPLIT)
        PcdNameTockens = GetSplitValueList(TokenList[0], DT.TAB_SPLIT)
        if len(PcdNameTockens) == 2:
            self._ValueList[0], self._ValueList[1] = PcdNameTockens[0], PcdNameTockens[1]
        elif len(PcdNameTockens) == 3:
            self._ValueList[0], self._ValueList[1] = ".".join((PcdNameTockens[0], PcdNameTockens[1])), PcdNameTockens[2]
        elif len(PcdNameTockens) > 3:
            self._ValueList[0], self._ValueList[1] = ".".join((PcdNameTockens[0], PcdNameTockens[1])), ".".join(PcdNameTockens[2:])
        if len(TokenList) == 2:
            self._ValueList[2] = TokenList[1]
        if self._ValueList[0] == '' or self._ValueList[1] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No token space GUID or PCD name specified",
                            ExtraData=self._CurrentLine + " (<TokenSpaceGuidCName>.<TokenCName>|<PcdValue>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if self._ValueList[2] == '':
            #
            # The PCD values are optional for FIXEDATBUILD, PATCHABLEINMODULE, Dynamic/DynamicEx default
            #
            if self._SectionType in (DC.MODEL_PCD_FIXED_AT_BUILD, DC.MODEL_PCD_PATCHABLE_IN_MODULE, DC.MODEL_PCD_DYNAMIC_DEFAULT, DC.MODEL_PCD_DYNAMIC_EX_DEFAULT):
                return
            EdkLogger.error('Parser', FORMAT_INVALID, "No PCD value given",
                            ExtraData=self._CurrentLine + " (<TokenSpaceGuidCName>.<TokenCName>|<PcdValue>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)

        # Validate the datum type of Dynamic Defaul PCD and DynamicEx Default PCD
        ValueList = GetSplitValueList(self._ValueList[2])
        if len(ValueList) > 1 and ValueList[1] in [DT.TAB_UINT8, DT.TAB_UINT16, DT.TAB_UINT32, DT.TAB_UINT64] \
                              and self._ItemType in [DC.MODEL_PCD_DYNAMIC_DEFAULT, DC.MODEL_PCD_DYNAMIC_EX_DEFAULT]:
            EdkLogger.error('Parser', FORMAT_INVALID, "The datum type '%s' of PCD is wrong" % ValueList[1],
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        # Validate the VariableName of DynamicHii and DynamicExHii for PCD Entry must not be an empty string
        if self._ItemType in [DC.MODEL_PCD_DYNAMIC_HII, DC.MODEL_PCD_DYNAMIC_EX_HII]:
            DscPcdValueList = GetSplitValueList(TokenList[1], DT.TAB_VALUE_SPLIT, 1)
            if len(DscPcdValueList[0].replace('L', '').replace('"', '').strip()) == 0:
                EdkLogger.error('Parser', FORMAT_INVALID, "The VariableName field in the HII format PCD entry must not be an empty string",
                            ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)

        # if value are 'True', 'true', 'TRUE' or 'False', 'false', 'FALSE', replace with integer 1 or 0.
        DscPcdValueList = GetSplitValueList(TokenList[1], DT.TAB_VALUE_SPLIT, 1)
        if DscPcdValueList[0] in ['True', 'true', 'TRUE']:
            self._ValueList[2] = TokenList[1].replace(DscPcdValueList[0], '1', 1);
        elif DscPcdValueList[0] in ['False', 'false', 'FALSE']:
            self._ValueList[2] = TokenList[1].replace(DscPcdValueList[0], '0', 1);


    ## [components] section parser
    @ParseMacro
    def _ComponentParser(self):
        if self._CurrentLine[-1] == '{':
            self._ValueList[0] = self._CurrentLine[0:-1].strip()
            self._InSubsection = True
            self._SubsectionType = DC.MODEL_UNKNOWN
        else:
            self._ValueList[0] = self._CurrentLine

    ## [LibraryClasses] section
    @ParseMacro
    def _LibraryClassParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT)
        if len(TokenList) < 2:
            EdkLogger.error('Parser', FORMAT_INVALID, "No library class or instance specified",
                            ExtraData=self._CurrentLine + " (<LibraryClassName>|<LibraryInstancePath>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if TokenList[0] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No library class specified",
                            ExtraData=self._CurrentLine + " (<LibraryClassName>|<LibraryInstancePath>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if TokenList[1] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No library instance specified",
                            ExtraData=self._CurrentLine + " (<LibraryClassName>|<LibraryInstancePath>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)

        self._ValueList[0:len(TokenList)] = TokenList


    ## [BuildOptions] section parser
    @ParseMacro
    def _BuildOptionParser(self):
        self._CurrentLine = CleanString(self._CurrentLine, BuildOption=True)
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        TokenList2 = GetSplitValueList(TokenList[0], ':', 1)
        if len(TokenList2) == 2:
            self._ValueList[0] = TokenList2[0]  # toolchain family
            self._ValueList[1] = TokenList2[1]  # keys
        else:
            self._ValueList[1] = TokenList[0]
        if len(TokenList) == 2:                 # value
            self._ValueList[2] = TokenList[1]

        if self._ValueList[1].count('_') != 4:
            EdkLogger.error(
                'Parser',
                FORMAT_INVALID,
                "'%s' must be in format of <TARGET>_<TOOLCHAIN>_<ARCH>_<TOOL>_FLAGS" % self._ValueList[1],
                ExtraData=self._CurrentLine,
                File=self.MetaFile,
                Line=self._LineIndex + 1
                )

    ## Override parent's method since we'll do all macro replacements in parser
    @property
    def _Macros(self):
        Macros = {}
        Macros.update(self._FileLocalMacros)
        Macros.update(self._GetApplicableSectionMacro())
        Macros.update(GlobalData.gEdkGlobal)
        Macros.update(GlobalData.gPlatformDefines)
        Macros.update(GlobalData.gCommandLineDefines)
        # PCD cannot be referenced in macro definition
        if self._ItemType not in [DC.MODEL_META_DATA_DEFINE, DC.MODEL_META_DATA_GLOBAL_DEFINE]:
            Macros.update(self._Symbols)
        if GlobalData.BuildOptionPcd:
            for Item in GlobalData.BuildOptionPcd:
                if isinstance(Item, tuple):
                    continue
                PcdName, TmpValue = Item.split("=")
                TmpValue = BuildOptionValue(TmpValue, self._GuidDict)
                Macros[PcdName.strip()] = TmpValue
        return Macros

    def _PostProcess(self):
        Processer = {
            DC.MODEL_META_DATA_SECTION_HEADER                  :   self.__ProcessSectionHeader,
            DC.MODEL_META_DATA_SUBSECTION_HEADER               :   self.__ProcessSubsectionHeader,
            DC.MODEL_META_DATA_HEADER                          :   self.__ProcessDefine,
            DC.MODEL_META_DATA_DEFINE                          :   self.__ProcessDefine,
            DC.MODEL_META_DATA_GLOBAL_DEFINE                   :   self.__ProcessDefine,
            DC.MODEL_META_DATA_INCLUDE                         :   self.__ProcessDirective,
            DC.MODEL_META_DATA_PACKAGE                         :   self.__ProcessPackages,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF        :   self.__ProcessDirective,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSE      :   self.__ProcessDirective,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFDEF     :   self.__ProcessDirective,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF    :   self.__ProcessDirective,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ENDIF     :   self.__ProcessDirective,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSEIF    :   self.__ProcessDirective,
            DC.MODEL_EFI_SKU_ID                                :   self.__ProcessSkuId,
            DC.MODEL_EFI_DEFAULT_STORES                        :   self.__ProcessDefaultStores,
            DC.MODEL_EFI_LIBRARY_INSTANCE                      :   self.__ProcessLibraryInstance,
            DC.MODEL_EFI_LIBRARY_CLASS                         :   self.__ProcessLibraryClass,
            DC.MODEL_PCD_FIXED_AT_BUILD                        :   self.__ProcessPcd,
            DC.MODEL_PCD_PATCHABLE_IN_MODULE                   :   self.__ProcessPcd,
            DC.MODEL_PCD_FEATURE_FLAG                          :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_DEFAULT                       :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_HII                           :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_VPD                           :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_EX_DEFAULT                    :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_EX_HII                        :   self.__ProcessPcd,
            DC.MODEL_PCD_DYNAMIC_EX_VPD                        :   self.__ProcessPcd,
            DC.MODEL_META_DATA_COMPONENT                       :   self.__ProcessComponent,
            DC.MODEL_META_DATA_BUILD_OPTION                    :   self.__ProcessBuildOption,
            DC.MODEL_UNKNOWN                                   :   self._Skip,
            DC.MODEL_META_DATA_USER_EXTENSION                  :   self._SkipUserExtension,
            DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ERROR     :   self._ProcessError,
        }

        self._Table = MetaFileStorage(self.MetaFile, DC.MODEL_FILE_DSC, True)
        self._DirectiveStack = []
        self._DirectiveEvalStack = []
        self._FileWithError = self.MetaFile
        self._FileLocalMacros = {}
        self._SectionsMacroDict.clear()
        GlobalData.gPlatformDefines = {}

        # Get all macro and PCD which has straitforward value
        self.__RetrievePcdValue()
        self._Content = self._RawTable.GetAll()
        self._ContentIndex = 0
        self._InSubsection = False
        while self._ContentIndex < len(self._Content) :
            # Id, self._ItemType, V1, V2, V3, S1, S2, S3, Owner, self._From, \
                # LineStart, ColStart, LineEnd, ColEnd, Enabled = self._Content[self._ContentIndex]

            item = self._Content[self._ContentIndex]
            Id = item.ID
            self._ItemType = item.Model
            V1 = item.Value1
            V2 = item.Value2
            V3 = item.Value3
            S1 = item.Scope1
            S2 = item.Scope2
            S3 = item.Scope3
            Owner = item.BelongsToItem
            self._From = item.FromItem
            LineStart = item.StartLine
            LineEnd = item.EndLine

            if self._From < 0:
                self._FileWithError = self.MetaFile

            self._ContentIndex += 1

            self._Scope = [[S1, S2, S3]]
            #
            # For !include directive, handle it specially,
            # merge arch and module type in case of duplicate items
            #
            while self._ItemType == DC.MODEL_META_DATA_INCLUDE:
                if self._ContentIndex >= len(self._Content):
                    break
                Record = self._Content[self._ContentIndex]
                if LineStart == Record.StartLine and LineEnd == Record.EndLine:
                    if [Record.Scope1, Record.Scope2, Record.Scope3] not in self._Scope:
                        self._Scope.append([Record.Scope1, Record.Scope2, Record.Scope3])
                    self._ContentIndex += 1
                else:
                    break

            self._LineIndex = LineStart - 1
            self._ValueList = [V1, V2, V3]

            if Owner > 0 and Owner in self._IdMapping:
                self._InSubsection = True
            else:
                self._InSubsection = False
            try:
                Processer[self._ItemType]()
            except EvaluationException as Excpt:
                #
                # Only catch expression evaluation error here. We need to report
                # the precise number of line on which the error occurred
                #
                if hasattr(Excpt, 'Pcd'):
                    if Excpt.Pcd in GlobalData.gPlatformOtherPcds:
                        Info = GlobalData.gPlatformOtherPcds[Excpt.Pcd]
                        EdkLogger.error('Parser', FORMAT_INVALID, "Cannot use this PCD (%s) in an expression as"
                                        " it must be defined in a [PcdsFixedAtBuild] or [PcdsFeatureFlag] section"
                                        " of the DSC file, and it is currently defined in this section:"
                                        " %s, line #: %d." % (Excpt.Pcd, Info[0], Info[1]),
                                    File=self._FileWithError, ExtraData=' '.join(self._ValueList),
                                    Line=self._LineIndex + 1)
                    else:
                        EdkLogger.error('Parser', FORMAT_INVALID, "PCD (%s) is not defined in DSC file" % Excpt.Pcd,
                                    File=self._FileWithError, ExtraData=' '.join(self._ValueList),
                                    Line=self._LineIndex + 1)
                else:
                    EdkLogger.error('Parser', FORMAT_INVALID, "Invalid expression: %s" % str(Excpt),
                                    File=self._FileWithError, ExtraData=' '.join(self._ValueList),
                                    Line=self._LineIndex + 1)
            except MacroException as Excpt:
                EdkLogger.error('Parser', FORMAT_INVALID, str(Excpt),
                                File=self._FileWithError, ExtraData=' '.join(self._ValueList),
                                Line=self._LineIndex + 1)

            if self._ValueList is None:
                continue

            NewOwner = self._IdMapping.get(Owner, -1)
            self._Enabled = (not self._DirectiveEvalStack) or (False not in self._DirectiveEvalStack)
            self._LastItem = self._Store(
                                self._ItemType,
                                self._ValueList[0],
                                self._ValueList[1],
                                self._ValueList[2],
                                S1,
                                S2,
                                S3,
                                NewOwner,
                                self._From,
                                self._LineIndex + 1,
                                - 1,
                                self._LineIndex + 1,
                                - 1,
                                "",
                                "",
                                "",
                                self._Enabled
                                )
            self._IdMapping[Id] = self._LastItem

        GlobalData.gPlatformDefines.update(self._FileLocalMacros)
        self._PostProcessed = True
        self._Content = None
    def _ProcessError(self):
        if not self._Enabled:
            return
        EdkLogger.error('Parser', ERROR_STATEMENT, self._ValueList[1], File=self.MetaFile, Line=self._LineIndex + 1)

    def __ProcessSectionHeader(self):
        self._SectionName = self._ValueList[0]
        if self._SectionName in self.DataType:
            self._SectionType = self.DataType[self._SectionName]
        else:
            self._SectionType = DC.MODEL_UNKNOWN

    def __ProcessSubsectionHeader(self):
        self._SubsectionName = self._ValueList[0]
        if self._SubsectionName in self.DataType:
            self._SubsectionType = self.DataType[self._SubsectionName]
        else:
            self._SubsectionType = DC.MODEL_UNKNOWN

    def __RetrievePcdValue(self):
        try:
            with open(str(self.MetaFile), 'r') as File:
                Content = File.readlines()
        except:
            EdkLogger.error("Parser", FILE_READ_FAILURE, ExtraData=self.MetaFile)

        GlobalData.gPlatformOtherPcds['DSCFILE'] = str(self.MetaFile)
        for PcdType in (DC.MODEL_PCD_PATCHABLE_IN_MODULE, DC.MODEL_PCD_DYNAMIC_DEFAULT, DC.MODEL_PCD_DYNAMIC_HII,
                        DC.MODEL_PCD_DYNAMIC_VPD, DC.MODEL_PCD_DYNAMIC_EX_DEFAULT, DC.MODEL_PCD_DYNAMIC_EX_HII,
                        DC.MODEL_PCD_DYNAMIC_EX_VPD):
            Records = self._RawTable.Query(PcdType, BelongsToItem= -1.0)
            #for TokenSpaceGuid, PcdName, Value, Dummy2, Dummy3, Dummy4, ID, Line in Records:
            for item in Records:
                TokenSpaceGuid = item.Value1
                PcdName = item.Value2
                Line = item.StartLine
                Name = TokenSpaceGuid + '.' + PcdName
                if Name not in GlobalData.gPlatformOtherPcds:
                    PcdLine = Line
                    while not Content[Line - 1].lstrip().startswith(DT.TAB_SECTION_START):
                        Line -= 1
                    GlobalData.gPlatformOtherPcds[Name] = (CleanString(Content[Line - 1]), PcdLine, PcdType)

    def __ProcessDefine(self):
        if not self._Enabled:
            return

        Type, Name, Value = self._ValueList
        Value = ReplaceMacro(Value, self._Macros, False)
        #
        # If it is <Defines>, return
        #
        if self._InSubsection:
            self._ValueList = [Type, Name, Value]
            return

        if self._ItemType == DC.MODEL_META_DATA_DEFINE:
            if self._SectionType == DC.MODEL_META_DATA_HEADER:
                self._FileLocalMacros[Name] = Value
            else:
                self._ConstructSectionMacroDict(Name, Value)
        elif self._ItemType == DC.MODEL_META_DATA_GLOBAL_DEFINE:
            GlobalData.gEdkGlobal[Name] = Value

        #
        # Keyword in [Defines] section can be used as Macros
        #
        if (self._ItemType == DC.MODEL_META_DATA_HEADER) and (self._SectionType == DC.MODEL_META_DATA_HEADER):
            self._FileLocalMacros[Name] = Value

        self._ValueList = [Type, Name, Value]

    def __ProcessDirective(self):
        Result = None
        if self._ItemType in [DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF,
                             DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSEIF]:
            Macros = self._Macros
            Macros.update(GlobalData.gGlobalDefines)
            try:
                Result = ValueExpression(self._ValueList[1], Macros)()
            except SymbolNotFound as Exc:
                EdkLogger.debug(EdkLogger.DEBUG_5, str(Exc), self._ValueList[1])
                Result = False
            except WrnExpression as Excpt:
                #
                # Catch expression evaluation warning here. We need to report
                # the precise number of line and return the evaluation result
                #
                EdkLogger.warn('Parser', "Suspicious expression: %s" % str(Excpt),
                                File=self._FileWithError, ExtraData=' '.join(self._ValueList),
                                Line=self._LineIndex + 1)
                Result = Excpt.result

        if self._ItemType in [DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF,
                              DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFDEF,
                              DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF]:
            self._DirectiveStack.append(self._ItemType)
            if self._ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF:
                Result = bool(Result)
            else:
                Macro = self._ValueList[1]
                Macro = Macro[2:-1] if (Macro.startswith("$(") and Macro.endswith(")")) else Macro
                Result = Macro in self._Macros
                if self._ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF:
                    Result = not Result
            self._DirectiveEvalStack.append(Result)
        elif self._ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSEIF:
            self._DirectiveStack.append(self._ItemType)
            self._DirectiveEvalStack[-1] = not self._DirectiveEvalStack[-1]
            self._DirectiveEvalStack.append(bool(Result))
        elif self._ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ELSE:
            self._DirectiveStack.append(self._ItemType)
            self._DirectiveEvalStack[-1] = not self._DirectiveEvalStack[-1]
            self._DirectiveEvalStack.append(True)
        elif self._ItemType == DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_ENDIF:
            # Back to the nearest !if/!ifdef/!ifndef
            while self._DirectiveStack:
                self._DirectiveEvalStack.pop()
                Directive = self._DirectiveStack.pop()
                if Directive in [DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IF,
                                 DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFDEF,
                                 DC.MODEL_META_DATA_CONDITIONAL_STATEMENT_IFNDEF]:
                    break
        elif self._ItemType == DC.MODEL_META_DATA_INCLUDE:
            # The included file must be relative to workspace or same directory as DSC file
            __IncludeMacros = {}
            #
            # Allow using system environment variables  in path after !include
            #
            __IncludeMacros['WORKSPACE'] = GlobalData.gGlobalDefines['WORKSPACE']
            #
            # Allow using MACROs comes from [Defines] section to keep compatible.
            #
            __IncludeMacros.update(self._Macros)

            IncludedFile = NormPath(ReplaceMacro(self._ValueList[1], __IncludeMacros, RaiseError=True))
            #
            # First search the include file under the same directory as DSC file
            #
            IncludedFile1 = PathClass(IncludedFile, self.MetaFile.Dir)
            if self._Enabled:
                ErrorCode, ErrorInfo1 = IncludedFile1.Validate()
                if ErrorCode != 0:
                    #
                    # Also search file under the WORKSPACE directory
                    #
                    IncludedFile1 = PathClass(IncludedFile, GlobalData.gWorkspace)
                    ErrorCode, ErrorInfo2 = IncludedFile1.Validate()
                    if ErrorCode != 0:
                        EdkLogger.error('parser', ErrorCode, File=self._FileWithError,
                                        Line=self._LineIndex + 1, ExtraData=ErrorInfo1 + "\n" + ErrorInfo2)

                self._FileWithError = IncludedFile1

                FromItem = self._Content[self._ContentIndex - 1].ID
                if self._InSubsection:
                    Owner = self._Content[self._ContentIndex - 1].BelongsToItem
                else:
                    Owner = self._Content[self._ContentIndex - 1].ID
                IncludedFileTable = MetaFileStorage(IncludedFile1, DC.MODEL_FILE_DSC, False, FromItem=FromItem)
                self.IncludedFiles.add (IncludedFile1)
                Parser = DscParser(IncludedFile1, self._FileType, self._Arch, IncludedFileTable,
                                   Owner=Owner, From=FromItem)

                

                # set the parser status with current status
                Parser._SectionName = self._SectionName
                Parser._SubsectionType = self._SubsectionType
                Parser._InSubsection = self._InSubsection
                Parser._SectionType = self._SectionType
                Parser._Scope = self._Scope
                Parser._Enabled = self._Enabled
                # Parse the included file
                Parser.StartParse()
                # Insert all records in the table for the included file into dsc file table
                Records = IncludedFileTable.GetAll()
                if Records:
                    self._Content[self._ContentIndex:self._ContentIndex] = Records
                    self._Content.pop(self._ContentIndex - 1)
                    self._ValueList = None
                    self._ContentIndex -= 1

    def __ProcessPackages(self):
        self._ValueList[0] = ReplaceMacro(self._ValueList[0], self._Macros)

    def __ProcessSkuId(self):
        self._ValueList = [ReplaceMacro(Value, self._Macros, RaiseError=True)
                           for Value in self._ValueList]
    def __ProcessDefaultStores(self):
        self._ValueList = [ReplaceMacro(Value, self._Macros, RaiseError=True)
                           for Value in self._ValueList]

    def __ProcessLibraryInstance(self):
        self._ValueList = [ReplaceMacro(Value, self._Macros) for Value in self._ValueList]

    def __ProcessLibraryClass(self):
        self._ValueList[1] = ReplaceMacro(self._ValueList[1], self._Macros, RaiseError=True)

    def __ProcessPcd(self):
        if self._ItemType not in [DC.MODEL_PCD_FEATURE_FLAG, DC.MODEL_PCD_FIXED_AT_BUILD]:
            self._ValueList[2] = ReplaceMacro(self._ValueList[2], self._Macros, RaiseError=True)
            return

        ValList, Valid, Index = AnalyzeDscPcd(self._ValueList[2], self._ItemType)
        if not Valid:
            if self._ItemType in (DC.MODEL_PCD_DYNAMIC_DEFAULT, DC.MODEL_PCD_DYNAMIC_EX_DEFAULT, DC.MODEL_PCD_FIXED_AT_BUILD, DC.MODEL_PCD_PATCHABLE_IN_MODULE):
                if ValList[1] != DT.TAB_VOID and StructPattern.match(ValList[1]) is None and ValList[2]:
                    EdkLogger.error('build', FORMAT_INVALID, "Pcd format incorrect. The datum type info should be VOID* or a valid struct name.", File=self._FileWithError,
                                    Line=self._LineIndex + 1, ExtraData="%s.%s|%s" % (self._ValueList[0], self._ValueList[1], self._ValueList[2]))
            EdkLogger.error('build', FORMAT_INVALID, "Pcd format incorrect.", File=self._FileWithError, Line=self._LineIndex + 1,
                            ExtraData="%s.%s|%s" % (self._ValueList[0], self._ValueList[1], self._ValueList[2]))
        PcdValue = ValList[Index]
        if PcdValue and "." not in self._ValueList[0]:
            try:
                ValList[Index] = ValueExpression(PcdValue, self._Macros)(True)
            except WrnExpression as Value:
                ValList[Index] = Value.result
            except:
                pass

        if ValList[Index] == 'True':
            ValList[Index] = '1'
        if ValList[Index] == 'False':
            ValList[Index] = '0'

        if (not self._DirectiveEvalStack) or (False not in self._DirectiveEvalStack):
            GlobalData.gPlatformPcds[DT.TAB_SPLIT.join(self._ValueList[0:2])] = PcdValue
            self._Symbols[DT.TAB_SPLIT.join(self._ValueList[0:2])] = PcdValue
        try:
            self._ValueList[2] = '|'.join(ValList)
        except Exception:
            print(ValList)

    def __ProcessComponent(self):
        self._ValueList[0] = ReplaceMacro(self._ValueList[0], self._Macros)

    def __ProcessBuildOption(self):
        self._ValueList = [ReplaceMacro(Value, self._Macros, RaiseError=False)
                           for Value in self._ValueList]

    def DisableOverrideComponent(self,module_id):
        for ori_id in self._IdMapping:
            if self._IdMapping[ori_id] == module_id:
                self._RawTable.DisableComponent(ori_id)

    _SectionParser = {
        DC.MODEL_META_DATA_HEADER                          :   _DefineParser,
        DC.MODEL_EFI_SKU_ID                                :   _SkuIdParser,
        DC.MODEL_EFI_DEFAULT_STORES                        :   _DefaultStoresParser,
        DC.MODEL_EFI_LIBRARY_INSTANCE                      :   _LibraryInstanceParser,
        DC.MODEL_EFI_LIBRARY_CLASS                         :   _LibraryClassParser,
        DC.MODEL_PCD_FIXED_AT_BUILD                        :   _PcdParser,
        DC.MODEL_PCD_PATCHABLE_IN_MODULE                   :   _PcdParser,
        DC.MODEL_PCD_FEATURE_FLAG                          :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_DEFAULT                       :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_HII                           :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_VPD                           :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_EX_DEFAULT                    :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_EX_HII                        :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_EX_VPD                        :   _PcdParser,
        DC.MODEL_META_DATA_COMPONENT                       :   _ComponentParser,
        DC.MODEL_META_DATA_BUILD_OPTION                    :   _BuildOptionParser,
        DC.MODEL_UNKNOWN                                   :   MetaFileParser._Skip,
        DC.MODEL_META_DATA_PACKAGE                         :   MetaFileParser._PackageParser,
        DC.MODEL_META_DATA_USER_EXTENSION                  :   MetaFileParser._SkipUserExtension,
        DC.MODEL_META_DATA_SECTION_HEADER                  :   MetaFileParser._SectionHeaderParser,
        DC.MODEL_META_DATA_SUBSECTION_HEADER               :   _SubsectionHeaderParser,
    }

## DEC file parser class
#
#   @param      FilePath        The path of platform description file
#   @param      FileType        The raw data of DSC file
#   @param      Table           Database used to retrieve module/package information
#   @param      Macros          Macros used for replacement in file
#
class DecParser(MetaFileParser):
    # DEC file supported data types (one type per section)
    DataType = {
        DT.TAB_DEC_DEFINES.upper()                     :   DC.MODEL_META_DATA_HEADER,
        DT.TAB_DSC_DEFINES_DEFINE                      :   DC.MODEL_META_DATA_DEFINE,
        DT.TAB_INCLUDES.upper()                        :   DC.MODEL_EFI_INCLUDE,
        DT.TAB_LIBRARY_CLASSES.upper()                 :   DC.MODEL_EFI_LIBRARY_CLASS,
        DT.TAB_GUIDS.upper()                           :   DC.MODEL_EFI_GUID,
        DT.TAB_PPIS.upper()                            :   DC.MODEL_EFI_PPI,
        DT.TAB_PROTOCOLS.upper()                       :   DC.MODEL_EFI_PROTOCOL,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_FIXED_AT_BUILD.upper()        :   DC.MODEL_PCD_FIXED_AT_BUILD,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_PATCHABLE_IN_MODULE.upper()   :   DC.MODEL_PCD_PATCHABLE_IN_MODULE,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_FEATURE_FLAG.upper()          :   DC.MODEL_PCD_FEATURE_FLAG,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC.upper()               :   DC.MODEL_PCD_DYNAMIC,
        DT.TAB_PCDS.upper() + DT.TAB_PCDS_DYNAMIC_EX.upper()            :   DC.MODEL_PCD_DYNAMIC_EX,
        DT.TAB_USER_EXTENSIONS.upper()                 :   DC.MODEL_META_DATA_USER_EXTENSION,
    }

    ## Constructor of DecParser
    #
    #  Initialize object of DecParser
    #
    #   @param      FilePath        The path of platform description file
    #   @param      FileType        The raw data of DSC file
    #   @param      Arch            Default Arch value for filtering sections
    #   @param      Table           Database used to retrieve module/package information
    #
    def __init__(self, FilePath, FileType, Arch, Table):
        # prevent re-initialization
        if hasattr(self, "_Table"):
            return
        MetaFileParser.__init__(self, FilePath, FileType, Arch, Table, -1)
        self._Comments = []
        self._Version = 0x00010005  # Only EDK2 dec file is supported
        self._AllPCDs = [] # Only for check duplicate PCD
        self._AllPcdDict = {}

        self._CurrentStructurePcdName = ""
        self._include_flag = False
        self._package_flag = False

        self._RestofValue = ""

    ## Parser starter
    def Start(self):
        Content = ''
        try:
            with open(str(self.MetaFile), 'r') as File:
                Content = File.readlines()
        except:
            EdkLogger.error("Parser", FILE_READ_FAILURE, ExtraData=self.MetaFile)

        Content = self.ProcessMultipleLineCODEValue(Content)

        self._DefinesCount = 0
        for Index in range(0, len(Content)):
            Line, Comment = CleanString2(Content[Index])
            self._CurrentLine = Line
            self._LineIndex = Index

            # save comment for later use
            if Comment:
                self._Comments.append((Comment, self._LineIndex + 1))
            # skip empty line
            if Line == '':
                continue

            # section header
            if Line[0] == DT.TAB_SECTION_START and Line[-1] == DT.TAB_SECTION_END:
                self._SectionHeaderParser()
                if self._SectionName == DT.TAB_DEC_DEFINES.upper():
                    self._DefinesCount += 1
                self._Comments = []
                continue
            if self._SectionType == DC.MODEL_UNKNOWN:
                EdkLogger.error("Parser", FORMAT_INVALID,
                                ""
                                "Not able to determine \"%s\" in which section."%self._CurrentLine,
                                self.MetaFile, self._LineIndex + 1)
            elif len(self._SectionType) == 0:
                self._Comments = []
                continue

            # section content
            self._ValueList = ['', '', '']
            self._SectionParser[self._SectionType[0]](self)
            if self._ValueList is None or self._ItemType == DC.MODEL_META_DATA_DEFINE:
                self._ItemType = -1
                self._Comments = []
                continue

            #
            # Model, Value1, Value2, Value3, Arch, BelongsToItem=-1, LineBegin=-1,
            # ColumnBegin=-1, LineEnd=-1, ColumnEnd=-1, FeatureFlag='', Enabled=-1
            #
            for Arch, ModuleType, Type in self._Scope:
                self._LastItem = self._Store(
                    Type,
                    self._ValueList[0],
                    self._ValueList[1],
                    self._ValueList[2],
                    Arch,
                    ModuleType,
                    self._Owner[-1],
                    self._LineIndex + 1,
                    - 1,
                    self._LineIndex + 1,
                    - 1,
                    True
                    )
                for Comment, LineNo in self._Comments:
                    self._Store(
                        DC.MODEL_META_DATA_COMMENT,
                        Comment,
                        self._ValueList[0],
                        self._ValueList[1],
                        Arch,
                        ModuleType,
                        self._LastItem,
                        LineNo,
                        - 1,
                        LineNo,
                        - 1,
                        True
                        )
            self._Comments = []
        if self._DefinesCount > 1:
            EdkLogger.error('Parser', FORMAT_INVALID, 'Multiple [Defines] section is exist.', self.MetaFile )
        if self._DefinesCount == 0:
            EdkLogger.error('Parser', FORMAT_INVALID, 'No [Defines] section exist.', self.MetaFile)
        self._Done()


    ## Section header parser
    #
    #   The section header is always in following format:
    #
    #       [section_name.arch<.platform|module_type>]
    #
    def _SectionHeaderParser(self):
        self._Scope = []
        self._SectionName = ''
        self._SectionType = []
        ArchList = set()
        PrivateList = set()
        Line = re.sub(',[\s]*', DT.TAB_COMMA_SPLIT, self._CurrentLine)
        for Item in Line[1:-1].split(DT.TAB_COMMA_SPLIT):
            if Item == '':
                EdkLogger.error("Parser", FORMAT_UNKNOWN_ERROR,
                                "section name can NOT be empty or incorrectly use separator comma",
                                self.MetaFile, self._LineIndex + 1, self._CurrentLine)
            ItemList = Item.split(DT.TAB_SPLIT)

            # different types of PCD are permissible in one section
            self._SectionName = ItemList[0].upper()
            if self._SectionName == DT.TAB_DEC_DEFINES.upper() and (len(ItemList) > 1 or len(Line.split(DT.TAB_COMMA_SPLIT)) > 1):
                EdkLogger.error("Parser", FORMAT_INVALID, "Defines section format is invalid",
                                self.MetaFile, self._LineIndex + 1, self._CurrentLine)
            if self._SectionName in self.DataType:
                if self.DataType[self._SectionName] not in self._SectionType:
                    self._SectionType.append(self.DataType[self._SectionName])
            else:
                EdkLogger.error("Parser", FORMAT_UNKNOWN_ERROR, "%s is not a valid section name" % Item,
                                self.MetaFile, self._LineIndex + 1, self._CurrentLine)

            if DC.MODEL_PCD_FEATURE_FLAG in self._SectionType and len(self._SectionType) > 1:
                EdkLogger.error(
                            'Parser',
                            FORMAT_INVALID,
                            "%s must not be in the same section of other types of PCD" % DT.TAB_PCDS_FEATURE_FLAG_NULL,
                            File=self.MetaFile,
                            Line=self._LineIndex + 1,
                            ExtraData=self._CurrentLine
                            )
            # S1 is always Arch
            if len(ItemList) > 1:
                S1 = ItemList[1].upper()
            else:
                S1 = DT.TAB_ARCH_COMMON
            ArchList.add(S1)
            # S2 may be Platform or ModuleType
            if len(ItemList) > 2:
                S2 = ItemList[2].upper()
                # only Includes, GUIDs, PPIs, Protocols section have Private tag
                if self._SectionName in [DT.TAB_INCLUDES.upper(), DT.TAB_GUIDS.upper(), DT.TAB_PROTOCOLS.upper(), DT.TAB_PPIS.upper()]:
                    if S2 != 'PRIVATE':
                        EdkLogger.error("Parser", FORMAT_INVALID, 'Please use keyword "Private" as section tag modifier.',
                                        File=self.MetaFile, Line=self._LineIndex + 1, ExtraData=self._CurrentLine)
            else:
                S2 = DT.TAB_COMMON
            PrivateList.add(S2)
            if [S1, S2, self.DataType[self._SectionName]] not in self._Scope:
                self._Scope.append([S1, S2, self.DataType[self._SectionName]])

        # 'COMMON' must not be used with specific ARCHs at the same section
        if DT.TAB_ARCH_COMMON in ArchList and len(ArchList) > 1:
            EdkLogger.error('Parser', FORMAT_INVALID, "'common' ARCH must not be used with specific ARCHs",
                            File=self.MetaFile, Line=self._LineIndex + 1, ExtraData=self._CurrentLine)

        # It is not permissible to mix section tags without the Private attribute with section tags with the Private attribute
        if DT.TAB_COMMON in PrivateList and len(PrivateList) > 1:
            EdkLogger.error('Parser', FORMAT_INVALID, "Can't mix section tags without the Private attribute with section tags with the Private attribute",
                            File=self.MetaFile, Line=self._LineIndex + 1, ExtraData=self._CurrentLine)

    ## [guids], [ppis] and [protocols] section parser
    @ParseMacro
    def _GuidParser(self):
        TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_EQUAL_SPLIT, 1)
        if len(TokenList) < 2:
            EdkLogger.error('Parser', FORMAT_INVALID, "No GUID name or value specified",
                            ExtraData=self._CurrentLine + " (<CName> = <GuidValueInCFormat>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if TokenList[0] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No GUID name specified",
                            ExtraData=self._CurrentLine + " (<CName> = <GuidValueInCFormat>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if TokenList[1] == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "No GUID value specified",
                            ExtraData=self._CurrentLine + " (<CName> = <GuidValueInCFormat>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        if TokenList[1][0] != '{' or TokenList[1][-1] != '}' or GuidStructureStringToGuidString(TokenList[1]) == '':
            EdkLogger.error('Parser', FORMAT_INVALID, "Invalid GUID value format",
                            ExtraData=self._CurrentLine + \
                                      " (<CName> = <GuidValueInCFormat:{8,4,4,{2,2,2,2,2,2,2,2}}>)",
                            File=self.MetaFile, Line=self._LineIndex + 1)
        self._ValueList[0] = TokenList[0]
        self._ValueList[1] = TokenList[1]
        if self._ValueList[0] not in self._GuidDict:
            self._GuidDict[self._ValueList[0]] = self._ValueList[1]

    def ParsePcdName(self,namelist):
        if "[" in namelist[1]:
            pcdname = namelist[1][:namelist[1].index("[")]
            arrayindex = namelist[1][namelist[1].index("["):]
            namelist[1] = pcdname
            if len(namelist) == 2:
                namelist.append(arrayindex)
            else:
                namelist[2] = ".".join((arrayindex,namelist[2]))
        return namelist

    ## PCD sections parser
    #
    #   [PcdsFixedAtBuild]
    #   [PcdsPatchableInModule]
    #   [PcdsFeatureFlag]
    #   [PcdsDynamicEx
    #   [PcdsDynamic]
    #
    @ParseMacro
    def _PcdParser(self):

        if self._CurrentStructurePcdName:
            self._ValueList[0] = self._CurrentStructurePcdName

            if "|" not in self._CurrentLine:
                if "<HeaderFiles>" == self._CurrentLine:
                    self._include_flag = True
                    self._package_flag = False
                    self._ValueList = None
                    return
                if "<Packages>" == self._CurrentLine:
                    self._package_flag = True
                    self._ValueList = None
                    self._include_flag = False
                    return

                if self._include_flag:
                    self._ValueList[1] = "<HeaderFiles>_" + md5(self._CurrentLine.encode('utf-8')).hexdigest()
                    self._ValueList[2] = self._CurrentLine
                if self._package_flag and "}" != self._CurrentLine:
                    self._ValueList[1] = "<Packages>_" + md5(self._CurrentLine.encode('utf-8')).hexdigest()
                    self._ValueList[2] = self._CurrentLine
                if self._CurrentLine == "}":
                    self._package_flag = False
                    self._include_flag = False
                    self._ValueList = None
                    return
            else:
                PcdTockens = self._CurrentLine.split(DT.TAB_VALUE_SPLIT)
                PcdNames = self.ParsePcdName(PcdTockens[0].split(DT.TAB_SPLIT))
                if len(PcdNames) == 2:
                    if PcdNames[1].strip().endswith("]"):
                        PcdName = PcdNames[1][:PcdNames[1].index('[')]
                        Index = PcdNames[1][PcdNames[1].index('['):]
                        self._ValueList[0] = DT.TAB_SPLIT.join((PcdNames[0],PcdName))
                        self._ValueList[1] = Index
                        self._ValueList[2] = PcdTockens[1]
                    else:
                        self._CurrentStructurePcdName = ""
                else:
                    if self._CurrentStructurePcdName != DT.TAB_SPLIT.join(PcdNames[:2]):
                        EdkLogger.error('Parser', FORMAT_INVALID, "Pcd Name does not match: %s and %s " % (self._CurrentStructurePcdName, DT.TAB_SPLIT.join(PcdNames[:2])),
                                File=self.MetaFile, Line=self._LineIndex + 1)
                    self._ValueList[1] = DT.TAB_SPLIT.join(PcdNames[2:])
                    self._ValueList[2] = PcdTockens[1]
        if not self._CurrentStructurePcdName:
            if self._PcdDataTypeCODE:
                if ")}" in self._CurrentLine:
                    ValuePart,RestofValue = self._CurrentLine.split(")}")
                    self._PcdCodeValue = self._PcdCodeValue + "\n " + ValuePart
                    self._CurrentLine = "|".join((self._CurrentPcdName, self._PcdCodeValue,RestofValue))
                    self._PcdDataTypeCODE = False
                    self._PcdCodeValue = ""
                else:
                    self._PcdCodeValue = self._PcdCodeValue + "\n " + self._CurrentLine
                    self._ValueList = None
                    return
            TokenList = GetSplitValueList(self._CurrentLine, DT.TAB_VALUE_SPLIT, 1)
            self._CurrentPcdName = TokenList[0]
            if len(TokenList) == 2 and TokenList[1].strip().startswith("{CODE"):
                if ")}" in self._CurrentLine:
                    self._PcdDataTypeCODE = False
                    self._PcdCodeValue = ""
                else:
                    self._PcdDataTypeCODE = True
                    self._PcdCodeValue = TokenList[1].strip()
                    self._ValueList = None
                    return

            self._ValueList[0:1] = GetSplitValueList(TokenList[0], DT.TAB_SPLIT)
            ValueRe = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*')
            # check PCD information
            if self._ValueList[0] == '' or self._ValueList[1] == '':
                EdkLogger.error('Parser', FORMAT_INVALID, "No token space GUID or PCD name specified",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check format of token space GUID CName
            if not ValueRe.match(self._ValueList[0]):
                EdkLogger.error('Parser', FORMAT_INVALID, "The format of the token space GUID CName is invalid. The correct format is '(a-zA-Z_)[a-zA-Z0-9_]*'",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check format of PCD CName
            if not ValueRe.match(self._ValueList[1]):
                EdkLogger.error('Parser', FORMAT_INVALID, "The format of the PCD CName is invalid. The correct format is '(a-zA-Z_)[a-zA-Z0-9_]*'",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check PCD datum information
            if len(TokenList) < 2 or TokenList[1] == '':
                EdkLogger.error('Parser', FORMAT_INVALID, "No PCD Datum information given",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)


            ValueRe = re.compile(r'^\s*L?\".*\|.*\"')
            PtrValue = ValueRe.findall(TokenList[1])

            # Has VOID* type string, may contain "|" character in the string.
            if len(PtrValue) != 0:
                ptrValueList = re.sub(ValueRe, '', TokenList[1])
                ValueList = AnalyzePcdExpression(ptrValueList)
                ValueList[0] = PtrValue[0]
            else:
                ValueList = AnalyzePcdExpression(TokenList[1])


            # check if there's enough datum information given
            if len(ValueList) != 3:
                EdkLogger.error('Parser', FORMAT_INVALID, "Invalid PCD Datum information given",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check default value
            if ValueList[0] == '':
                EdkLogger.error('Parser', FORMAT_INVALID, "Missing DefaultValue in PCD Datum information",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check datum type
            if ValueList[1] == '':
                EdkLogger.error('Parser', FORMAT_INVALID, "Missing DatumType in PCD Datum information",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)
            # check token of the PCD
            if ValueList[2] == '':
                EdkLogger.error('Parser', FORMAT_INVALID, "Missing Token in PCD Datum information",
                                ExtraData=self._CurrentLine + \
                                          " (<TokenSpaceGuidCName>.<PcdCName>|<DefaultValue>|<DatumType>|<Token>)",
                                File=self.MetaFile, Line=self._LineIndex + 1)

            PcdValue = ValueList[0]
            if PcdValue:
                try:
                    self._GuidDict.update(self._AllPcdDict)
                    ValueList[0] = ValueExpressionEx(ValueList[0], ValueList[1], self._GuidDict)(True)
                except BadExpression as Value:
                    EdkLogger.error('Parser', FORMAT_INVALID, Value, ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
            # check format of default value against the datum type
            IsValid, Cause = CheckPcdDatum(ValueList[1], ValueList[0])
            if not IsValid:
                EdkLogger.error('Parser', FORMAT_INVALID, Cause, ExtraData=self._CurrentLine,
                                File=self.MetaFile, Line=self._LineIndex + 1)

            if Cause == "StructurePcd":
                self._CurrentStructurePcdName = DT.TAB_SPLIT.join(self._ValueList[0:2])
                self._ValueList[0] = self._CurrentStructurePcdName
                self._ValueList[1] = ValueList[1].strip()

            if ValueList[0] in ['True', 'true', 'TRUE']:
                ValueList[0] = '1'
            elif ValueList[0] in ['False', 'false', 'FALSE']:
                ValueList[0] = '0'

            # check for duplicate PCD definition
            if (self._Scope[0], self._ValueList[0], self._ValueList[1]) in self._AllPCDs:
                EdkLogger.error('Parser', FORMAT_INVALID,
                                "The same PCD name and GUID have been already defined",
                                ExtraData=self._CurrentLine, File=self.MetaFile, Line=self._LineIndex + 1)
            else:
                self._AllPCDs.append((self._Scope[0], self._ValueList[0], self._ValueList[1]))
                self._AllPcdDict[DT.TAB_SPLIT.join(self._ValueList[0:2])] = ValueList[0]

            self._ValueList[2] = ValueList[0].strip() + '|' + ValueList[1].strip() + '|' + ValueList[2].strip()

    _SectionParser = {
        DC.MODEL_META_DATA_HEADER          :   MetaFileParser._DefineParser,
        DC.MODEL_EFI_INCLUDE               :   MetaFileParser._PathParser,
        DC.MODEL_EFI_LIBRARY_CLASS         :   MetaFileParser._PathParser,
        DC.MODEL_EFI_GUID                  :   _GuidParser,
        DC.MODEL_EFI_PPI                   :   _GuidParser,
        DC.MODEL_EFI_PROTOCOL              :   _GuidParser,
        DC.MODEL_PCD_FIXED_AT_BUILD        :   _PcdParser,
        DC.MODEL_PCD_PATCHABLE_IN_MODULE   :   _PcdParser,
        DC.MODEL_PCD_FEATURE_FLAG          :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC               :   _PcdParser,
        DC.MODEL_PCD_DYNAMIC_EX            :   _PcdParser,
        DC.MODEL_UNKNOWN                   :   MetaFileParser._Skip,
        DC.MODEL_META_DATA_USER_EXTENSION  :   MetaFileParser._SkipUserExtension,
    }

##
#
# This acts like the main() function for the script, unless it is 'import'ed into another
# script.
#
if __name__ == '__main__':
    pass

