
## @file
# This file is used to check format of comments
#
# Copyright (c) 2012, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
from collections import OrderedDict
import CommonDataClass.DataClass as DC


class DscGen(object):
    def __init__(self):
        self.content = OrderedDict()
        self.txt = ""
        self.tab_sp = "  "
        self.arch_lst = set()

    def from_parser(self, dsc_parser):
        ''' Process the parser database and store the data in dict '''
        dsc_parser_dict = dict()
        if isinstance(dsc_parser,dict):
            dsc_parser_dict.update(dsc_parser)
            if "COMMON" not in dsc_parser_dict:
                dsc_parser_dict['COMMON'] = list(dsc_parser_dict.values())[0]
        else:
            dsc_parser_dict['COMMON'] = dsc_parser
            dsc_parser_dict[dsc_parser._Arch] = dsc_parser
        self.Set_Defines(dsc_parser_dict)
        self.Set_SkuIds(dsc_parser_dict)
        self.Set_DefaultStores(dsc_parser_dict)
        self.Set_Packages(dsc_parser_dict)
        self.Set_BuildOptions(dsc_parser_dict)
    
    def from_yaml(self, yaml_content):
        ''' Import the yaml_content into dict'''
        import yaml
        self.content = yaml.load(yaml_content)
    
    def from_json(self, json_content):
        ''' Import the json_content into dict'''
        import json
        self.content = json.loads(json_content)

    def FormatDsc(self):
        self.txt += str(Sec_Defines(self.content.get("Defines")))
        self.txt += str(Sec_SkuIds(self.content.get("SkuIds")))
        self.txt += str(Sec_DefaultStores(self.content.get("DefaultStores")))
        self.txt += str(Sec_Packages(self.content.get("Packages")))
        self.txt += str(Sec_PcdsFeatureFlag(self.content.get("PcdsFeatureFlag")))
        self.txt += str(Sec_PcdsFixedAtBuild(self.content.get("PcdsFixedAtBuild")))
        self.txt += str(Sec_BuildOptions(self.content.get("BuildOptions")))
        self.txt += str(Sec_Components(self.content.get("Components")))
        self.txt += str(Sec_LibraryClasses(self.content.get("LibraryClasses")))
        self.txt += str(Sec_PcdsPatchableInModule(self.content.get("PcdspatchableInModule")))
        self.txt += str(Sec_PcdsDynamicDefault(self.content.get("PcdsDynamicDefault")))
        self.txt += str(Sec_PcdsDynamicExDefault(self.content.get("PcdsDynamicExDefault")))
        self.txt += str(Sec_PcdsDynamicHii(self.content.get("PcdsDynamicHii")))
        self.txt += str(Sec_PcdsDynamicExHii(self.content.get("PcdsDynamicExHii")))
        self.txt += str(Sec_PcdsDynamicVpd(self.content.get("PcdsDynamicVpd")))
        self.txt += str(Sec_PcdsDynamicExVpd(self.content.get("PcdsDynamicExVpd")))
        return self.txt

    def FormatYaml(self):
        import yaml
        self.txt = yaml.dump(self.content)
        return self.txt

    def FormatJson(self):
        import json
        self.txt = json.dump(self.content)
        return self.txt

    def Set_Defines(self,dsc_parser_dict):
        dsc_parser = dsc_parser_dict.get("COMMON", list(dsc_parser_dict.values())[0])
        defines_section = OrderedDict()
        keywords = OrderedDict()
        macros = OrderedDict()
        edk_globals = OrderedDict()
        for item in dsc_parser[DC.MODEL_META_DATA_HEADER]:
            keywords[item[1]] = item[2]
        for item in dsc_parser[DC.MODEL_META_DATA_DEFINE,"COMMON","COMMON"]:
            macros[item[1]] = item[2]
        for item in dsc_parser[DC.MODEL_META_DATA_GLOBAL_DEFINE,"COMMON","COMMON"]:
            edk_globals[item[1]] = item[2]
        
        defines_section["Defines"] = keywords
        defines_section["Defines"]['DEFINE'] = macros 
        defines_section["Defines"]['EDK_GLOBAL'] = edk_globals
        self.content.update(defines_section)

    def Set_SkuIds(self, dsc_parser_dict):
        dsc_parser = dsc_parser_dict.get("COMMON", list(dsc_parser_dict.values())[0])
        skuids = OrderedDict()
        for item in dsc_parser[DC.MODEL_EFI_SKU_ID]:
            skuids[item[0]] = " | ".join((item[1], item[2])) if item[2] else item[1]

        self.content.update({"SkuIds":skuids})

    def Set_DefaultStores(self, dsc_parser_dict):
        dsc_parser = dsc_parser_dict.get("COMMON", list(dsc_parser_dict.values())[0])
        defaultstores = OrderedDict()
        for item in dsc_parser[DC.MODEL_EFI_DEFAULT_STORES]:
            defaultstores[item[0]] = " | ".join((item[1], item[2])) if item[2] else item[1]

        self.content.update({"DefaultStores":defaultstores})

    def Set_Packages(self, dsc_parser_dict):
        dsc_parser = dsc_parser_dict.get("COMMON", list(dsc_parser_dict.values())[0])
        packages = []
        for item in dsc_parser[DC.MODEL_META_DATA_PACKAGE]:
            packages.append(item[0])

        self.content.update({"Packages":packages})

    def Set_BuildOptions(self,dsc_parser_dict):
        '''
        row = [
            ToolChain,
            FLAGS,
            FLAGSValue,
            Arch,
            CodeBase, # EDKII
            ModuleType,
            ID,
            LineNum
        ]
        '''
        build_opts = OrderedDict()
        '''
        build_opts:
            Arch1:
                ModuleType1:
                    ToolChain1:
                        FLAG_1:
                            Value_1
                        FLAG_2:
                            Value_2
                    ToolChain2:
                        FLAG_3:
                            Value_3
                ModuleType2:
                    ...
            Arch2:
                ...
        '''
        for arch in dsc_parser_dict:
            dsc_parser = dsc_parser_dict[arch]
            l_build_opts = OrderedDict()
            for item in dsc_parser[DC.MODEL_META_DATA_BUILD_OPTION,arch]:
                if not item[0]:
                    toolchain = "COMMON"
                else:
                    toolchain = item[0]
                module_type = item[5]
                flag = item[1]
                flagvalue = item[2]

                if module_type not in l_build_opts:
                    l_build_opts[module_type] = OrderedDict()
                if toolchain not in l_build_opts[module_type]:
                    l_build_opts[module_type][toolchain] = OrderedDict()
                l_build_opts[module_type][toolchain][flag] = flagvalue

            build_opts[arch] = l_build_opts

        self.content.update({"BuildOptions":build_opts})

class Sec_Defines(object):
    DEFINE_STR = "DEFINE"
    EDK_GLOBAL_STR     = "EDK_GLOBAL"
    DESCRIPTION = '''
################################################################################
#
# Defines Section - statements that will be processed to create a Makefile.
#
################################################################################
'''
    def __init__(self, content):
        self.keywords = content
        self.macros = content.get("DEFINE",{})
        self.edk_globals = content.get("EDK_GLOBAL", {})
        self.tab_sp = "  "

    def __str__(self):

        section_strlst = []
        section_strlst.append(self.DESCRIPTION)
        section_strlst.append("[Defines]")
        def_len = len(self.DEFINE_STR) + 1
        glo_len = len(self.EDK_GLOBAL_STR) + 1

        key_str_width = max(
            [
                max([len(k) for k in self.keywords]),
                max([len(k) + def_len for k in self.macros]),
                max([len(k) + glo_len for k in self.edk_globals]),
            ])
        for key in self.keywords:
            if key in ["DEFINE","EDK_GLOBAL"]:
                continue
            section_strlst.append(self.tab_sp + "{0:<{width}}".format(key,width=key_str_width) + " = " + self.keywords[key])

        section_strlst.append("")
        for key in self.macros:
            section_strlst.append(self.tab_sp + "DEFINE {0:<{width}}".format(key,width = key_str_width - def_len) + " = " + self.macros[key])

        section_strlst.append("")
        for key in self.edk_globals:
            section_strlst.append(self.tab_sp + "EDK_GLOBAL {0:<{width}}".format(key,width = key_str_width - glo_len) + " = " + self.edk_globals[key])

        section_strlst.append("")
        return '\r\n'.join(section_strlst)

class Sec_SkuIds(object):
    DESCRIPTION = '''
################################################################################
#
# SKU Identification section - list of all SKU IDs supported by this Platform.
#
################################################################################
'''

    def __init__(self, content):
        self.skuids = content
        self.tab_sp = "  "

    def __str__(self):
        section_strlst = []
        section_strlst.append(self.DESCRIPTION)
        section_strlst.append("[SkuIds]")
        for key, value in self.skuids.items():
            section_strlst.append(self.tab_sp + " | ".join((key,value)))

        section_strlst.append('\r\n')
        return '\r\n'.join(section_strlst)
class Sec_DefaultStores(object):

    def __init__(self, content):
        self.defaultstores = content
        self.tab_sp = "  "

    def __str__(self):
        section_strlst = []
        section_strlst.append("[DefaultStores]")
        for key, value in self.defaultstores.items():
            section_strlst.append(self.tab_sp + " | ".join((key,value)))

        section_strlst.append('\r\n')
        return '\r\n'.join(section_strlst)

class Sec_Packages(object):
    
    def __init__(self,content):
        self.packages = content
        self.tab_sp = "  "

    def __str__(self):
        section_strlst = []
        section_strlst.append("[Packages]")
        for item in self.packages:
            section_strlst.append(self.tab_sp + item)
  
        section_strlst.append('\r\n')
        return '\r\n'.join(section_strlst)

class Sec_BuildOptions(object):

    def __init__(self, content):
        self.buildoptions = content
        self.tab_sp = "  "

    def __str__(self):
        section_strlst = []
        sections = OrderedDict()
        for arch in self.buildoptions:
            for module_type in self.buildoptions[arch]:
                for toolchain in self.buildoptions[arch][module_type]:
                    for flag in self.buildoptions[arch][module_type][toolchain]:
                        flag_value = self.buildoptions[arch][module_type][toolchain][flag]
                        if module_type == "COMMON":
                            section_head = "[" + ".".join(("BuildOptions",arch)) + "]"
                        else:
                            section_head = "[" + ".".join(("BuildOptions",arch,"EDKII",module_type)) + "]"
                        if section_head not in sections:
                            sections[section_head] = OrderedDict()
                        if toolchain not in sections[section_head]:
                            sections[section_head][toolchain] = OrderedDict()
                        sections[section_head][toolchain].update({flag:flag_value})
        for sec_head in sections:
            section_strlst.append(sec_head)
            for toolchain in sections[sec_head]:
                for flag in sections[sec_head][toolchain]:
                    flag_value = sections[sec_head][toolchain][flag]
                    if toolchain == "COMMON":
                        if flag_value.startswith("="):
                            section_strlst.append(self.tab_sp + flag + " =" + flag_value)
                        else:
                            section_strlst.append(self.tab_sp + flag + " = " + flag_value)
                    else:
                        if flag_value.startswith("="):
                            section_strlst.append(self.tab_sp + toolchain + ":" + flag + " =" + flag_value)
                        else:
                            section_strlst.append(self.tab_sp + toolchain + ":" + flag + " = " + flag_value)
            section_strlst.append("")

        return '\r\n'.join(section_strlst)

class Sec_LibraryClasses(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_Components(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""

class Sec_PcdsFeatureFlag(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsFixedAtBuild(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsPatchableInModule(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicDefault(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicHii(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicVpd(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicExDefault(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicExHii(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""
class Sec_PcdsDynamicExVpd(object):
    def __init__(self, content):
        ...
    def __str__(self):
        return ""