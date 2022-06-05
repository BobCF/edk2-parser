## @file
# This file is used to check format of comments
#
# Copyright (c) 2012, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

from collections import OrderedDict
import CommonDataClass.DataClass as DC

class DscElement(object):
    def __init__(self):
        self.key = ""
        self.value = ""
        self.settings = dict()
        self.lineNo = 0
        self.owner = "" # included dsc/inc
        self.condition = dict()
        self.seprator = "="
        self.level = 1
        self.tab_spa = "  "

    def __str__(self):
        return "%s%s %s %s" % (self.tab_spa*self.level, self.key,self.seprator,self.value)

class DscSection(object):
    def __init__(self, name):
        self.sec_head = name
        self.macros = dict()
        self.arch = "COMMON"
        self.filter1 = "COMMON"
        self.filter2 = "COMMON"
        self.data = []

    def __str__(self):
        sec_strlst = []
        filter_str = ""
        if self.filter2.upper() != "COMMON":
            filter_str = ".".join(self.arch.upper(),self.filter1.upper(),self.filter2.upper())
        elif self.filter1.upper() != "COMMON":
            filter_str = ".".join(self.arch.upper(),self.filter1.upper())
        elif self.arch.upper() != "COMMON":
            filter_str = self.arch.upper()
        else:
            filter_str = ""

        if filter_str:
            sec_head_str = "[%s.%s]" % (self.sec_head,filter_str)
        else:
            sec_head_str = "[%s]" % self.sec_head

        sec_strlst.append(sec_head_str)
        for key in self.macros:
            sec_head_str.append("  DEFINE %s = %s" % (key, self.macros[key]))

    def mark_owners(self):
        pass
class Dsc(object):
    def __init__(self, dsc_path, ext_macros, ext_pcds):
        self.dscfile = dsc_path
        self.ext_macros = ext_macros
        self.ext_pcds = ext_pcds

        self.defines = DscSection("Defines")
        self.buildoptions = DscSection("BuildOptions")
        self.skuids = DscSection("SkuIds")
        self.libraryclasses = DscSection("LibraryClasses")
        self.defaulstore = DscSection("DefaultStores")
        self.packages = DscSection("Packages")
        self.ffpcd = DscSection("PcdsFeatureFlag")
        self.fixedpcd = DscSection("PcdsFixedAtBuild")
        self.components = DscSection("Components")
        self.patchpcd = DscSection("PcdspatchableInModule")
        self.dyndefaultpcd = DscSection("PcdsDynamicDefault")
        self.dynexdefaultpcd = DscSection("PcdsDynamicExDefault")
        self.dynhiipcd = DscSection("PcdsDynamicHii")
        self.dynexhiipcd = DscSection("PcdsDynamicExHii")
        self.dynvpdpcd = DscSection("PcdsDynamicVpd")
        self.dynexvpdpcd = DscSection("PcdsDynamicExVpd")

        self.inital_dsc()
        
    def get_property(self,name):
        return self.defines.data.get(name,"")

    def inital_dsc(self):
        pass

    def format_dsc(self):
        pass

    def format_json(self):
        pass
