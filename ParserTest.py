from parsers.MetaFileParser import DscParser,InfParser,DecParser
from parsers.MetaFileTable import MetaFileStorage
from Common.Misc import PathClass
from CommonDataClass.DataClass import *
import Common.GlobalData as GlobalData
from Common.MultipleWorkspace import MultipleWorkspace as mws
import os


def TestDscParser(dsc_path,WorkspaceDir):
    dsc_parser = DscParser(PathClass(dsc_path,WorkspaceDir),MODEL_FILE_DSC,"IA32",
                                MetaFileStorage(PathClass(dsc_path,WorkspaceDir), MODEL_FILE_DSC))
    
    # '''
    #     ['OvmfPkg/ResetVector/ResetVector.inf', '', '', 'COMMON', 'COMMON', 'COMMON', 474, 584]
    # '''
    # for item in dsc_parser[MODEL_META_DATA_COMPONENT,"IA32"]:
    #     print(item)
    # print("--------------x64---------------")
    # for item in dsc_parser[MODEL_META_DATA_COMPONENT,"X64"]:
    #     print(item)

    # '''
    #     ['gEfiMdeModulePkgTokenSpaceGuid', 'PcdStatusCodeMemorySize', '1', 'COMMON', 'COMMON', 'COMMON', 359, 438]
    # '''
    # for item in dsc_parser[MODEL_PCD_FIXED_AT_BUILD]:
    #     print (item)

    '''
        ['', 'PLATFORM_NAME', 'Ovmf', 'COMMON', 'COMMON', 'COMMON', 2, 17]
        ['', 'PLATFORM_GUID', '5a9e7754-d81b-49ea-85ad-69eaa7b1539b', 'COMMON', 'COMMON', 'COMMON', 3, 18]
        ['', 'PLATFORM_VERSION', '0.1', 'COMMON', 'COMMON', 'COMMON', 4, 19]
        ['', 'DSC_SPECIFICATION', '0x00010005', 'COMMON', 'COMMON', 'COMMON', 5, 20]
        ['', 'OUTPUT_DIRECTORY', 'Build/OvmfIa32', 'COMMON', 'COMMON', 'COMMON', 6, 21]
        ['', 'SUPPORTED_ARCHITECTURES', 'IA32', 'COMMON', 'COMMON', 'COMMON', 7, 22]
        ['', 'BUILD_TARGETS', 'NOOPT|DEBUG|RELEASE', 'COMMON', 'COMMON', 'COMMON', 8, 23]
        ['', 'SKUID_IDENTIFIER', 'DEFAULT', 'COMMON', 'COMMON', 'COMMON', 9, 24]
        ['', 'FLASH_DEFINITION', 'OvmfPkg/OvmfPkgIa32.fdf', 'COMMON', 'COMMON', 'COMMON', 10, 25]
    '''
    for item in dsc_parser[MODEL_META_DATA_HEADER]:
        print(item)

    ['0', 'DEFAULT', '', 'COMMON', 'COMMON', 'COMMON', 57, 99]
    for item in dsc_parser[MODEL_EFI_SKU_ID]:
        print(item)
    for item in dsc_parser[MODEL_META_DATA_DEFINE,"COMMON","COMMON"]:
        print(item)
    for item in dsc_parser[MODEL_META_DATA_GLOBAL_DEFINE,"COMMON","COMMON"]:
        print(item)

    for item in dsc_parser[MODEL_EFI_DEFAULT_STORES]:
        print(item)

    for item in dsc_parser[MODEL_META_DATA_PACKAGE]:
        print(item)

    # '''
    #     ['PcdLib', 'MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf', '', 'COMMON', 'COMMON', 'COMMON', 59, 107]
    # '''
    # for item in dsc_parser[MODEL_EFI_LIBRARY_CLASS]:
    #     print(item)

    # '''
    #     ['GCC', 'RELEASE_*_*_CC_FLAGS', '-DMDEPKG_NDEBUG', 'COMMON', 'COMMON', 'COMMON', 35, 67]
    #     ['INTEL', 'RELEASE_*_*_CC_FLAGS', '/D MDEPKG_NDEBUG', 'COMMON', 'COMMON', 'COMMON', 36, 68]
    #     ['MSFT', 'RELEASE_*_*_CC_FLAGS', '/D MDEPKG_NDEBUG', 'COMMON', 'COMMON', 'COMMON', 37, 69]
    # '''
    # for item in dsc_parser[MODEL_META_DATA_BUILD_OPTION]:
    #     print(item)

def TestInfParser(inf_path,WorkspaceDir):
    inf_parser = InfParser(PathClass(inf_path,WorkspaceDir),MODEL_FILE_INF,"IA32",
                                MetaFileStorage(PathClass(inf_path,WorkspaceDir), MODEL_FILE_INF))
    for item in inf_parser[MODEL_META_DATA_HEADER]:
        print(item)

    for item in inf_parser[MODEL_EFI_SOURCE_FILE]:
        print (item)

    for item in inf_parser[MODEL_EFI_LIBRARY_CLASS]:
        print(item)

    for item in inf_parser[MODEL_EFI_LIBRARY_INSTANCE]:
        print(item)

    for item in inf_parser[MODEL_EFI_PROTOCOL]:
        print(item)

    for item in inf_parser[MODEL_EFI_PPI]:
        print(item)

    for item in inf_parser[MODEL_EFI_GUID]:
        print(item)

    for item in inf_parser[MODEL_EFI_INCLUDE]:
        print(item)

    for item in inf_parser[MODEL_META_DATA_PACKAGE]:
        print(item)

    for item in inf_parser[MODEL_PCD_DYNAMIC]:
        print(item)

    for item in inf_parser[MODEL_META_DATA_BUILD_OPTION]:
        print(item)

    for item in inf_parser[MODEL_EFI_DEPEX]:
        print(item)

def TestDecParser(dec_path,WorkspaceDir):
    inf_parser = DecParser(PathClass(dec_path,WorkspaceDir),MODEL_FILE_INF,"IA32",
                                MetaFileStorage(PathClass(dec_path,WorkspaceDir), MODEL_FILE_INF))
    for item in inf_parser[MODEL_META_DATA_HEADER]:
        print(item)

    # for item in inf_parser[MODEL_EFI_PROTOCOL]:
    #     print (item)

    # for item in inf_parser[MODEL_EFI_PPI]:
    #     print(item)

    # for item in inf_parser[MODEL_EFI_GUID]:
    #     print(item)

    # for item in inf_parser[MODEL_EFI_INCLUDE]:
    #     print(item)

    # for item in inf_parser[MODEL_EFI_LIBRARY_CLASS]:
    #     print(item)

    # for item in inf_parser[MODEL_PCD_DYNAMIC]:
    #     print(item)

if __name__ == "__main__":
    WorkspaceDir = r"C:\BobFeng\ToolDev\BobEdk2\edk2"
    GlobalData.gGlobalDefines['WORKSPACE'] = WorkspaceDir
    GlobalData.gWorkspace = WorkspaceDir
    PackagesPath = os.getenv("PACKAGES_PATH")
    mws.setWs(WorkspaceDir, PackagesPath)
    dsc_path = r"OvmfPkg\OvmfPkgIa32.dsc"
    inf_path = r"OvmfPkg\Sec\SecMain.inf"
    dec_path = r"OvmfPkg\OvmfPkg.dec"
    TestDscParser(dsc_path,WorkspaceDir)
