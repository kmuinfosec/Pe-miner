import os
import pefile

__LIST_OF_DLLS = {
    'ADVAP132.DLL', # Advanced Win32 application programming interfaces
    'AWFAXP32.DLL', # Mail API fax transport
    'AWFXAB32.DLL', # Address book
    'AWPWD32.DLL', # Security support
    'AWRESX32.DLL', # Resource Executor
    'AWUTIL32.DLL', # At Work Security Support
    'BHNETB.DLL', # Network monitor SMS client
    'BHSUPP.DLL', # Network monitor SMS client
    'CCAPI.DLL', # Microsoft Network component
    'CCEI.DLL', # Microsoft Network component
    'CCPSH.DLL', # Microsoft Network component
    'CCTN20.DLL', # Microsoft Network component
    'CMC.DLL', # Common messaging calls for Mail API 1.0
    'COMCTL32.DLL', # User Experience Controls Library
    'COMDLG32.DLL', # Common Dialogue Library
    'CRTDLL.DLL', # Microsoft C Runtime Library
    'DCIMAN.DLL', # Display Control Interface Manager
    'DCIMAN32.DLL', # Display Control Interface Manager
    'DSKMAINT.DLL', # Disk Utilities engine
    'GDI32.DLL', # GDI Client DLL
    'GROUP.DLL', # policy support
    'HYPERTERM.DLL', # Terminal DLL
    'KERNL32.DLL', # Windows NT BASE API Client DLL
    'LZ32.DLL', # LZ Expand/Compress API DLL
    'MAPI.DLL', # Mail / Exchange component
    'MAPI32.DLL', # Extended MAPI 1.0 for Windows NT
    'MFC30.DLL', # Shared MFC DLL
    'MPR.DLL', # Multiple Provider Router DLL
    'MSPST32.DLL', # Microsoft Personal Folder/Address Book Service Provider
    'MSFS32.DLL', # MAPI 1.0 Service Providers for Microsoft Mail
    'MSNDUI.DLL', # Microsoft Network component
    'MSNET32.DLL', # Microsoft 32-bit Network API Library
    'MSSHRUI.DLL', # Shell extensions for sharing
    'MSVIEWUT.DLL', # Service data-link libraries for display engines
    'NAL.DLL', # Network monitor SMS client
    'NDIS30.DLL', # Network monitor SMS client
    'NETAPI.DLL', # Network API
    'NETAPI32.DLL', # Net Win32 API DLL
    'NETBIOS.DLL', # NetBIOS API Library
    'NETDI.DLL', # Net Device installer
    'NETSETUP.DLL', # Network server-based setup
    'NWAB32.DLL', # Address book provider
    'NWNET32.DLL', # NetWare client
    'NWNP32.DLL', # NetWare component
    'OLEDLG.DLL', # Microsoft Windows OLE 2.0 User Interface Support
    'POWERCFG.DLL', # Advanced Power Management Control Panel
    'RASPI.DLL', # Automated Software Profile, Analysis, Removal and Signature Information
    'RASAPI16.DLL', # Remote Access Services 16-bit API Library
    'RASAPI32.DLL', # Remote Access 16-bit API Library
    'RPCRT4.DLL', # Remote Procedure Call Runtime
    'RPCLTC1.DLL', # Remote Procedure Call libraries
    'RPCTLC3.DLL', # Remote Procedure Call libraries
    'RPCTLC5.DLL', # Remote Procedure Call libraries
    'RPCTLC6.DLL', # Remote Procedure Call libraries
    'RPCTLS3.DLL', # Remote Procedure Call libraries
    'RPCTLS5.DLL', # Remote Procedure Call libraries
    'RPCTLS6.DLL', # Remote Procedure Call libraries
    'RPCNS4.DLL', # Remote Procedure Call Name Service Client
    'RSRC32.DLL', # Resource Meter
    'SAPNSP.DLL', # Winsock data-link library
    'SECUR32.DLL', # Security Support Provider Interface
    'SHELL32.DLL', # Windows Shell Common DLL
    'SLENH.DLL', # Advanced Power Management options
    'SHLWAPI.DLL', # Library for UNC and URL Paths, Registry Entries and Color Settings
    'UMDM32.DLL', # Universal Modem Driver component
    'USER32.DLL', # USER API Client DLL
    'VERSION.DLL', # Version Checking and File Installation Libraries
    'WININET.DLL', # Internet Extensions for Win32
    'WINMM.DLL', # MCI API DLL
    'WINREG.DLL', # Remote Registry support
    'WINSOCK.DLL', # Socket API for Windows
    'WS2.DLL', # 32.DLL Windows Socket 2.0 32-Bit DLL
    'WSOCK32.DLL', # Windows Socket 32-Bit DLL
}

__SET_OF_DLLS = set(__LIST_OF_DLLS)

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_file_header
__FILE_HEADER = [
    'Machine', # The architecture type of the computer.
    'NumberOfSections', # The number of sections.
    'TimeDateStamp', # The low 32 bits of the time stamp of the image.
    'PointerToSymbolTable', # The offset of the symbol table, in bytes, or zero if no COFF symbol table exists.
    'NumberOfSymbols', # The number of symbols in the symbol table.
    'SizeOfOptionalHeader', # The size of the optional header, in bytes.
    'Characteristics' # The characteristics of the image.
]

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
__OPTIONAL_HEADER = [
    'Magic', # The state of the image file.
    'MajorLinkerVersion', # The major version number of the linker.
    'MinorLinkerVersion', # The minor version number of the linker.
    'SizeOfCode', # The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.
    'SizeOfInitializedData', # The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.
    'SizeOfUninitializedData', # The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.
    'AddressOfEntryPoint', # A pointer to the entry point function, relative to the image base address.
    'BaseOfCode', # A pointer to the beginning of the code section, relative to the image base.
    'BaseOfData', # A pointer to the beginning of the data section, relative to the image base.
    'ImageBase', # The preferred address of the first byte of the image when it is loaded in memory.
    'SectionAlignment', # The alignment of sections loaded in memory, in bytes.
    'FileAlignment', # The alignment of the raw data of sections in the image file, in bytes.
    'MajorOperatingSystemVersion', # The major version number of the required operating system.
    'MinorOperatingSystemVersion', # The minor version number of the required operating system.
    'MajorImageVersion', # The major version number of the image.
    'MinorImageVersion', # The minor version number of the image.
    'MajorSubsystemVersion', # The major version number of the subsystem.
    'MinorSubsystemVersion', # The minor version number of the subsystem.
    'Reserved1',  # (Win32VersionValue) This member is reserved and must be 0.
    'SizeOfImage', # The size of the image, in bytes, including all headers.
    'SizeOfHeaders', # The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.
    'CheckSum', # The image file checksum.
    'Subsystem', # The subsystem required to run this image.
    'DllCharacteristics', # The DLL characteristics of the image.
    'SizeOfStackReserve', # The number of bytes to reserve for the stack.
    'SizeOfStackCommit', # The number of bytes to commit for the stack.
    'SizeOfHeapReserve', # The number of bytes to commit for the local heap.
    'SizeOfHeapCommit', # This member is obsolete.
    'LoaderFlags', # The number of directory entries in the remainder of the optional header.
    'NumberOfRvaAndSizes' # A pointer to the first IMAGE_DATA_DIRECTORY structure in the data directory.
]

__DIRECTORY_ENTRY_TYPES = {
    'IMAGE_DIRECTORY_ENTRY_EXPORT' : 0,
    'IMAGE_DIRECTORY_ENTRY_IMPORT' : 1,
    'IMAGE_DIRECTORY_ENTRY_RESOURCE' : 2,
    'IMAGE_DIRECTORY_ENTRY_EXCEPTION' : 3,
    'IMAGE_DIRECTORY_ENTRY_SECURITY' : 4,
    'IMAGE_DIRECTORY_ENTRY_BASERELOC' : 5,
    'IMAGE_DIRECTORY_ENTRY_DEBUG' : 6,
    'IMAGE_DIRECTORY_ENTRY_COPYRIGHT' : 7,
    'IMAGE_DIRECTORY_ENTRY_GLOBALPTR' : 8,
    'IMAGE_DIRECTORY_ENTRY_TLS' : 9,
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG' : 10,
    'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT' : 11,
    'IMAGE_DIRECTORY_ENTRY_IAT' : 12,
    'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT' : 13,
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR' : 14,
    'IMAGE_DIRECTORY_ENTRY_RESERVED' : 15
}
# https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
__SECTION_HEADER = [
    'VirtualSize',
    'VirtualAddress',
    'SizeOfRawData',
    'PointerToRawData',
    'PointerToRelocations',
    'PointerToLinenumbers',
    'NumberOfRelocations',
    'NumberOfLinenumbers',
    'Characteristics'
]

__RESOURCE_DIRECTORY_TABLE = [
    'Characteristics',
    'MajorVersion',
    'MinorVersion',
    'NumberOfIdEntries',
    'NumberOfNamedEntries',
    'TimeDateStamp'
]

def extract_feature(file_path):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    try:
        pe = pefile.PE(data=file_data)
        ret = dict()
        # Feature From DLLs referred
        for dll in __LIST_OF_DLLS:
            ret[dll] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for lib in pe.DIRECTORY_ENTRY_IMPORT:
                if lib.dll != None:
                    if lib.dll.decode().upper() in __SET_OF_DLLS :
                        ret[lib.dll.decode().upper()] = 1
        # Feature From COFF file header
        for member in __FILE_HEADER:
            ret[member] = getattr(pe.FILE_HEADER, member, -1)
        # Feature From Optional header: standard fields and Windows specific fields
        for member in __OPTIONAL_HEADER:
            ret[member] = getattr(pe.OPTIONAL_HEADER, member, -1)
        # Feature From Optional header: data directories
        for key in __DIRECTORY_ENTRY_TYPES.keys():
            ret[f'{key}:VirtualAddress'] = -1
            ret[f'{key}:Size'] = -1
        for structure in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            ret[f'{structure.name}:VirtualAddress'] = structure.VirtualAddress
            ret[f'{structure.name}:Size'] = structure.Size
        # Feature From Section headers
        for section_name in ['text', 'data', 'resource']:
            for member_name in __SECTION_HEADER :
                ret[f'{section_name}:{member_name}'] = -1
        for section in pe.sections:
            scn = section.Name
            if section.Name == b'.text\x00\x00\x00':
                for member in __SECTION_HEADER:
                    ret[f'text:{member}'] = getattr(section, member, -1)
            elif section.Name == b'.data\x00\x00\x00':
                for member in __SECTION_HEADER:
                    ret[f'data:{member}'] = getattr(section, member, -1)
            elif section.Name == b'.rsrc\x00\x00\x00':
                for member in __SECTION_HEADER:
                    ret[f'resource:{member}'] = getattr(section, member, -1)

        # Feature From Resource directory table & resources
        for resource_type in ['Cursors', 'Bitmaps', 'Icons', 'Menus', 'Dialogs', 'Strings', 'Fonts', 'Group Cursors', 'Group Icons']:
            ret[resource_type] = 0
        for resource_struct in __RESOURCE_DIRECTORY_TABLE:
            ret[f'Resource:{resource_struct}'] = -1
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_struct in __RESOURCE_DIRECTORY_TABLE:
                ret[f'Resource:{resource_struct}'] = getattr(pe.DIRECTORY_ENTRY_RESOURCE.struct, resource_struct, -1)
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                # Cursors
                if resource_type.struct.Id == 1:
                    ret['Cursors'] += len(resource_type.directory.entries)
                # Bitmaps
                elif resource_type.struct.Id == 2:
                    ret['Bitmaps'] += len(resource_type.directory.entries)
                # Icons
                elif resource_type.struct.Id == 3:
                    ret['Icons'] += len(resource_type.directory.entries)
                # Menus
                elif resource_type.struct.Id == 4:
                    ret['Menus'] += len(resource_type.directory.entries)
                # Dialogs
                elif resource_type.struct.Id == 5 :
                    ret['Dialogs'] += len(resource_type.directory.entries)
                # Strings
                elif resource_type.struct.Id == 6:
                    ret['Strings'] += len(resource_type.directory.entries)
                # Fonts
                elif resource_type.struct.Id == 8:
                    ret['Fonts'] += len(resource_type.directory.entries)
                # Group Cursors
                elif resource_type.struct.Id == 12:
                    ret['Group Cursors'] += len(resource_type.directory.entries)
                # Group Icons
                elif resource_type.struct.Id == 14:
                    ret['Group Icons'] += len(resource_type.directory.entries)
        return ret
    except pefile.PEFormatError as pefe:
        print("PEFormatError", pefe, os.path.basename(file_path))
        return None
    except Exception as e:
        print("Exception", e, os.path.basename(file_path))
        return None





