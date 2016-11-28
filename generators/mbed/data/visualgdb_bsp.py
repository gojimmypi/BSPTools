"""
    This file generates a BSP file that makes VisualGDB recognize the Mbed library and automatically create Visual Studio
    projects for it
"""
import copy
import json
import os
import re
import sys
import xml.etree.ElementTree as ElementTree
from os.path import join, dirname, basename
from xml.dom import minidom

import tools.build_api as ba
import tools.config
import tools.libraries
import tools.project
import tools.toolchains
import tools.export.cmsis as cmsis
from tools.export import EXPORTERS
from tools.libraries import LIBRARIES
from tools.paths import MBED_HEADER
from tools.settings import ROOT

# FILE_ROOT = abspath(join(dirname(tools.project.__file__), ".."))
# sys.path.insert(0, FILE_ROOT)

GccExporter = EXPORTERS['gcc_arm']


class Memory(object):
    FLASH = 'FLASH'
    RAM = 'RAM'

    def __init__(self, name, mem_type, start, size):
        self.__name = name
        if mem_type != self.FLASH and mem_type != self.RAM:
            raise Exception('No such memory type: ' + mem_type)
        self.__type = mem_type
        self.__start = start
        self.__size = size

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def get_start(self):
        return self.__start

    def get_size(self):
        return self.__size


class Memories(object):
    __memories = []
    __ram_size = 0
    __flash_size = 0
    __valid = False

    def add_memory(self, mem):
        self.__memories.append(mem)
        self.__valid = True
        if mem.get_type() == Memory.FLASH:
            self.__flash_size += mem.get_size()
        else:
            self.__ram_size += mem.get_size()

    def get_memories(self):
        return self.__memories

    def get_ram_size(self):
        return self.__ram_size

    def get_flash_size(self):
        return self.__flash_size

    def valid(self):
        return self.__valid


class InfoProvider(object):
    __official_targets = set()
    __all_targets = set()
    __sizes_from_linker = None

    def __init__(self):
        release_targets = {}
        release_targets_name = {}

        for version in ba.RELEASE_VERSIONS:
            release_targets[version] = ba.get_mbed_official_release(version)
            release_targets_name[version] = [x[0] for x in release_targets[version] if 'GCC_ARM' in x[1]]

        merged = set()
        for version in ba.RELEASE_VERSIONS:
            merged |= set(release_targets_name[version])

        self.__official_targets = merged
        self.__all_targets = set(GccExporter.TARGETS)

        with open(os.path.join(script_path, 'sizes_from_linker.json')) as linker_data:
            self.__sizes_from_linker = json.load(linker_data)

    def get_official_targets(self):
        return self.__official_targets

    def get_all_targets(self):
        return self.__all_targets

    def get_mem_sizes_linker(self, target):
        memories = Memories()
        if target in self.__sizes_from_linker:
            ram_size = self.__sizes_from_linker[target]['ram_size']
            flash_size = self.__sizes_from_linker[target]['flash_size']
            for mem_name in self.__sizes_from_linker[target]['memories']:
                mem = self.__sizes_from_linker[target]['memories'][mem_name]
                if mem['type'] == Memory.RAM:
                    memories.add_memory(Memory(mem_name, Memory.RAM, int(mem['start']), int(mem['size'])))
                elif mem['type'] == Memory.FLASH:
                    memories.add_memory(Memory(mem_name, Memory.FLASH, int(mem['start']), int(mem['size'])))
                else:
                    raise Exception('Invalid memory type in the linker sizes cache for the target ' + target)

        return memories

    def get_mem_sizes_mbed(self, target):
        try:
            ram_regexp = re.compile('.*RAM.*')
            rom_regexp = re.compile('.*ROM.*')
            cmsis_dev = cmsis.DeviceCMSIS(target)
        except cmsis.TargetNotSupportedException as e:
            return Memories()

        memories = Memories()
        for mem_name in cmsis_dev.target_info['memory']:
            start = int(cmsis_dev.target_info['memory'][mem_name]['start'], 16)
            size = int(cmsis_dev.target_info['memory'][mem_name]['size'], 16)
            if ram_regexp.match(mem_name):
                memories.add_memory(Memory(mem_name, Memory.RAM, start, size))
            elif rom_regexp.match(mem_name):
                memories.add_memory(Memory(mem_name, Memory.FLASH, start, size))
            else:
                raise Exception('Unknown type of memory')

        return memories


class LibraryBuilder(object):
    def __init__(self, lib, target):
        self.source_condition_map = {}
        self.header_condition_map = {}
        self.include_dir_condition_map = {}
        self.ID = lib['id']
        self.macros_condition_map = {}
        if lib.get('macros', None) is not None:
            self.append_resources(target, tools.toolchains.Resources(), lib.get('macros', None))
        self.SupportedTargets = {}
        self.Dependencies = lib['dependencies']

    def append_resources(self, target, res, macros):
        found = False
        for items, cond_map, is_path in [
            [res.c_sources + res.cpp_sources + res.s_sources, self.source_condition_map, True],
            [res.headers, self.header_condition_map, True],
            [res.inc_dirs, self.include_dir_condition_map, True],
            [macros, self.macros_condition_map, False]]:
                for fn in items:
                    if is_path:
                        fn = "$$SYS:BSP_ROOT$$/" + fn.replace("\\", "/")
                        found = True
                    cond_map.setdefault(fn, set([])).add(target)
        if found:
            self.SupportedTargets[target] = True


def make_node(name, text):
    str_node = ElementTree.Element(name)
    str_node.text = text
    return str_node


def append_node(el, name):
    n = ElementTree.Element(name)
    el.append(n)
    return n


def provide_node(el, name):
    n = el.find(name)
    if n is None:
        n = ElementTree.Element(name)
        el.append(n)
    return n


def add_file_condition(lib_builder, fw_node, cond_list, file_regex, condition_id, condition_name):
    prop_list = provide_node(
        provide_node(provide_node(provide_node(fw_node, "ConfigurableProperties"), "PropertyGroups"), "PropertyGroup"),
        "Properties")
    ElementTree.SubElement(prop_list, "PropertyEntry", {"xsi:type": "Boolean"}).extend(
        [make_node("Name", condition_name), make_node("UniqueID", condition_id), make_node("ValueForTrue", "1")])
    pattern = re.compile(file_regex)

    for s in lib_builder.sourceConditionMap.keys() + lib_builder.header_condition_map.keys():
        if not pattern.match(s.replace("$$SYS:BSP_ROOT$$/", "")):
            continue
        file_condition_node = ElementTree.SubElement(cond_list, "FileCondition")
        condition_node = ElementTree.SubElement(file_condition_node, "ConditionToInclude", {"xsi:type": "Equals"})
        condition_node.append(make_node("Expression", "$$" + condition_id + "$$"))
        condition_node.append(make_node("ExpectedValue", "1"))
        file_condition_node.append(make_node("FilePath", s))


def parse_mem_size(size_str):
    size_reg_ex = re.compile("[( ]*([0-9a-fA-FxKkMm]+) *([+-]) *([0-9a-fA-FxKkMm]+)[) ]*")
    size_str = size_str.strip('()\n')

    match = size_reg_ex.match(size_str)
    if match is not None:
        if match.group(2) == '+':
            return parse_mem_size(match.group(1)) + parse_mem_size(match.group(3))
        else:
            return parse_mem_size(match.group(1)) - parse_mem_size(match.group(3))

    multiplier = 1
    if size_str[-1].upper() == 'K':
        multiplier = 1024
        size_str = size_str[:-1]
    elif size_str[-1].upper() == 'M':
        multiplier = 1024 * 1024
        size_str = size_str[:-1]

    if size_str[0:2] == "0x":
        return int(size_str, 16) * multiplier
    else:
        return int(size_str, 10) * multiplier


def parse_linker_script(lds_file):
    inside_memory_block = False
    rg_mem_def = re.compile(' *([^ ]+) *\([^()]+\) *: *ORIGIN *= *([^ ,]+), *LENGTH *= *([^/]*)($|/\\*)')

    memories = Memories()
    with open(lds_file) as f:
        for line in f:
            if not inside_memory_block and line.strip() == "MEMORY":
                inside_memory_block = True
            elif inside_memory_block and line.strip() == "}":
                break
            elif inside_memory_block:
                match = rg_mem_def.match(line)
                if match is not None:
                    mem_name = match.group(1)
                    mem_start = parse_mem_size(match.group(2))
                    mem_size = parse_mem_size(match.group(3))
                    if mem_size == 0:
                        print('Warning: Zero size of the memory in the linker script')
                        continue
                    if 'RAM' in mem_name:
                        memories.add_memory(Memory(mem_name, Memory.RAM, mem_start, mem_size))
                    elif 'FLASH' in mem_name:
                        memories.add_memory(Memory(mem_name, Memory.FLASH, mem_start, mem_size))
                    else:
                        print('Warning: Unknown type of the memory')
    return memories

script_path = join(dirname(__file__))


def dump_targets():
    mbed_info = InfoProvider()

    root = ElementTree.Element("SupportedTargets")
    official_targets = ElementTree.SubElement(root, "OfficialTargets")
    for target in mbed_info.get_official_targets():
        ElementTree.SubElement(official_targets, "Target").text = target

    official_targets = ElementTree.SubElement(root, "AllTargets")
    for target in mbed_info.get_all_targets():
        ElementTree.SubElement(official_targets, "Target").text = target

    tree = ElementTree.ElementTree(root)
    root_node = minidom.parseString(ElementTree.tostring(tree.getroot()))
    xml_str = '\n'.join([line for line in root_node.toprettyxml(indent=' ' * 2).split('\n') if line.strip()])
    with open(join(ROOT, 'available_targets.xml'), 'w') as xml_file:
        xml_file.write(xml_str.encode('utf-8'))


def main(argv):
    if 'dump_targets' in argv:
        dump_targets()
        return
    ignore_targets = {
    }

    mbed_info = InfoProvider()

    source_condition_map = {}
    header_condition_map = {}
    symbol_condition_map = {}
    include_dir_condition_map = {}
    src_dir_to_lib_map = {}
    resources_map = {}
    lib_builder_map = {}

    library_names = {
        'cpputest': "CppUTest",
        'usb_host': "USB Host support",
        'usb': "USB Device support",
        'ublox': "U-blox drivers",
        'rtos': "RTOS abstraction layer",
        'dsp': "DSP Library",
        'rpc': "RPC Support",
        'fat': "FAT File System support",
        'eth': "Ethernet support",
        'rtx': "Keil RTX RTOS",
        'features': 'Device features'
    }

    print("Parsing targets...")
    xml = ElementTree.parse(os.path.join(script_path, 'bsp_template.xml'))
    mcus = xml.find("SupportedMCUs")
    family = xml.find("MCUFamilies/MCUFamily")

    targets_count = 0
    for target in GccExporter.TARGETS:
        print('\t' + target + '...')

        toolchain = ba.prepare_toolchain(ROOT, target, 'GCC_ARM')

        # Scan src_path for config files
        res = toolchain.scan_resources(ROOT, exclude_paths=[os.path.join(ROOT, 'rtos'), os.path.join(ROOT, 'features')])
        res.toolchain = toolchain
        # for path in src_paths[1:]:
        #     resources.add(toolchain.scan_resources(path))

        res.headers += [MBED_HEADER, ROOT]
        # res += toolchain.scan_resources(os.path.join(ROOT, 'events'))

        toolchain.config.load_resources(res)

        target_lib_macros = toolchain.config.config_to_macros(toolchain.config.get_config_data())
        toolchain.set_config_data(toolchain.config.get_config_data())
        toolchain.config.validate_config()

        res.relative_to(ROOT, False)
        res.win_to_unix()

        for items, object_map, is_path in [
            [res.c_sources + res.cpp_sources + res.s_sources, source_condition_map, True],
            [res.headers, header_condition_map, True],
            [res.inc_dirs, include_dir_condition_map, True],
            [toolchain.get_symbols(), symbol_condition_map, False],
            [target_lib_macros, symbol_condition_map, False]]:
            for fn in items:
                if is_path:
                    fn = "$$SYS:BSP_ROOT$$/" + fn.replace("\\", "/")
                object_map.setdefault(fn, []).append(target)
        targets_count += 1
        resources_map[target] = res

        for lib in LIBRARIES:
            sources = lib['source_dir']
            if isinstance(sources, str):
                sources = [sources]
            for src in sources:
                lib_toolchain = ba.prepare_toolchain(ROOT, target, 'GCC_ARM')
                # ignore rtx while scanning rtos
                exclude_paths = [os.path.join(ROOT, 'rtos', 'rtx')] if lib['id'] != 'rtos' else []
                lib_res = lib_toolchain.scan_resources(src, exclude_paths=exclude_paths)
                lib_toolchain.config.load_resources(lib_res)
                lib_macros = lib_toolchain.config.config_to_macros(lib_toolchain.config.get_config_data())
                new_lib = copy.copy(lib)
                macros = new_lib.get('macros', None)
                if macros is None:
                    macros = lib_macros
                else:
                    macros += lib_macros
                new_lib['macros'] = macros
                lib_res.relative_to(ROOT, False)
                lib_res.win_to_unix()
                lib_builder_map.setdefault(new_lib['id'], LibraryBuilder(new_lib, target)).append_resources(
                    target, lib_res, macros)
                src_dir_to_lib_map[src] = new_lib['id']

        # Add specific features as a library
        features_path = os.path.join(ROOT, 'features')
        features_toolchain = ba.prepare_toolchain(features_path, target, 'GCC_ARM')
        features_resources = features_toolchain.scan_resources(features_path)
        features_toolchain.config.load_resources(features_resources)
        new_macros = features_toolchain.config.config_to_macros(features_toolchain.config.get_config_data())
        features_macros = [x for x in new_macros if x not in target_lib_macros]
        # if 'MBED_CONF_LWIP_ADDR_TIMEOUT=5' in features_macros:
        #     features_macros.remove('MBED_CONF_LWIP_ADDR_TIMEOUT=5')
        #     features_macros.append('MBED_CONF_LWIP_ADDR_TIMEOUT=$$com.sysprogs.bspoptions.lwip.addr_timeout$$')
        if 'MBED_CONF_LWIP_IPV6_ENABLED=0' in features_macros:
            features_macros.remove('MBED_CONF_LWIP_IPV6_ENABLED=0')
            features_macros.append('MBED_CONF_LWIP_IPV6_ENABLED=$$com.sysprogs.bspoptions.lwip.ipv6_en$$')
        if 'MBED_CONF_LWIP_IPV4_ENABLED=1' in features_macros:
            features_macros.remove('MBED_CONF_LWIP_IPV4_ENABLED=1')
            features_macros.append('MBED_CONF_LWIP_IPV4_ENABLED=$$com.sysprogs.bspoptions.lwip.ipv4_en$$')

        features_resources.relative_to(ROOT, False)
        features_resources.win_to_unix()
        features_lib = {
            'id': 'features',
            'source_dir': os.path.join(ROOT, 'features'),
            'build_dir': tools.libraries.RTOS_LIBRARIES,
            'dependencies': [tools.libraries.MBED_LIBRARIES, tools.libraries.MBED_RTX, tools.libraries.RTOS_LIBRARIES],
            'macros': features_macros
        }
        for feature in toolchain.config.get_features():
            if feature in features_resources.features:
                features_resources += features_resources.features[feature]
        lib_builder_map.setdefault('features', LibraryBuilder(features_lib, target)).append_resources(
            target, features_resources, features_macros)
        src_dir_to_lib_map[features_path] = 'features'

    for fw in lib_builder_map.values():
        fw.DependencyIDs = set([])
        for dep in fw.Dependencies:
            id = src_dir_to_lib_map.get(dep)
            if id is not None:
                fw.DependencyIDs.add(id)

    # Set flags different for each target
    for target in GccExporter.TARGETS:
        res = resources_map.get(target, None)
        if res is None:
            print('Target ignored: ' + target + ': No resources')
            continue
        if res.linker_script is None:
            print('Target ignored: ' + target + ': No linker script')
            continue
        if target in ignore_targets:
            print('Target ' + target + ' ignored: ' + ignore_targets[target])
            continue

        mcu = ElementTree.Element('MCU')
        mcu.append(make_node('ID', target))
        mcu.append(make_node('HierarchicalPath', 'Mbed'))
        mcu.append(make_node('FamilyID', family.find('ID').text))

        props_list = provide_node(provide_node(provide_node(provide_node(mcu, "ConfigurableProperties"),
                                                            "PropertyGroups"), "PropertyGroup"), "Properties")

        if 'FEATURE_LWIP=1' in symbol_condition_map:
            if target in symbol_condition_map['FEATURE_LWIP=1']:
                prop_node = ElementTree.SubElement(props_list, "PropertyEntry", {"xsi:type": "Enumerated"})
                prop_node.extend([make_node('Name', 'LWIP IPV6 config'),
                                  make_node('UniqueID', 'com.sysprogs.bspoptions.lwip.ipv6_en'),
                                  make_node('DefaultEntryIndex', '1')])
                list_node = ElementTree.SubElement(prop_node, 'SuggestionList')
                ElementTree.SubElement(list_node, "Suggestion").extend([make_node("UserFriendlyName", "enable"),
                                                                        make_node("InternalValue", '1')])
                ElementTree.SubElement(list_node, "Suggestion").extend([make_node("UserFriendlyName", "disable"),
                                                                        make_node("InternalValue", '0')])

                prop_node = ElementTree.SubElement(props_list, "PropertyEntry", {"xsi:type": "Enumerated"})
                prop_node.extend([make_node("Name", "LWIP IPV4 config"),
                                  make_node("UniqueID", "com.sysprogs.bspoptions.lwip.ipv4_en"),
                                  make_node("DefaultEntryIndex", "0")])
                list_node = ElementTree.SubElement(prop_node, "SuggestionList")
                ElementTree.SubElement(list_node, "Suggestion").extend([make_node("UserFriendlyName", "enable"),
                                                                        make_node("InternalValue", '1')])
                ElementTree.SubElement(list_node, "Suggestion").extend([make_node("UserFriendlyName", "disable"),
                                                                        make_node("InternalValue", '0')])

        flags = append_node(mcu, "CompilationFlags")
        for (node, cond_map) in [[append_node(mcu, "AdditionalSourceFiles"), source_condition_map],
                             [append_node(mcu, "AdditionalHeaderFiles"), header_condition_map],
                             [append_node(flags, "IncludeDirectories"), include_dir_condition_map],
                             [append_node(flags, "PreprocessorMacros"), symbol_condition_map]]:
            for (filename, targets) in cond_map.items():
                if len(list(set(targets))) < targets_count and target in targets:
                    node.append(make_node("string", filename))

        flags_list = res.toolchain.cpu[:]
        if "-mfloat-abi=softfp" in flags_list:
            flags_list.remove("-mfloat-abi=softfp")
            flags_list.append("$$com.sysprogs.bspoptions.arm.floatmode$$")
            prop_node = ElementTree.SubElement(props_list, "PropertyEntry", {"xsi:type": "Enumerated"})
            prop_node.extend([make_node("Name", "Floating point support"),
                              make_node("UniqueID", "com.sysprogs.bspoptions.arm.floatmode"),
                              make_node("DefaultEntryIndex", "2")])
            list_node = ElementTree.SubElement(prop_node, "SuggestionList")
            ElementTree.SubElement(list_node, "Suggestion").extend(
                [make_node("UserFriendlyName", "Software"), make_node("InternalValue", "-mfloat-abi=soft")])
            ElementTree.SubElement(list_node, "Suggestion").extend(
                [make_node("UserFriendlyName", "Hardware"), make_node("InternalValue", "-mfloat-abi=hard")])
            ElementTree.SubElement(list_node, "Suggestion").extend(
                [make_node("UserFriendlyName", "Hardware with Software interface"),
                 make_node("InternalValue", "-mfloat-abi=softfp")])
            ElementTree.SubElement(list_node, "Suggestion").extend(
                [make_node("UserFriendlyName", "Unspecified"), make_node("InternalValue", "")])

        ElementTree.SubElement(flags, "COMMONFLAGS").text = " ".join(flags_list)
        ElementTree.SubElement(flags, "LinkerScript").text = "$$SYS:BSP_ROOT$$/" + res.linker_script

        memories = mbed_info.get_mem_sizes_mbed(target)
        if not memories.valid():
            print('Warning: No FLASH and RAM size for the ' + target + ' in mbed cache')
            memories = mbed_info.get_mem_sizes_linker(target)
        if not memories.valid():
            print('Warning: No FLASH and RAM size for the ' + target + ' in cached sizes from linker script')
            if target in mbed_info.get_official_targets():
                raise Exception('Memory definition for the official targets should be guaranteed correct')
            memories = parse_linker_script(os.path.join(ROOT, res.linker_script))
        if not memories.valid():
            raise Exception('FLASH and\or RAM size is invalid')

        mcu.append(make_node("RAMSize", memories.get_ram_size()))
        mcu.append(make_node("FLASHSize", memories.get_flash_size()))

        mem_list = ElementTree.SubElement(ElementTree.SubElement(mcu, "MemoryMap"), "Memories")
        for mem in memories.get_memories():
            mem_el = ElementTree.SubElement(mem_list, "MCUMemory")
            mem_el.append(make_node("Name", mem.get_name()))
            mem_el.append(make_node("Address", str(mem.get_start())))
            mem_el.append(make_node("Size", str(mem.get_size())))
            if mem.get_type() == Memory.FLASH:
                mem_el.append(make_node("Flags", "IsDefaultFLASH"))
            if mem.get_type() == Memory.RAM:
                mem_el.append(make_node("LoadedFromMemory", "FLASH"))

        mcus.append(mcu)

    # Set flags shared between targets
    flags = append_node(family, "CompilationFlags")
    for (node, cond_map) in [[append_node(family, "AdditionalSourceFiles"), source_condition_map],
                             [append_node(family, "AdditionalHeaderFiles"), header_condition_map],
                             [append_node(flags, "IncludeDirectories"), include_dir_condition_map],
                             [append_node(flags, "PreprocessorMacros"), symbol_condition_map]]:
        for (filename, targets) in cond_map.items():
            if len(list(set(targets))) == targets_count:
                node.append(make_node("string", filename))

    family.find("AdditionalSourceFiles").append(make_node("string", "$$SYS:BSP_ROOT$$/stubs.cpp"))
    cond_list = xml.find("FileConditions")
    flag_cond_list = xml.find("ConditionalFlags")

    # Add frameworks
    for lib in lib_builder_map.values():
        fw = ElementTree.SubElement(xml.find("Frameworks"), "EmbeddedFramework")
        if len(lib.SupportedTargets) != targets_count:
            fw.append(make_node("MCUFilterRegex", "|".join(lib.SupportedTargets.keys())))

        fw.append(make_node("ID", "com.sysprogs.arm.mbed." + lib.ID))
        fw.append(make_node("ProjectFolderName", lib.ID))
        fw.append(make_node("UserFriendlyName", library_names.get(lib.ID, lib.ID + " library")))
        ElementTree.SubElement(fw, "AdditionalSourceFiles").extend(
            [make_node("string", fn) for fn in lib.source_condition_map.keys()])
        ElementTree.SubElement(fw, "AdditionalHeaderFiles").extend(
            [make_node("string", fn) for fn in lib.header_condition_map.keys()])
        ElementTree.SubElement(fw, "AdditionalIncludeDirs").extend(
            [make_node("string", fn) for (fn, cond) in lib.include_dir_condition_map.items() if
             len(cond) == len(lib.SupportedTargets)])
        ElementTree.SubElement(fw, "AdditionalPreprocessorMacros").extend(
            [make_node("string", fn) for fn in lib.macros_condition_map.keys()])
        if len(lib.DependencyIDs) > 0:
            ElementTree.SubElement(fw, "RequiredFrameworks").extend(
                [make_node("string", "com.sysprogs.arm.mbed." + id) for id in lib.DependencyIDs])
        # ET.SubElement(ET.SubElement(fw, "AdditionalSystemVars"), "SysVarEntry").extend([make_node("Key", "com.sysprogs.arm.mbed." + lib.ID + ".included"), make_node("Value", "1")])

        for (fn, cond) in lib.source_condition_map.items() + lib.header_condition_map.items():
            if len(cond) == len(lib.SupportedTargets):
                continue
            if len(cond) > len(lib.SupportedTargets):
                raise AssertionError("Source file condition list longer than the framework condition list. "
                                     "Check how the framework conditions are formed.")
            file_cond_node = ElementTree.SubElement(cond_list, "FileCondition")
            h_cond_node = ElementTree.SubElement(file_cond_node, "ConditionToInclude", {"xsi:type": "MatchesRegex"})
            h_cond_node.append(make_node("Expression", "$$SYS:MCU_ID$$"))
            h_cond_node.append(make_node("Regex", "|".join(cond)))
            file_cond_node.append(make_node("FilePath", fn))

        for (inc_dir, cond) in lib.include_dir_condition_map.items():
            if len(cond) == len(lib.SupportedTargets):
                continue
            if len(cond) > len(lib.SupportedTargets):
                raise AssertionError("Source file condition list longer than the framework condition list. "
                                     "Check how the framework conditions are formed.")
            flag_cond_node = ElementTree.SubElement(flag_cond_list, "ConditionalToolFlags")
            cond_list_node = ElementTree.SubElement(
                ElementTree.SubElement(flag_cond_node, "FlagCondition", {"xsi:type": "And"}), "Arguments")
            ElementTree.SubElement(cond_list_node, "Condition", {"xsi:type": "ReferencesFramework"}).append(
                make_node("FrameworkID", "com.sysprogs.arm.mbed." + lib.ID))
            ElementTree.SubElement(cond_list_node, "Condition", {"xsi:type": "MatchesRegex"}).extend(
                [make_node("Expression", "$$SYS:MCU_ID$$"), make_node("Regex", "|".join(cond))])
            flags_node = ElementTree.SubElement(flag_cond_node, "Flags")
            include_dir_list_node = ElementTree.SubElement(flags_node, "IncludeDirectories")
            include_dir_list_node.append(make_node("string", inc_dir))

        for (macro, cond) in lib.macros_condition_map.items():
            if len(cond) == len(lib.SupportedTargets):
                continue
            if len(cond) > len(lib.SupportedTargets):
                raise AssertionError('A number of macros is larger than number of supported targets')
            macro_cond_node = ElementTree.SubElement(flag_cond_list, "ConditionalToolFlags")
            macro_list_node = ElementTree.SubElement(
                ElementTree.SubElement(macro_cond_node, "FlagCondition", {"xsi:type": "And"}), "Arguments")
            ElementTree.SubElement(macro_list_node, "Condition", {"xsi:type": "ReferencesFramework"}).append(
                make_node("FrameworkID", "com.sysprogs.arm.mbed." + lib.ID))
            ElementTree.SubElement(macro_list_node, "Condition", {"xsi:type": "MatchesRegex"}).extend(
                [make_node("Expression", "$$SYS:MCU_ID$$"), make_node("Regex", "|".join(cond))])
            macro_flags_node = ElementTree.SubElement(macro_cond_node, 'Flags')
            macros_node = ElementTree.SubElement(macro_flags_node, 'PreprocessorMacros')
            macros_node.append(make_node('string', macro))

    samples = xml.find('Examples')
    for (root, dirs, files) in os.walk(os.path.join(ROOT, 'samples')):
        for subdir in dirs:
            samples.append(make_node('string', 'samples/' + basename(subdir)))

    xml.getroot().attrib['xmlns:xsi'] = 'http://www.w3.org/2001/XMLSchema-instance'
    xml.getroot().attrib['xmlns:xsd'] = 'http://www.w3.org/2001/XMLSchema'
    root_node = minidom.parseString(ElementTree.tostring(xml.getroot()))
    xml_str = '\n'.join([line for line in root_node.toprettyxml(indent=' '*2).split('\n') if line.strip()])
    with open(join(ROOT, 'BSP.xml'), 'w') as xml_file:
        xml_file.write(xml_str.encode('utf-8'))


main(sys.argv[1:])
