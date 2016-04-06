﻿/* Copyright (c) 2015 Sysprogs OU. All Rights Reserved.
   This software is licensed under the Sysprogs BSP Generator License.
   https://github.com/sysprogs/BSPTools/blob/master/LICENSE
*/
using BSPEngine;
using BSPGenerationTools;
using LinkerScriptGenerator;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace InfineonXMC_bsp_generator
{
    class Program
    {
        class InfineonXMCBSPBuilder : BSPBuilder
        {
            const uint FLASHBase = 0x00000000, SRAMBase = 0x10000000;

            public InfineonXMCBSPBuilder(BSPDirectories dirs)
                : base(dirs)
            {
                ShortName = "Infineon_XMC";
            }

            public override void GetMemoryBases(out uint flashBase, out uint ramBase)
            {
                flashBase = FLASHBase;
                ramBase = SRAMBase;
            }

            public override MemoryLayout GetMemoryLayout(MCUBuilder mcu, MCUFamilyBuilder family)
            {
                MemoryLayout layout = new MemoryLayout { DeviceName = mcu.Name, Memories = new List<Memory>() };
                string aDir = Directories.InputDir+ @"\CMSIS\Infineon\"+ family.Definition.Name + @"_series\Source\GCC";
                Regex aRgFl1 = new Regex(@"((FLASH)[ \(]+RX[\) :]+ORIGIN[ =]+)(0x[A-F\d]*)[ ,\t\w]+[ =]+(0x[A-F\d]*)");
                Regex aRgFl2 = new Regex(@"((FLASH_1_uncached)[ \(]+RX[\) :]+ORIGIN[ =]+)(0x[A-F\d]*)[ ,\t\w]+[ =]+(0x[A-F\d]*)");
                Regex aRgRam1 = new Regex(@"((SRAM)[ \(!RWX\) :]+ORIGIN[ =]+)(0x[A-F\d]*)[ ,\t\w]+[ =]+(0x[A-F\d]*)");
                Regex aRgRam3 = new Regex(@"((PSRAM_1)[ \(!RWX\) :]+ORIGIN[ =]+)(0x[A-F\d]*)[ ,\t\w]+[ =]+(0x[A-F\d]*)");
                Regex aRgRam2 = new Regex(@"((SRAM_combined)[ \(!RWX\) :]+ORIGIN[ =]+)(0x[A-F\d]*)[ ,\t\w]+[ =]+(0x[A-F\d]*)");
                string aStartFlash = "";
                string aLenFlash = "";
                string aStartRam = "";
                string aLenRam = "";
                int idX = mcu.Name.IndexOf("x");
                string aShortMcuName = mcu.Name.Replace("_", "-").Substring(0,idX);
           
                //  missing name mcu
                if (aShortMcuName.StartsWith("XMC1201-T028"))
                    aShortMcuName = "XMC1202-T028";
                if (aShortMcuName.StartsWith("XMC1401-Q048") || aShortMcuName.StartsWith("XMC1401-F064"))
                    aShortMcuName = "XMC1402-Q040";

                // search ld file
                foreach (var afl in Directory.GetFiles(aDir,"*.ld"))
                {
                    bool ablIsFileLd = false;

                    if (ablIsFileLd)
                        break;

                    foreach (var astrfl in File.ReadAllLines(afl))
                    {
                        if (ablIsFileLd)
                        {
                            // Search Flash notes
                            var m = aRgFl1.Match(astrfl);
                            if (!m.Success)
                                m = aRgFl2.Match(astrfl);
                             
                            if (m.Success)
                            {
                                aStartFlash = m.Groups[3].Value;
                                aLenFlash = m.Groups[4].Value;
                            }
                            // Search RAM notes
                            m = aRgRam1.Match(astrfl);
                            if (!m.Success)
                                m = aRgRam2.Match(astrfl);

                            if (!m.Success)
                                m = aRgRam3.Match(astrfl);

                            if (m.Success)
                            {
                                aStartRam = m.Groups[3].Value;
                                aLenRam = m.Groups[4].Value;
                            }

                            if (aStartFlash.Length > 0 && aStartRam.Length > 0)
                                break;

                            continue;
                        }

                        // Search file with Memory Layout
                        if (astrfl.Contains(aShortMcuName))
                            ablIsFileLd = true;
                    }  
                }

                layout.Memories.Add(new Memory
                {
                    Name = "FLASH",
                    Access = MemoryAccess.Undefined,
                    Type = MemoryType.FLASH,
                    Start = Convert.ToUInt32(aStartFlash, 16),
                    Size = (uint)mcu.FlashSize,
                });

                layout.Memories.Add(new Memory
                {
                    Name = "SRAM",
                    Access = MemoryAccess.Undefined,
                    Type = MemoryType.RAM,
                    Start = Convert.ToUInt32(aStartRam, 16),
                    Size = (uint)mcu.RAMSize,
                });

                return layout;
            }
        }
//===============================================================
        static IEnumerable<StartupFileGenerator.InterruptVectorTable> ParseStartupFiles(string dir)
        {
            var fn = dir;
            List<StartupFileGenerator.InterruptVector[]> list = new List<StartupFileGenerator.InterruptVector[]>();

            list.Add(StartupFileGenerator.ParseInterruptVectors(fn,
                    @"__Vectors:",
                    @"    .size  __Vectors, . - __Vectors",// - start tabl
                    @"[ \t]*.long[ \t]+([\w]+)[ \t/\*]+(.*[^\*/])",//.long - line A
                   @"[ \t]*.Entry[ \t]+([\w]+)[ /\*]+(.*[^\*/])",//Entry - line B
                    @"^[ \t/]*[\*#]+.*",//Ignor line

                    @"(USE_LPCOPEN_IRQHANDLER_NAMES)",
                    1,
                    2));

            List<StartupFileGenerator.InterruptVector> vectors = new List<StartupFileGenerator.InterruptVector>(list[0]);
            list.RemoveAt(0);

            //Fix the vector names from comments
            for (int i = 0; i < vectors.Count; i++)
            {
                if (vectors[i] == null)
                    continue;

                if (i == 0)
                {
                    vectors[i].Name = "_estack";
                    continue;
                }
                else if (i == 1)
                {
                    vectors[i].Name = "Reset_Handler";
                    continue;
                }
                else if (vectors[i].OptionalComment == "Reserved")
                {
                    vectors[i] = null;
                    continue;
                }
                else
                {
                    for (int c = 0; c < i; c++)
                    {
                        if (vectors[c] != null)
                            if (vectors[c].Name == vectors[i].Name)
                            {
                                int idx = vectors[c].OptionalComment.IndexOf(" ");
                                if (idx == -1) idx = 0;

                                vectors[i].Name = "INT_" + i + "_" + vectors[i].Name;
                            }
                    }
                }

            }
            yield return new StartupFileGenerator.InterruptVectorTable
            {
                FileName = Path.ChangeExtension(Path.GetFileName(fn), ".c"),
                MatchPredicate = null,
                Vectors = vectors.ToArray()
            };
  
    }
//===========================================================
//  Correct name Mcu for Segger
        static void UpdateNameMcuToSeggerFormat(ref List<MCU> pMcuList)
        {
            List<MCUBuilder> aoUpdateListNCU = new List<MCUBuilder>();
            Regex aReg = new Regex(@"^(XMC[\d]+)[_]?([\w]?)([\d]+)[x]?([\w]+)");
            foreach (var mcu in pMcuList)
            {
                var m = aReg.Match(mcu.ID);
                if (!m.Success)
                    throw new Exception("Error: Failed to update name of Mcu");
                mcu.ID = $"{m.Groups[1].Value}-{m.Groups[4].Value}";
            }
            // Remove dublicate
            for(int i = 0; i<pMcuList.Count-1;i++)
            {
                for (var c = i + 1; c < pMcuList.Count; c++)
                    if (pMcuList[i].ID == pMcuList[c].ID)
                    {
                        pMcuList.RemoveAt(c);
                        c--;
                    }
            }
        }
//===========================================================
// Correct name Mcu for macros
   static List<MCUBuilder> UpdateListMCU( List<MCUBuilder> pMcuList)
    {
            List<MCUBuilder> aoUpdateListNCU = new List<MCUBuilder>();
            Regex reg = new Regex(@"^(XMC[\d]+)[-]?([\w]?)([\d]+)([\w]?)([\w]+)");
            foreach (var mcu in pMcuList)
            {
                var m = reg.Match(mcu.Name);
                if (!m.Success)
                    throw new Exception("Error: Failed to update name of Mcu");
                mcu.Name = $"{m.Groups[1].Value}_{m.Groups[2].Value}{m.Groups[3].Value}x{m.Groups[5].Value}";
                if (aoUpdateListNCU.IndexOf(mcu) < 0)
                    aoUpdateListNCU.Add(mcu);
            }
            return aoUpdateListNCU;
    }
//===========================================================
    static void Main(string[] args)
    {
        if (args.Length < 1)
          throw new Exception("Usage: InfineonXMC.exe <InfineonXMC SW package directory>");

        var bspBuilder = new InfineonXMCBSPBuilder(new BSPDirectories(args[0], @"..\..\Output", @"..\..\rules"));

        var devices = BSPGeneratorTools.ReadMCUDevicesFromCommaDelimitedCSVFile(bspBuilder.Directories.RulesDir + @"\McuInfineonDevices.csv",
           "Product", "Program Memory(KB) ", "SRAM (KB) ", "CORE", true);
            devices = UpdateListMCU(devices);

        List<MCUFamilyBuilder> allFamilies = new List<MCUFamilyBuilder>();
        foreach (var fn in Directory.GetFiles(bspBuilder.Directories.RulesDir + @"\Families", "*.xml"))
            allFamilies.Add(new MCUFamilyBuilder(bspBuilder, XmlTools.LoadObject<FamilyDefinition>(fn)));

        var rejects = BSPGeneratorTools.AssignMCUsToFamilies(devices, allFamilies);
        List<MCUFamily> familyDefinitions = new List<MCUFamily>();
        List<MCU> mcuDefinitions = new List<MCU>();
        List<EmbeddedFramework> frameworks = new List<EmbeddedFramework>();
        List<string> exampleDirs = new List<string>();

        bool noPeripheralRegisters = args.Contains("/noperiph");
        List<KeyValuePair<string, string>> macroToHeaderMap = new List<KeyValuePair<string, string>>();

        var commonPseudofamily = new MCUFamilyBuilder(bspBuilder, XmlTools.LoadObject<FamilyDefinition>(bspBuilder.Directories.RulesDir + @"\CommonFiles.xml"));
        var flags = new ToolFlags();
        List<string> projectFiles = new List<string>();
        commonPseudofamily.CopyFamilyFiles(ref flags, projectFiles);

        foreach (var sample in commonPseudofamily.CopySamples())
            exampleDirs.Add(sample);

        foreach (var fam in allFamilies)
        {
            var rejectedMCUs = fam.RemoveUnsupportedMCUs(true);
            if (rejectedMCUs.Length != 0)
            {
                Console.WriteLine("Unsupported {0} MCUs:", fam.Definition.Name);
                foreach (var mcu in rejectedMCUs)
                    Console.WriteLine("\t{0}", mcu.Name);
            }

            fam.AttachStartupFiles(ParseStartupFiles(fam.Definition.StartupFileDir));
            if (!noPeripheralRegisters)
                fam.AttachPeripheralRegisters(new MCUDefinitionWithPredicate[] { SVDParser.ParseSVDFile(Path.Combine(fam.Definition.PrimaryHeaderDir, @"CMSIS\Infineon\SVD\"+ fam.Definition.Name+".svd") , fam.Definition.Name) });

            var famObj = fam.GenerateFamilyObject(true);

            famObj.AdditionalSourceFiles = LoadedBSP.Combine(famObj.AdditionalSourceFiles, projectFiles.Where(f => !MCUFamilyBuilder.IsHeaderFile(f)).ToArray());
            famObj.AdditionalHeaderFiles = LoadedBSP.Combine(famObj.AdditionalHeaderFiles, projectFiles.Where(f => MCUFamilyBuilder.IsHeaderFile(f)).ToArray());

            famObj.AdditionalSystemVars = LoadedBSP.Combine(famObj.AdditionalSystemVars, commonPseudofamily.Definition.AdditionalSystemVars);
            famObj.CompilationFlags = famObj.CompilationFlags.Merge(flags);
            famObj.CompilationFlags.PreprocessorMacros = LoadedBSP.Combine(famObj.CompilationFlags.PreprocessorMacros, new string[] { "$$com.sysprogs.bspoptions.primary_memory$$_layout" });

            familyDefinitions.Add(famObj);
            fam.GenerateLinkerScripts(false);
            foreach (var mcu in fam.MCUs)
                mcuDefinitions.Add(mcu.GenerateDefinition(fam, bspBuilder, !noPeripheralRegisters));

            foreach (var fw in fam.GenerateFrameworkDefinitions())
                frameworks.Add(fw);

            foreach (var sample in fam.CopySamples())
                exampleDirs.Add(sample);
        }

        UpdateNameMcuToSeggerFormat(ref mcuDefinitions);

        BoardSupportPackage bsp = new BoardSupportPackage
        {
            PackageID = "com.sysprogs.arm.infineon.xmc",
            PackageDescription = "Infineon XMC Devices",
            GNUTargetID = "arm-eabi",
            GeneratedMakFileName = "infineon_xmc.mak",
            MCUFamilies = familyDefinitions.ToArray(),
            SupportedMCUs = mcuDefinitions.ToArray(),
            Frameworks = frameworks.ToArray(),
            Examples = exampleDirs.ToArray(),
            FileConditions = bspBuilder.MatchedFileConditions.ToArray(),
            PackageVersion = "1.0"
        };

        bspBuilder.Save(bsp, true);

    }
}
}