using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Il2CppDumper
{
    public partial class Il2CppHelper
    {
        // ref: https://github.com/khang06/Il2CppDumper-YuanShen
        public static bool KhangSearch(Il2Cpp il2Cpp, string il2cppPath, double version, long metadataUsagesCount)
        {
            if (!(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && il2Cpp is PE))
                return false;
            Console.WriteLine("Use custom PE loader");
            PE pe = PELoader.Load(il2cppPath);
            pe.SetProperties(version, metadataUsagesCount);
            ProcessModuleCollection modules = Process.GetCurrentProcess().Modules;
            ulong baseaddr = 0;
            ProcessModule targetModule = null;
            foreach (ProcessModule module in modules)
            {
                if (module.ModuleName == "UserAssembly.dll")
                {
                    baseaddr = (ulong)module.BaseAddress;
                    targetModule = module;
                    break;
                }
            }
            Console.WriteLine("baseAddress: 0x" + baseaddr.ToString("X2"));

            ulong codeRegistration = 0;
            ulong metadataRegistration = 0;

            // custom search
            // searching .text for the following pattern:
            // lea r8,  [rip+0x????????]
            // lea rdx, [rip+0x????????]
            // lea rcx, [rip+0x????????]
            // jmp [rip+0x????????]
            // or...
            // 4c 8d 05 ?? ?? ?? ??
            // 48 8d 15 ?? ?? ?? ??
            // 48 8d 0d ?? ?? ?? ??
            // e9
            // 22 bytes long
            // ....alter
            // lea r9,  [rip+0x????????]
            // lea r8,  [rip+0x????????]
            // lea rdx, [rip+0x????????]
            // lea rcx, [rip+0x????????]
            // jmp [rip+0x????????]
            // or...
            // 4c 8d 0d ?? ?? ?? ??
            // 4c 8d 05 ?? ?? ?? ??
            // 48 8d 15 ?? ?? ?? ??
            // 48 8d 0d ?? ?? ?? ??
            // e9
            // 29 bytes long

            // .text is always the first section
            var text_start = pe.sections[0].VirtualAddress + baseaddr;
            var text_end = text_start + pe.sections[0].VirtualSize;

            // functions are always aligned to 16 bytes
            const int patternLength = 29;
            byte[] temp = new byte[patternLength];
            bool found = false;
            for (ulong ptr = text_start; ptr < text_end - patternLength; ptr += 0x10)
            {
                Marshal.Copy((IntPtr)ptr, temp, 0, patternLength);
                if (
                    temp[0] == 0x4C && temp[1] == 0x8D && temp[2] == 0x05 &&
                    temp[7] == 0x48 && temp[8] == 0x8D && temp[9] == 0x15 &&
                    temp[14] == 0x48 && temp[15] == 0x8D && temp[16] == 0x0D &&
                    temp[21] == 0xE9
                )
                {
                    codeRegistration = ptr + 21 + BitConverter.ToUInt32(temp, 14 + 3);
                    metadataRegistration = ptr + 14 + BitConverter.ToUInt32(temp, 7 + 3);
                    found = true;
                }
                else if (
                    temp[0] == 0x4C && temp[1] == 0x8D && temp[2] == 0x0D &&
                    temp[7] == 0x4C && temp[8] == 0x8D && temp[9] == 0x05 &&
                    temp[14] == 0x48 && temp[15] == 0x8D && temp[16] == 0x15 &&
                    temp[21] == 0x48 && temp[22] == 0x8D && temp[23] == 0x0D &&
                    temp[28] == 0xE9
                )
                {
                    codeRegistration = ptr + 28 + BitConverter.ToUInt32(temp, 21 + 3);
                    metadataRegistration = ptr + 21 + BitConverter.ToUInt32(temp, 14 + 3);
                    found = true;
                }
                if (found)
                {
                    Console.WriteLine($"Found the offsets! codeRegistration: 0x{(codeRegistration).ToString("X2")}, metadataRegistration: 0x{(metadataRegistration).ToString("X2")}");
                    break;
                }
            }

            if (codeRegistration == 0 && metadataRegistration == 0)
            {
                Console.WriteLine("Failed to find CodeRegistration and MetadataRegistration, go yell at Khang");
                return false;
            }
            codeRegistration -= baseaddr - 0x180000000;
            metadataRegistration -= baseaddr - 0x180000000;
            Console.WriteLine("CodeRegistration : 0x{0:X}", codeRegistration);
            Console.WriteLine("MetadataRegistration : 0x{0:X}", metadataRegistration);
            il2Cpp.Init(codeRegistration, metadataRegistration);
            return true;
        }
    }
}
