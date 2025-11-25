using System;
using System.Runtime.InteropServices;

namespace OPLUS_EDL
{
    internal static class NativeMethods
    {
        private const string DllName = "oplus_edl_lib.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int run_sahara(int argc, [In] string[] argv);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int run_firehose(int argc, [In] string[] argv);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void LogCallback([MarshalAs(UnmanagedType.LPStr)] string message);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void set_log_callback(LogCallback callback);
    }
}
