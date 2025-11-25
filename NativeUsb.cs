using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.ComponentModel;

namespace OPLUS_EDL
{
    public class NativeUsb : IDisposable
    {
        private SafeFileHandle _deviceHandle;
        private IntPtr _winUsbHandle;
        private byte _bulkInPipe;
        private byte _bulkOutPipe;
        private int _interfaceIndex;

        public byte InterfaceClass { get; private set; }
        public byte InterfaceSubClass { get; private set; }
        public byte InterfaceProtocol { get; private set; }

        public NativeUsb(string devicePath)
        {
            _deviceHandle = CreateFile(devicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, IntPtr.Zero);
            if (_deviceHandle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!WinUsb_Initialize(_deviceHandle, out _winUsbHandle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Find pipes
            USB_INTERFACE_DESCRIPTOR interfaceDescriptor;
            if (WinUsb_QueryInterfaceSettings(_winUsbHandle, 0, out interfaceDescriptor))
            {
                InterfaceClass = interfaceDescriptor.bInterfaceClass;
                InterfaceSubClass = interfaceDescriptor.bInterfaceSubClass;
                InterfaceProtocol = interfaceDescriptor.bInterfaceProtocol;

                for (int i = 0; i < interfaceDescriptor.bNumEndpoints; i++)
                {
                    WINUSB_PIPE_INFORMATION pipeInfo;
                    if (WinUsb_QueryPipe(_winUsbHandle, 0, (byte)i, out pipeInfo))
                    {
                        if (pipeInfo.PipeType == UsbdPipeType.UsbdPipeTypeBulk)
                        {
                            if ((pipeInfo.PipeId & 0x80) != 0)
                                _bulkInPipe = pipeInfo.PipeId;
                            else
                                _bulkOutPipe = pipeInfo.PipeId;
                        }
                    }
                }
            }
        }

        public void Write(byte[] data)
        {
            uint bytesWritten;
            if (!WinUsb_WritePipe(_winUsbHandle, _bulkOutPipe, data, (uint)data.Length, out bytesWritten, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public int Read(byte[] buffer)
        {
            uint bytesRead;
            if (!WinUsb_ReadPipe(_winUsbHandle, _bulkInPipe, buffer, (uint)buffer.Length, out bytesRead, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return (int)bytesRead;
        }

        public void Dispose()
        {
            if (_winUsbHandle != IntPtr.Zero)
            {
                WinUsb_Free(_winUsbHandle);
                _winUsbHandle = IntPtr.Zero;
            }
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            {
                _deviceHandle.Close();
            }
        }

        // Static method to find devices
        public static List<string> FindDevices(Guid interfaceGuid)
        {
            var devices = new List<string>();
            IntPtr deviceInfoSet = SetupDiGetClassDevs(ref interfaceGuid, null, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if (deviceInfoSet == IntPtr.Zero) return devices;

            try
            {
                SP_DEVICE_INTERFACE_DATA interfaceData = new SP_DEVICE_INTERFACE_DATA();
                interfaceData.cbSize = Marshal.SizeOf(interfaceData);

                for (int i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref interfaceGuid, i, ref interfaceData); i++)
                {
                    uint requiredSize = 0;
                    SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref interfaceData, IntPtr.Zero, 0, ref requiredSize, IntPtr.Zero);

                    if (requiredSize > 0)
                    {
                        IntPtr detailDataBuffer = Marshal.AllocHGlobal((int)requiredSize);
                        try
                        {
                            SP_DEVICE_INTERFACE_DETAIL_DATA detailData = new SP_DEVICE_INTERFACE_DETAIL_DATA();
                            if (IntPtr.Size == 8) // 64-bit
                                detailData.cbSize = 8;
                            else
                                detailData.cbSize = 5; // 32-bit

                            Marshal.StructureToPtr(detailData, detailDataBuffer, false);

                            if (SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref interfaceData, detailDataBuffer, requiredSize, ref requiredSize, IntPtr.Zero))
                            {
                                IntPtr pPath = new IntPtr(detailDataBuffer.ToInt64() + 4); // Skip cbSize
                                string path = Marshal.PtrToStringAuto(pPath);
                                devices.Add(path);
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(detailDataBuffer);
                        }
                    }
                }
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }
            return devices;
        }

        // P/Invoke Declarations
        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const int DIGCF_PRESENT = 0x02;
        private const int DIGCF_DEVICEINTERFACE = 0x10;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_Initialize(SafeFileHandle DeviceHandle, out IntPtr InterfaceHandle);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_Free(IntPtr InterfaceHandle);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_QueryInterfaceSettings(IntPtr InterfaceHandle, byte AlternateInterfaceNumber, out USB_INTERFACE_DESCRIPTOR UsbAltInterfaceDescriptor);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_QueryPipe(IntPtr InterfaceHandle, byte AlternateInterfaceNumber, byte PipeIndex, out WINUSB_PIPE_INFORMATION PipeInformation);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_WritePipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DllImport("winusb.dll", SetLastError = true)]
        private static extern bool WinUsb_ReadPipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, int MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, ref uint RequiredSize, IntPtr DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVICE_INTERFACE_DATA
        {
            public int cbSize;
            public Guid InterfaceClassGuid;
            public int Flags;
            public IntPtr Reserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            public int cbSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DevicePath;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct USB_INTERFACE_DESCRIPTOR
        {
            public byte bLength;
            public byte bDescriptorType;
            public byte bInterfaceNumber;
            public byte bAlternateSetting;
            public byte bNumEndpoints;
            public byte bInterfaceClass;
            public byte bInterfaceSubClass;
            public byte bInterfaceProtocol;
            public byte iInterface;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINUSB_PIPE_INFORMATION
        {
            public UsbdPipeType PipeType;
            public byte PipeId;
            public ushort MaximumPacketSize;
            public byte Interval;
        }

        private enum UsbdPipeType
        {
            UsbdPipeTypeControl,
            UsbdPipeTypeIsochronous,
            UsbdPipeTypeBulk,
            UsbdPipeTypeInterrupt
        }
    }
}
