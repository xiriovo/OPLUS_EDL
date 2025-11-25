using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace OPLUS_EDL
{
    public class FastbootClient
    {
        private static Guid AndroidUsbDeviceGuid = new Guid("f72fe0d4-cbcb-407d-8814-9ed673d0dd6b");

        public static bool IsConnected()
        {
            var devices = NativeUsb.FindDevices(AndroidUsbDeviceGuid);
            foreach (var devPath in devices)
            {
                try
                {
                    using (var usb = new NativeUsb(devPath))
                    {
                        if (usb.InterfaceClass == 0xFF && 
                            usb.InterfaceSubClass == 0x42 && 
                            usb.InterfaceProtocol == 0x03)
                        {
                            return true;
                        }
                    }
                }
                catch {}
            }
            return false;
        }

        public static void RebootEdl()
        {
            // Try multiple commands
            string[] commands = { "oem edl", "oem enter-dload", "reboot-edl" };
            foreach (var cmd in commands)
            {
                try
                {
                    SendCommand(cmd);
                    return; // If successful (or at least sent without error)
                }
                catch { /* Try next */ }
            }
            throw new Exception("Failed to reboot to EDL (tried oem edl, oem enter-dload, reboot-edl)");
        }

        public static void RebootBootloader()
        {
            SendCommand("reboot-bootloader");
        }

        public static void RebootRecovery()
        {
             try { SendCommand("oem reboot-recovery"); return; } catch {}
             SendCommand("reboot recovery");
        }

        public static void RebootSystem()
        {
            SendCommand("reboot");
        }

        public static void RebootFastbootD()
        {
            SendCommand("reboot fastboot");
        }

        public static void PowerOff()
        {
            SendCommand("oem poweroff");
        }

        private static void SendCommand(string command)
        {
            var devices = NativeUsb.FindDevices(AndroidUsbDeviceGuid);
            bool deviceFound = false;
            foreach (var devPath in devices)
            {
                try
                {
                    using (var usb = new NativeUsb(devPath))
                    {
                        if (usb.InterfaceClass == 0xFF && 
                            usb.InterfaceSubClass == 0x42 && 
                            usb.InterfaceProtocol == 0x03)
                        {
                            deviceFound = true;
                            byte[] cmdBytes = Encoding.ASCII.GetBytes(command);
                            usb.Write(cmdBytes);
                            
                            byte[] buffer = new byte[64];
                            int read = usb.Read(buffer);
                            string response = Encoding.ASCII.GetString(buffer, 0, read);
                            
                            if (!response.StartsWith("OKAY"))
                            {
                                throw new Exception($"Fastboot command failed: {response}");
                            }
                            return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    // If we found the device but failed to talk, rethrow
                    if (deviceFound) throw new Exception($"Failed to send fastboot command: {ex.Message}");
                }
            }
            if (!deviceFound) throw new Exception("No Fastboot device found");
        }
    }
}
