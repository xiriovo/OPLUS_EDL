using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading;

namespace OPLUS_EDL
{
    public class DiagClient : IDisposable
    {
        private SerialPort _port;
        private Action<string> _logger;
        private Action<double, string> _progress;

        // Diag Commands
        private const byte DIAG_VERNO_F = 0x00;
        private const byte DIAG_ESN_F = 0x01;
        private const byte DIAG_PEEK_BYTE_F = 0x02;
        private const byte DIAG_PEEK_WORD_F = 0x03;
        private const byte DIAG_PEEK_DWORD_F = 0x04;
        private const byte DIAG_POKE_BYTE_F = 0x05;
        private const byte DIAG_POKE_WORD_F = 0x06;
        private const byte DIAG_POKE_DWORD_F = 0x07;
        private const byte DIAG_STATUS_F = 0x0C;
        private const byte DIAG_LOGMASK_F = 0x0F;
        private const byte DIAG_NV_READ_F = 0x26;
        private const byte DIAG_NV_WRITE_F = 0x27;
        private const byte DIAG_CONTROL_F = 0x29;
        private const byte DIAG_EXT_BUILD_ID_F = 0x7C;
        private const byte DIAG_SUBSYS_CMD_F = 0x4B;

        public DiagClient(SerialPort port, Action<string> logger, Action<double, string> progress)
        {
            _port = port;
            _logger = logger;
            _progress = progress;
        }

        private void Log(string message)
        {
            _logger?.Invoke(message);
        }

        private void SendPacket(byte[] data)
        {
            byte[] packet = Hdlc.Encapsulate(data);
            _port.Write(packet, 0, packet.Length);
        }

        private byte[] ReceivePacket()
        {
            List<byte> buffer = new List<byte>();
            byte[] temp = new byte[1];
            bool startFound = false;
            
            DateTime start = DateTime.Now;
            while ((DateTime.Now - start).TotalSeconds < 5)
            {
                if (_port.BytesToRead > 0)
                {
                    _port.Read(temp, 0, 1);
                    byte b = temp[0];

                    if (b == 0x7E)
                    {
                        if (startFound)
                        {
                            buffer.Add(b);
                            return Hdlc.Decapsulate(buffer.ToArray());
                        }
                        else
                        {
                            startFound = true;
                            buffer.Add(b);
                        }
                    }
                    else if (startFound)
                    {
                        buffer.Add(b);
                    }
                }
            }
            throw new TimeoutException("Timeout waiting for packet");
        }

        public bool Connect()
        {
            try
            {
                Log("Sending Version Request...");
                SendPacket(new byte[] { DIAG_VERNO_F });
                byte[] resp = ReceivePacket();
                if (resp != null && resp.Length > 0 && resp[0] == DIAG_VERNO_F)
                {
                    Log("Connected to Diagnostic mode.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log($"Connection failed: {ex.Message}");
            }
            return false;
        }

        public byte[] ReadNV(ushort itemId)
        {
            Log($"Reading NV Item {itemId}...");
            List<byte> req = new List<byte>();
            req.Add(DIAG_NV_READ_F);
            req.Add((byte)(itemId & 0xFF));
            req.Add((byte)((itemId >> 8) & 0xFF));
            // Padding might be needed depending on implementation
            
            SendPacket(req.ToArray());
            byte[] resp = ReceivePacket();
            if (resp != null && resp.Length > 0 && resp[0] == DIAG_NV_READ_F)
            {
                return resp;
            }
            return null;
        }

        public bool WriteNV(ushort itemId, byte[] data)
        {
            Log($"Writing NV Item {itemId}...");
            List<byte> req = new List<byte>();
            req.Add(DIAG_NV_WRITE_F);
            req.Add((byte)(itemId & 0xFF));
            req.Add((byte)((itemId >> 8) & 0xFF));
            req.AddRange(data);
            
            SendPacket(req.ToArray());
            byte[] resp = ReceivePacket();
            if (resp != null && resp.Length > 0 && resp[0] == DIAG_NV_WRITE_F)
            {
                return true;
            }
            return false;
        }

        public void SwitchToEDL()
        {
            Log("Switching to EDL mode...");
            // Command to switch to EDL (often 0x3A or specific subsys command)
            // Common method: Send DLOAD command
            byte[] cmd = new byte[] { 0x3A }; // DIAG_DLOAD_F
            SendPacket(cmd);
        }

        public void Dispose()
        {
            // _port?.Close();
        }
    }
}
