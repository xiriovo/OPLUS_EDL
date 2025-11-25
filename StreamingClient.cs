using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading;

namespace OPLUS_EDL
{
    public class StreamingClient : IDisposable
    {
        private SerialPort _port;
        private Action<string> _logger;
        private Action<double, string> _progress;

        // Commands based on QC DLOAD protocol
        private const byte CMD_WRITE = 0x01;
        private const byte CMD_ACK = 0x02;
        private const byte CMD_NAK = 0x03;
        private const byte CMD_ERASE = 0x04;
        private const byte CMD_GO = 0x05;
        private const byte CMD_NOP = 0x06;
        private const byte CMD_PREAMBLE = 0x07;
        private const byte CMD_ADDR_32BIT = 0x08;
        private const byte CMD_BODY_32BIT = 0x09;
        private const byte CMD_MEM_READ = 0x0A;
        private const byte CMD_MEM_WRITE = 0x0B;
        private const byte CMD_READ_VERSION = 0x0C;
        private const byte CMD_READ_PHONE_ID = 0x0D;
        private const byte CMD_WRITE_32BIT = 0x0F;
        private const byte CMD_READ_MULTI_BLOCK = 0x10;
        private const byte CMD_WRITE_MULTI_BLOCK = 0x11;
        
        // Extended commands (Streaming DLOAD)
        private const byte CMD_STREAM_WRITE = 0x30;
        private const byte CMD_STREAM_READ = 0x31;
        private const byte CMD_RESET = 0x32;
        private const byte CMD_GET_PARAMS = 0x33;
        private const byte CMD_SET_PARAMS = 0x34;
        private const byte CMD_OPEN_MULTI_IMAGE = 0x35;
        private const byte CMD_CLOSE_MULTI_IMAGE = 0x36;
        private const byte CMD_READ_PARTITION_TABLE = 0x37;
        private const byte CMD_UNFRAMED_READ = 0x38;
        private const byte CMD_UNFRAMED_WRITE = 0x39;

        public StreamingClient(SerialPort port, Action<string> logger, Action<double, string> progress)
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

            // Simple state machine to read HDLC packet
            // 7E ... data ... 7E
            
            // Timeout handling needed
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
                            // End of packet
                            buffer.Add(b);
                            return Hdlc.Decapsulate(buffer.ToArray());
                        }
                        else
                        {
                            // Start of packet
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
                Log("Sending NOP to check connection...");
                SendPacket(new byte[] { CMD_NOP });
                byte[] resp = ReceivePacket();
                if (resp != null && resp.Length > 0 && resp[0] == CMD_ACK)
                {
                    Log("Connected to Streaming DLOAD mode.");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Log($"Connection failed: {ex.Message}");
            }
            return false;
        }

        public byte[] ReadPartitionTable()
        {
            Log("Reading Partition Table...");
            SendPacket(new byte[] { CMD_READ_PARTITION_TABLE });
            byte[] resp = ReceivePacket();
            if (resp != null && resp.Length > 0 && resp[0] == CMD_READ_PARTITION_TABLE)
            {
                // Response format depends on implementation, usually status + data
                // But for simple implementation, let's assume it returns the table or ACK + data
                // Need to check specific implementation details
                return resp;
            }
            return null;
        }

        public void Dispose()
        {
            // Port is managed externally usually, but if we own it:
            // _port?.Close();
        }
    }
}
