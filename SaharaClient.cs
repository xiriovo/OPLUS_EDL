using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace OPLUS_EDL
{
    // Sahara Protocol Constants and Enums based on edl-3.52.1 sahara.py
    public enum SaharaCommand : uint
    {
        HELLO_REQ = 0x1,
        HELLO_RSP = 0x2,
        READ_DATA = 0x3,
        END_IMAGE_TX = 0x4,
        DONE_REQ = 0x5,
        DONE_RSP = 0x6,
        RESET_REQ = 0x7,
        RESET_RSP = 0x8,
        MEMORY_DEBUG = 0x9,
        MEMORY_READ = 0xA,
        CMD_READY = 0xB,
        CMD_SWITCH_MODE = 0xC,
        CMD_EXEC = 0xD,
        CMD_EXEC_RSP = 0xE,
        CMD_EXEC_DATA = 0xF,
        MEMORY_DEBUG_64 = 0x10,
        MEMORY_READ_64 = 0x11,
        READ_DATA_64 = 0x12,
        RESET_STATE = 0x14
    }

    public enum SaharaExecCommand : uint
    {
        NOP = 0x00,
        SERIAL_NUM_READ = 0x01,
        MSM_HW_ID_READ = 0x02,
        OEM_PK_HASH_READ = 0x03,
        SWITCH_TO_DMSS_DLOAD = 0x04,
        SWITCH_TO_STREAM_DLOAD = 0x05,
        READ_DEBUG_DATA = 0x06,
        GET_SOFTWARE_VERSION_SBL = 0x07
    }

    public enum SaharaStatus : uint
    {
        SUCCESS = 0x00,
        NAK_INVALID_CMD = 0x01,
        NAK_PROTOCOL_MISMATCH = 0x02,
        NAK_INVALID_TARGET_PROTOCOL = 0x03,
        NAK_INVALID_HOST_PROTOCOL = 0x04,
        NAK_INVALID_PACKET_SIZE = 0x05,
        NAK_UNEXPECTED_IMAGE_ID = 0x06,
        NAK_INVALID_HEADER_SIZE = 0x07,
        NAK_INVALID_DATA_SIZE = 0x08,
        NAK_INVALID_IMAGE_TYPE = 0x09,
        NAK_INVALID_TX_LENGTH = 0x0A,
        NAK_INVALID_RX_LENGTH = 0x0B,
        NAK_GENERAL_TX_RX_ERROR = 0x0C,
        NAK_READ_DATA_ERROR = 0x0D,
        NAK_UNSUPPORTED_NUM_PHDRS = 0x0E,
        NAK_INVALID_PDHR_SIZE = 0x0F,
        NAK_MULTIPLE_SHARED_SEG = 0x10,
        NAK_UNINIT_PHDR_LOC = 0x11,
        NAK_INVALID_DEST_ADDR = 0x12,
        NAK_INVALID_IMG_HDR_DATA_SIZE = 0x13,
        NAK_INVALID_ELF_HDR = 0x14,
        NAK_UNKNOWN_HOST_ERROR = 0x15,
        NAK_TIMEOUT_RX = 0x16,
        NAK_TIMEOUT_TX = 0x17,
        NAK_INVALID_HOST_MODE = 0x18,
        NAK_INVALID_MEMORY_READ = 0x19,
        NAK_INVALID_DATA_SIZE_REQUEST = 0x1A,
        NAK_MEMORY_DEBUG_NOT_SUPPORTED = 0x1B,
        NAK_INVALID_MODE_SWITCH = 0x1C,
        NAK_CMD_EXEC_FAILURE = 0x1D,
        NAK_EXEC_CMD_INVALID_PARAM = 0x1E,
        NAK_EXEC_CMD_UNSUPPORTED = 0x1F,
        NAK_EXEC_DATA_INVALID_CLIENT_CMD = 0x20,
        NAK_HASH_TABLE_AUTH_FAILURE = 0x21,
        NAK_HASH_VERIFICATION_FAILURE = 0x22,
        NAK_HASH_TABLE_NOT_FOUND = 0x23,
        NAK_TARGET_INIT_FAILURE = 0x24,
        NAK_IMAGE_AUTH_FAILURE = 0x25,
        NAK_INVALID_IMG_HASH_TABLE_SIZE = 0x26,
        NAK_MAX_CODE = 0x7FFFFFFF
    }

    public enum SaharaMode : uint
    {
        IMAGE_TX_PENDING = 0x0,
        IMAGE_TX_COMPLETE = 0x1,
        MEMORY_DEBUG = 0x2,
        COMMAND = 0x3
    }

    public class SaharaClient : IDisposable
    {
        private SerialPort? _port;
        private readonly Action<string> _logger;
        private readonly Action<double, string> _progress;
        
        // 当前状态
        private bool _abort = false;
        private bool _bit64 = false;

        public SaharaClient(string portName, Action<string> logger, Action<double, string>? progress)
        {
            _logger = logger;
            _progress = progress ?? ((p, s) => { });
            _port = new SerialPort(portName, 115200, Parity.None, 8, StopBits.One);
            _port.ReadTimeout = 2000; // Sahara 握手很快，超时不要太长
            _port.WriteTimeout = 2000;
            _port.Open();
        }

        public bool ConnectAndUpload(string programmerPath, CancellationToken cancellationToken)
        {
            if (!File.Exists(programmerPath))
            {
                _logger("引导文件不存在");
                return false;
            }

            try
            {
                byte[] programmerData = File.ReadAllBytes(programmerPath);
                _logger($"加载 Programmer: {programmerData.Length} 字节");
                
                DateTime startTime = DateTime.Now;
                bool done = false;

                // 初始尝试读取 Hello 包，如果之前有垃圾数据，需要清空
                _port.DiscardInBuffer();

                while (!done && !cancellationToken.IsCancellationRequested)
                {
                    SaharaPacket? pkt = ReadPacket(cancellationToken);
                    if (pkt == null) continue; // 超时重试

                    switch (pkt.Command)
                    {
                        case SaharaCommand.HELLO_REQ:
                            HandleHello(pkt.Data);
                            startTime = DateTime.Now; 
                            break;

                        case SaharaCommand.READ_DATA:
                            if (_bit64) { _logger("收到 32位请求但当前是64位模式?"); _bit64 = false; }
                            HandleReadData(pkt.Data, programmerData, startTime);
                            break;

                        case SaharaCommand.READ_DATA_64:
                            _bit64 = true;
                            HandleReadData64(pkt.Data, programmerData, startTime);
                            break;

                        case SaharaCommand.END_IMAGE_TX:
                            uint status = BitConverter.ToUInt32(pkt.Data, 4);
                            if (status == 0) 
                            {
                                _logger("Image TX 完成");
                                SendDone();
                            }
                            else 
                            {
                                _logger($"Image TX 失败，状态码: 0x{status:X}");
                                return false;
                            }
                            break;

                        case SaharaCommand.DONE_RSP:
                            _logger("Sahara 完成，准备跳转 Firehose...");
                            done = true;
                            break;
                            
                        case SaharaCommand.RESET_REQ:
                             // 设备请求复位，可能是因为出错了
                             SendReset();
                             return false; 

                        default:
                            _logger($"未知指令: {pkt.Command}");
                            break;
                    }
                }
                return done;
            }
            catch (Exception ex)
            {
                _logger($"Sahara 异常: {ex.Message}");
                return false;
            }
        }

        private void HandleHello(byte[] data)
        {
            uint version = BitConverter.ToUInt32(data, 4);
            uint mode = BitConverter.ToUInt32(data, 16);
            
            // 策略：尽量使用设备支持的最高版本，但通常 V2 足够稳定
            // 如果设备是 V3 (SM8150+)，我们回应 V2 也能工作
            uint useVer = version >= 2 ? 2u : 1u;
            
            _logger($"设备 Hello: Ver={version}, Mode={mode}. 回应 Ver={useVer}");

            // 构建 HELLO_RSP
            // 结构: Cmd(4) + Len(4) + Ver(4) + CompatVer(4) + Status(4) + Mode(4) + Reserved(24) = 48 bytes
            byte[] resp = new byte[48];
            WriteUInt32(resp, 0, (uint)SaharaCommand.HELLO_RSP);
            WriteUInt32(resp, 4, 48);
            WriteUInt32(resp, 8, useVer); // Version
            WriteUInt32(resp, 12, 1);     // Compatible Version
            WriteUInt32(resp, 16, (uint)SaharaStatus.SUCCESS);
            WriteUInt32(resp, 20, (uint)SaharaMode.IMAGE_TX_PENDING); // 关键：告诉设备我们准备传文件
            
            _port?.Write(resp, 0, resp.Length);
        }

        private void HandleReadData(byte[] data, byte[] fileData, DateTime start)
        {
            uint offset = BitConverter.ToUInt32(data, 4);
            uint len = BitConverter.ToUInt32(data, 8);
            SendFileChunk(fileData, (long)offset, (int)len, start);
        }

        private void HandleReadData64(byte[] data, byte[] fileData, DateTime start)
        {
            ulong offset = BitConverter.ToUInt64(data, 8);
            ulong len = BitConverter.ToUInt64(data, 16);
            SendFileChunk(fileData, (long)offset, (int)len, start);
        }

        private void SendFileChunk(byte[] fileData, long offset, int length, DateTime startTime)
        {
            if (offset + length > fileData.Length)
            {
                _logger($"错误: 设备请求越界 {offset} + {length} > {fileData.Length}");
                return;
            }

            // 直接写入，无需复制数组 (SerialPort.Write 支持 offset)
            _port?.Write(fileData, (int)offset, length);
            
            // 报告进度
            double progress = (double)(offset + length) / fileData.Length * 100.0;
            _progress?.Invoke(progress, $"上传中 {(int)progress}%");
        }

        private void SendDone()
        {
            byte[] pkt = new byte[8];
            WriteUInt32(pkt, 0, (uint)SaharaCommand.DONE_REQ);
            WriteUInt32(pkt, 4, 8);
            _port?.Write(pkt, 0, 8);
        }
        
        private void SendReset()
        {
            byte[] pkt = new byte[8];
            WriteUInt32(pkt, 0, (uint)SaharaCommand.RESET_RSP);
            WriteUInt32(pkt, 4, 8);
            _port?.Write(pkt, 0, 8);
        }

        private SaharaPacket? ReadPacket(CancellationToken token)
        {
            try
            {
                // 1. 读取头 (8字节)
                byte[] header = ReadBytes(8, token);
                uint cmd = BitConverter.ToUInt32(header, 0);
                uint len = BitConverter.ToUInt32(header, 4);

                if (len < 8 || len > 1024*1024) throw new Exception($"非法包长度: {len}");

                // 2. 读取剩余体
                byte[] body = new byte[0];
                if (len > 8)
                {
                    body = ReadBytes((int)len - 8, token);
                }

                return new SaharaPacket { Command = (SaharaCommand)cmd, Length = len, Data = body };
            }
            catch (TimeoutException) { return null; }
            catch (Exception) { return null; }
        }

        private byte[] ReadBytes(int count, CancellationToken token)
        {
            byte[] buf = new byte[count];
            int total = 0;
            while (total < count)
            {
                if (token.IsCancellationRequested) throw new Exception("Cancelled");
                try
                {
                    int read = _port!.Read(buf, total, count - total);
                    if (read == 0) throw new EndOfStreamException();
                    total += read;
                }
                catch (TimeoutException) 
                {
                    if (token.IsCancellationRequested) throw new Exception("Cancelled");
                    throw; // 抛出 Timeout 让上层决定重试
                }
            }
            return buf;
        }

        private void WriteUInt32(byte[] buf, int offset, uint val)
        {
            BitConverter.GetBytes(val).CopyTo(buf, offset);
        }

        public void Dispose()
        {
            if (_port != null && _port.IsOpen)
            {
                _port.Close();
                _port.Dispose();
            }
        }

        // --- Compatibility Methods ---

        public class SaharaPacket
        {
            public SaharaCommand Command;
            public uint Length;
            public byte[] Data = Array.Empty<byte>();
        }

        public Dictionary<string, string>? GetDeviceInfo()
        {
            try
            {
                var pkt = ReadPacket(default);
                if (pkt == null || pkt.Command != SaharaCommand.HELLO_REQ)
                {
                    _logger("未收到 Hello 请求，无法获取信息。");
                    return null;
                }

                uint devVer = BitConverter.ToUInt32(pkt.Data, 4);
                int useVer = GetBestVersion(devVer);
                
                if (useVer < 3)
                {
                    _logger($"警告: 当前协议版本 ({useVer}) 可能不支持命令执行 (需 V3)。尝试继续...");
                }

                SendHelloResponse(SaharaMode.COMMAND, useVer);

                pkt = ReadPacket(default);
                if (pkt == null || pkt.Command != SaharaCommand.CMD_READY)
                {
                    _logger("未收到 CMD_READY。");
                    return null;
                }

                var info = new Dictionary<string, string>();

                info["Serial"] = ExecuteCommand(SaharaExecCommand.SERIAL_NUM_READ);
                info["HWID"] = ExecuteCommand(SaharaExecCommand.MSM_HW_ID_READ);
                info["PKHash"] = ExecuteCommand(SaharaExecCommand.OEM_PK_HASH_READ);
                info["SBLVersion"] = ExecuteCommand(SaharaExecCommand.GET_SOFTWARE_VERSION_SBL);

                SendSwitchMode(SaharaMode.IMAGE_TX_PENDING);

                return info;
            }
            catch (Exception ex)
            {
                _logger($"获取设备信息失败: {ex.Message}");
                return null;
            }
        }

        private string ExecuteCommand(SaharaExecCommand cmd)
        {
            byte[] pkt = new byte[12];
            WriteUInt32(pkt, 0, (uint)SaharaCommand.CMD_EXEC);
            WriteUInt32(pkt, 4, 12);
            WriteUInt32(pkt, 8, (uint)cmd);
            if (_port != null) _port.Write(pkt, 0, 12);

            var resp = ReadPacket(default);
            if (resp == null || resp.Command != SaharaCommand.CMD_EXEC_RSP) return "";

            uint respLen = BitConverter.ToUInt32(resp.Data, 4);
            
            byte[] pktData = new byte[12];
            WriteUInt32(pktData, 0, (uint)SaharaCommand.CMD_EXEC_DATA);
            WriteUInt32(pktData, 4, 12);
            WriteUInt32(pktData, 8, (uint)cmd);
            if (_port != null) _port.Write(pktData, 0, 12);

            if (respLen > 0)
            {
                byte[] data = ReadBytes((int)respLen, default);
                
                if (cmd == SaharaExecCommand.OEM_PK_HASH_READ)
                {
                    return BitConverter.ToString(data).Replace("-", "").ToLower();
                }
                else if (cmd == SaharaExecCommand.SERIAL_NUM_READ)
                {
                     if (data.Length == 4) return BitConverter.ToUInt32(data, 0).ToString("X8");
                     return BitConverter.ToString(data).Replace("-", "");
                }
                else if (cmd == SaharaExecCommand.MSM_HW_ID_READ)
                {
                     return BitConverter.ToString(data).Replace("-", "");
                }
                else if (cmd == SaharaExecCommand.GET_SOFTWARE_VERSION_SBL)
                {
                     return Encoding.ASCII.GetString(data).Trim('\0');
                }
                
                return BitConverter.ToString(data).Replace("-", "");
            }
            return "";
        }

        private int GetBestVersion(uint deviceVersion)
        {
            if (deviceVersion >= 3) return 3;
            if (deviceVersion == 2) return 2;
            return 1;
        }

        private void SendHelloResponse(SaharaMode mode, int version)
        {
            byte[] pkt = new byte[48];
            WriteUInt32(pkt, 0, (uint)SaharaCommand.HELLO_RSP);
            WriteUInt32(pkt, 4, 48);
            WriteUInt32(pkt, 8, (uint)version);
            WriteUInt32(pkt, 12, 1);
            WriteUInt32(pkt, 16, (uint)SaharaStatus.SUCCESS);
            WriteUInt32(pkt, 20, (uint)mode);
            if (_port != null) _port.Write(pkt, 0, 48);
        }

        private void SendSwitchMode(SaharaMode mode)
        {
            byte[] pkt = new byte[12];
            WriteUInt32(pkt, 0, (uint)SaharaCommand.CMD_SWITCH_MODE);
            WriteUInt32(pkt, 4, 12);
            WriteUInt32(pkt, 8, (uint)mode);
            if (_port != null) _port.Write(pkt, 0, 12);
        }
    }
}
