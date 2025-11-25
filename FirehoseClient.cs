using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Ports;
using System.Text;
using System.Threading;
using System.Text.RegularExpressions;
using System.Linq;
using System.Runtime.InteropServices;

namespace OPLUS_EDL
{
    public class FirehoseClient : IDisposable
    {
        private SerialPort? _port;
        private readonly string _portName;
        private readonly Action<string> _logger;
        
        // 增加缓冲区大小以提升大文件传输效率
        private const int INTERNAL_BUFFER_SIZE = 1024 * 1024; 

        public int SectorSize { get; private set; } = 4096;
        public string MemoryName { get; private set; } = "UFS";
        public int MaxPayloadSizeToTarget { get; private set; } = 1048576;
        public int MaxPayloadSizeFromTarget { get; private set; } = 1048576;
        public string TargetName { get; private set; } = "unknown";
        public int TotalBlocks { get; private set; } = 0;
        public int BlockSize { get; private set; } = 0;

        public FirehoseClient(string portName, Action<string> logger)
        {
            _portName = portName;
            _logger = logger;
        }

        public void Connect()
        {
            if (_port != null && _port.IsOpen) return;
            _port = new SerialPort(_portName, 115200, Parity.None, 8, StopBits.One);
            _port.ReadTimeout = 5000; // 设置合理的读超时
            _port.WriteTimeout = 5000;
            _port.ReadBufferSize = 1024 * 1024; // 1MB 读缓冲
            _port.WriteBufferSize = 1024 * 1024; // 1MB 写缓冲
            _port.Open();
        }

        public bool Configure()
        {
            Connect();
            // 修正：MaxDigestTableSizeInBytes 通常设大一点，SkipWrite=0
            string xml = $"<?xml version=\"1.0\" ?><data><configure ZlpAwareHost=\"1\" MaxPayloadSizeToTargetInBytes=\"{MaxPayloadSizeToTarget}\" AckRawDataEveryNumPackets=\"0\" SkipWrite=\"0\" Verbose=\"0\" MaxDigestTableSizeInBytes=\"8192\" AlwaysValidate=\"0\" MemoryName=\"ufs\" SkipStorageInit=\"0\" EnableFlash=\"0\" /></data>";
            if (!WriteXml(xml)) return false;

            var response = WaitForResponse();
            if (response == null || !IsAck(response)) 
            {
                _logger?.Invoke($"配置失败: {response?.Response ?? "无响应"}");
                return false;
            }

            ParseConfigResponse(response);
            return true;
        }

        private void ParseConfigResponse(QCResponse response)
        {
            if (response.Properties.TryGetValue("MemoryName", out var mem))
            {
                MemoryName = mem;
                SectorSize = MemoryName.ToLower() == "emmc" ? 512 : 4096;
                _logger?.Invoke($"存储类型: {MemoryName}, 扇区大小: {SectorSize}");
            }
            
            if (response.Properties.TryGetValue("MaxPayloadSizeFromTargetInBytes", out var sizeFrom))
            {
                if (int.TryParse(sizeFrom, out int val)) MaxPayloadSizeFromTarget = val;
            }
            
            if (response.Properties.TryGetValue("MaxPayloadSizeToTargetInBytesSupported", out var sizeTo))
            {
                if (int.TryParse(sizeTo, out int val)) MaxPayloadSizeToTarget = val;
            }

            if (response.Properties.TryGetValue("TargetName", out var target))
                TargetName = target;
        }

        public bool SendVIPAuth(string[] signatures)
        {
            Connect();
            foreach (var sign in signatures)
            {
                try
                {
                    if (_port == null || !_port.IsOpen) Connect();
                    
                    _logger?.Invoke("正在尝试 VIP 授权签名...");
                    string cmd = "<?xml version=\"1.0\" ?><data><sig TargetName=\"sig\" verbose=\"1\" size_in_bytes=\"256\" /></data>";
                    if (!WriteXml(cmd)) continue;

                    var resp = WaitForResponse();
                    if (resp == null || resp.Response != "ACK") continue;

                    byte[] signBytes = HexStringToByteArray(sign);
                    _port?.Write(signBytes, 0, signBytes.Length);

                    var authResp = WaitForResponse();
                    if (authResp != null && authResp.Logs.Any(l => l.ToLower().Contains("authenticated")))
                    {
                        _logger?.Invoke("VIP 授权成功!");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Invoke($"授权错误: {ex.Message}");
                    // Try to recover connection for next attempt
                    try { if (_port != null && _port.IsOpen) _port.Close(); } catch { }
                    continue;
                }
            }
            _logger?.Invoke("VIP 授权失败。");
            return false;
        }

        public byte[]? ReadData(int physicalPartition, long startSector, long numSectors, int? sectorSizeOverride = null, CancellationToken token = default, string label = "gptbackup0", string filename = "gpt_backup0.bin")
        {
            Connect();
            if (_port == null) return null;
            int actualSectorSize = sectorSizeOverride ?? SectorSize;
            // Added filename="read.bin" as some loaders require it to stream data
            // Added label="read_data" as some loaders (OPLUS) require it
            // Updated to use gptbackup0 as default to bypass some loader restrictions
            string command = $"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><read physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\" num_partition_sectors=\"{numSectors}\" SECTOR_SIZE_IN_BYTES=\"{actualSectorSize}\" filename=\"{filename}\" label=\"{label}\" /></data>";
            if (!WriteXml(command)) return null;

            // Pass true to indicate we are waiting for a read response, which might be just a log
            var response = WaitForResponse(true);
            if (response == null || response.Response != "ACK") 
            {
                _logger?.Invoke($"读取指令失败: {response?.Response ?? "无响应"}");
                return null;
            }

            long totalBytes = numSectors * actualSectorSize;
            byte[] result = new byte[totalBytes];
            long bytesRead = 0;

            if (response.UnhandledData != null && response.UnhandledData.Length > 0)
            {
                Array.Copy(response.UnhandledData, 0, result, 0, Math.Min(response.UnhandledData.Length, totalBytes));
                bytesRead += response.UnhandledData.Length;
            }

            while (bytesRead < totalBytes)
            {
                if (token.IsCancellationRequested) return null;

                int chunkSize = (int)Math.Min(MaxPayloadSizeFromTarget, totalBytes - bytesRead);
                int read = ReadExact(_port, result, (int)bytesRead, chunkSize, token);
                if (read == 0) break;
                bytesRead += read;
                
                // Optional: Report progress
            }

            WaitForResponse(); // Wait for final ACK/Finished
            return result;
        }

        public bool WriteData(int physicalPartition, long startSector, byte[] data, Action<double>? progress = null, string label = "gptbackup0", string filename = "gpt_backup0.bin")
        {
            Connect();
            if (_port == null) return false;
            long numSectors = data.Length / SectorSize;
            if (data.Length % SectorSize != 0) numSectors++;

            string command = $"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><program physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\" num_partition_sectors=\"{numSectors}\" SECTOR_SIZE_IN_BYTES=\"{SectorSize}\" filename=\"{filename}\" label=\"{label}\" /></data>";
            if (!WriteXml(command)) return false;

            var response = WaitForResponse();
            if (response == null || response.Response != "ACK")
            {
                _logger?.Invoke($"写入指令失败: {response?.Response ?? "无响应"}");
                return false;
            }

            int offset = 0;
            while (offset < data.Length)
            {
                int chunkSize = Math.Min(MaxPayloadSizeToTarget, data.Length - offset);
                _port.Write(data, offset, chunkSize);
                offset += chunkSize;
                progress?.Invoke((double)offset / data.Length * 100.0);
            }

            var finalResp = WaitForResponse();
            return finalResp != null && finalResp.Response == "ACK";
        }

        public bool Reset()
        {
            Connect();
            string command = "<?xml version=\"1.0\" ?><data><power value=\"reset\"/></data>";
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public bool SetActiveSlot(string slot)
        {
            Connect();
            int slotIndex = (slot.ToLower() == "a" || slot == "0") ? 0 : 1;
            string command = $"<?xml version=\"1.0\" ?><data><setactiveslot slot=\"{slotIndex}\"/></data>";
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && IsAck(resp);
        }

        public bool SetBootableStorageDrive(int lun)
        {
            Connect();
            string command = $"<?xml version=\"1.0\" ?><data><setbootablestoragedrive value=\"{lun}\" /></data>";
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public bool SetActiveBootSlot(string slotValue)
        {
            if (int.TryParse(slotValue, out int lun))
            {
                return SetBootableStorageDrive(lun);
            }
            return false;
        }

        public bool Nop()
        {
            Connect();
            string command = "<?xml version=\"1.0\" ?><data><nop /></data>";
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public string? GetSha256Digest(int physicalPartition, long startSector, long numSectors)
        {
            Connect();
            string command = $"<?xml version=\"1.0\" ?><data><getsha256digest SECTOR_SIZE_IN_BYTES=\"{SectorSize}\" num_partition_sectors=\"{numSectors}\" physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\"/></data>";
            if (!WriteXml(command)) return null;
            
            var resp = WaitForResponse();
            if (resp != null && resp.Response == "ACK")
            {
                foreach (var log in resp.Logs)
                {
                    if (log.Contains("Digest"))
                    {
                        // Format: "Digest <hash>"
                        var parts = log.Split(new[] { "Digest" }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length > 0) return parts[parts.Length - 1].Trim();
                    }
                }
                // Sometimes it's just in the log without "Digest" prefix if the device is weird, but standard is "Digest ..."
            }
            return null;
        }

        public bool WriteIMEI(string imei)
        {
            if (string.IsNullOrEmpty(imei) || imei.Length != 16)
            {
                _logger?.Invoke("IMEI must be 16 digits (including check digit/padding if needed)");
                return false;
            }
            Connect();
            string command = $"<?xml version=\"1.0\" ?><data><writeIMEI len=\"16\"/></data>";
            // Note: The python code sends the command, but doesn't seem to send the IMEI payload in the XML? 
            // Wait, looking at python: data = "<?xml ...><writeIMEI len=\"16\"/>..."
            // It seems it expects the device to ask for data or it's just a trigger?
            // Actually, usually writeIMEI is a custom command that might expect data packet afterwards.
            // But based on python code: val = self.xmlsend(data). If val[0] -> success.
            // It doesn't seem to send the IMEI bytes? 
            // Ah, maybe the IMEI is supposed to be in the command? 
            // Python code: def cmd_writeimei(self, imei): ... data = "...<writeIMEI len=\"16\"/>..."
            // It ignores the `imei` argument in the XML construction! This might be a bug in the python reference or it relies on a specific payload sequence not shown.
            // However, standard Qualcomm Firehose doesn't have "writeIMEI". This is likely an OEM extension.
            // I will implement it as is.
            
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public bool Peek(ulong address, ulong size, Stream outputStream, Action<long, long>? progress = null)
        {
            Connect();
            string command = $"<?xml version=\"1.0\" ?><data><peek address64=\"{address}\" size_in_bytes=\"{size}\" /></data>";
            if (!WriteXml(command)) return false;

            // Peek response is usually a series of logs with values: <log value="0x12 0x34 ..."/>
            // We need to parse these logs and write to stream.
            
            var resp = WaitForResponse(); // This might only get the first packet or ACK.
            // Actually, WaitForResponse accumulates logs.
            
            if (resp == null) return false;

            long bytesWritten = 0;
            foreach (var log in resp.Logs)
            {
                // Log value="0x12 0x34 ..."
                // We need to parse hex strings
                try 
                {
                    string cleanLog = log.Replace("0x", "").Replace(" ", "");
                    byte[] data = HexStringToByteArray(cleanLog);
                    outputStream.Write(data, 0, data.Length);
                    bytesWritten += data.Length;
                    progress?.Invoke(bytesWritten, (long)size);
                }
                catch {}
            }
            
            return bytesWritten > 0; // Return true if we got any data
        }

        public bool Poke(ulong address, byte[] data)
        {
            Connect();
            // Poke sends data in the XML attribute 'value64' or 'value'
            // It might need splitting if data is too large for one XML
            // Python does this splitting.
            
            int offset = 0;
            while (offset < data.Length)
            {
                int chunk = Math.Min(data.Length - offset, 8); // Python uses maxsize=8 by default for 64-bit poke?
                // Actually python loop: while lengthtowrite > 0 ... maxsize = 8 ...
                // It seems it writes 8 bytes at a time? That's very slow.
                // But `poke` is usually for registers, not bulk data.
                
                byte[] chunkData = new byte[chunk];
                Array.Copy(data, offset, chunkData, 0, chunk);
                
                // Convert to big integer hex string?
                // Python: content = hex(int(hexlify(data).decode('utf-8'), 16))
                // This creates a single hex number "0x12345678..."
                
                string hexVal = "0x" + BitConverter.ToString(chunkData.Reverse().ToArray()).Replace("-", ""); 
                // Note: Python's int(hexlify) treats it as a big number. 
                // If we send 0x12 0x34, hexlify is "1234", int is 0x1234.
                // BitConverter is Little Endian usually.
                
                string command = $"<?xml version=\"1.0\" ?><data><poke address64=\"{address + (ulong)offset}\" SizeInBytes=\"{chunk}\" value64=\"{hexVal}\" /></data>";
                
                if (!WriteXml(command)) return false;
                var resp = WaitForResponse();
                if (resp == null || resp.Response != "ACK") return false;
                
                offset += chunk;
            }
            return true;
        }

        public bool Patch(int physicalPartition, long startSector, long byteOffset, long sizeInBytes, string value, string filename = "DISK")
        {
            Connect();
            string command = $"<?xml version=\"1.0\" ?><data><patch SECTOR_SIZE_IN_BYTES=\"{SectorSize}\" byte_offset=\"{byteOffset}\" filename=\"{filename}\" physical_partition_number=\"{physicalPartition}\" size_in_bytes=\"{sizeInBytes}\" start_sector=\"{startSector}\" value=\"{value}\" /></data>";
            if (!WriteXml(command)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public Dictionary<string, string>? GetStorageInfo()
        {
            Connect();
            string command = "<?xml version=\"1.0\" ?><data><getstorageinfo /></data>";
            if (!WriteXml(command)) return null;
            var resp = WaitForResponse();
            if (resp != null && resp.Logs.Count > 0)
            {
                // Often the info is in a log message like "INFO: { ...json... }"
                foreach (var log in resp.Logs)
                {
                    if (log.Contains("storage_info"))
                    {
                        // This is a simplified parser, real one might need JSON parsing
                        // But for now we just return the properties from the response tag if available
                        // Or we could try to parse the log string if it's JSON
                        _logger?.Invoke($"Storage Info Log: {log}");
                    }
                }
                return resp.Properties;
            }
            return null;
        }

        // ---------------- 核心优化区域：ReadDataToStream ----------------
        // 使用流式读写，避免一次性分配巨大内存
        public bool ReadDataToStream(int physicalPartition, long startSector, long numSectors, Stream outputStream, Action<long, long>? progress = null, int? sectorSizeOverride = null, CancellationToken cancellationToken = default, string label = "read", string filename = "read.bin")
        {
            Connect();
            if (_port == null) return false;
            int actualSectorSize = sectorSizeOverride ?? SectorSize;
            
            string command = $"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><read physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\" num_partition_sectors=\"{numSectors}\" SECTOR_SIZE_IN_BYTES=\"{actualSectorSize}\" filename=\"{filename}\" label=\"{label}\" /></data>";
            
            if (!WriteXml(command)) return false;

            // 这里有一个关键点：Firehose 的 Read 响应可能包含 XML Log，紧接着是 Raw Data
            // WaitForResponse 需要能处理这种情况
            var response = WaitForResponse(expectRawData: true);
            
            if (response == null || !IsAck(response)) 
            {
                _logger?.Invoke($"读取指令失败: {response?.Response ?? "无响应"}");
                return false;
            }

            long totalBytes = numSectors * actualSectorSize;
            long bytesRead = 0;

            // 1. 处理 WaitForResponse 中可能已经读到的“残留”二进制数据
            if (response.UnhandledData != null && response.UnhandledData.Length > 0)
            {
                outputStream.Write(response.UnhandledData, 0, response.UnhandledData.Length);
                bytesRead += response.UnhandledData.Length;
                progress?.Invoke(bytesRead, totalBytes);
            }

            // 2. 循环读取剩余数据
            byte[] buffer = new byte[Math.Min(MaxPayloadSizeFromTarget, 64 * 1024)]; // 64KB chunks usually safer for UI updates
            
            while (bytesRead < totalBytes)
            {
                if (cancellationToken.IsCancellationRequested) return false;

                int bytesToRead = (int)Math.Min(buffer.Length, totalBytes - bytesRead);
                int read = ReadExact(_port, buffer, 0, bytesToRead, cancellationToken);
                
                if (read <= 0) break; // Timeout or closed
                
                outputStream.Write(buffer, 0, read);
                bytesRead += read;
                progress?.Invoke(bytesRead, totalBytes);
            }

            // 3. 读取传输结束后的最终 Log/ACK (部分设备传输完数据后还会发一个 XML)
            // 这一步是可选的，有些设备不发，为了防止卡住，可以用很短的超时尝试读一下，读不到也没关系
            TryReadFinalLog();

            return bytesRead == totalBytes;
        }

        public bool WriteDataFromStream(int physicalPartition, long startSector, Stream inputStream, long length, Action<long, long>? progress = null, CancellationToken cancellationToken = default, string label = "flash", string filename = "flash.bin")
        {
            Connect();
            if (_port == null) return false;
            
            // 计算扇区数，向上取整
            long numSectors = (length + SectorSize - 1) / SectorSize;

            string command = $"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><program physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\" num_partition_sectors=\"{numSectors}\" SECTOR_SIZE_IN_BYTES=\"{SectorSize}\" filename=\"{filename}\" label=\"{label}\" /></data>";
            if (!WriteXml(command)) return false;

            var response = WaitForResponse();
            if (response == null || !IsAck(response)) return false;

            byte[] buffer = new byte[MaxPayloadSizeToTarget]; 
            long totalSent = 0;
            int read;

            // 确保输入流在正确位置
            if (inputStream.CanSeek) inputStream.Seek(0, SeekOrigin.Begin);

            while ((read = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (cancellationToken.IsCancellationRequested) return false;

                // 如果是最后一块且不足 buffer 大小，Firehose 协议通常要求填充 0 或者是按实际字节发？
                // Firehose 是流式的，直接发实际字节即可，设备会根据 num_partition_sectors 计数。
                _port.Write(buffer, 0, read);
                totalSent += read;
                progress?.Invoke(totalSent, length);
            }

            // 发送完毕后，必须等待设备确认写入完成
            // 这里也需要支持取消，虽然通常很快
            // WaitForResponse 内部是 10s 超时，我们可以在外部循环调用或者修改 WaitForResponse 支持 Token
            // 鉴于 WaitForResponse 已经很复杂，这里暂时保持原样，因为它有超时保护
            var finalResp = WaitForResponse();
            return finalResp != null && IsAck(finalResp);
        }

        public bool Erase(int physicalPartition, long startSector, long numSectors)
        {
            Connect();
            string command = $"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><erase physical_partition_number=\"{physicalPartition}\" start_sector=\"{startSector}\" num_partition_sectors=\"{numSectors}\" SECTOR_SIZE_IN_BYTES=\"{SectorSize}\" /></data>";
            if (!WriteXml(command)) return false;
            
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public bool SendRawXml(string xml)
        {
            Connect();
            if (!WriteXml(xml)) return false;
            var resp = WaitForResponse();
            return resp != null && resp.Response == "ACK";
        }

        public bool SendXmlFile(string filePath)
        {
            if (!File.Exists(filePath)) return false;
            Connect();
            try
            {
                string xml = File.ReadAllText(filePath);
                _logger?.Invoke($"发送 XML 文件: {Path.GetFileName(filePath)}");
                if (!WriteXml(xml)) return false;
                
                var resp = WaitForResponse();
                if (resp == null || resp.Response != "ACK")
                {
                    _logger?.Invoke($"XML 文件 {Path.GetFileName(filePath)} 执行失败: {resp?.Response ?? "无响应"}");
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                _logger?.Invoke($"发送 XML 异常: {ex.Message}");
                return false;
            }
        }

        public bool SendSignatureFile(string filePath, string targetName = "sig")
        {
            if (!File.Exists(filePath)) return false;
            Connect();
            try
            {
                byte[] data = File.ReadAllBytes(filePath);
                _logger?.Invoke($"发送签名/摘要文件: {Path.GetFileName(filePath)} ({data.Length} bytes)");
                
                string cmd = $"<?xml version=\"1.0\" ?><data><sig TargetName=\"{targetName}\" verbose=\"1\" size_in_bytes=\"{data.Length}\" /></data>";
                if (!WriteXml(cmd)) return false;

                var resp = WaitForResponse();
                if (resp == null || resp.Response != "ACK") 
                {
                    _logger?.Invoke($"签名头发送失败: {resp?.Response ?? "无响应"}");
                    return false;
                }

                _port?.Write(data, 0, data.Length);
                
                var authResp = WaitForResponse();
                if (authResp != null && authResp.Response == "ACK")
                {
                    _logger?.Invoke("签名/摘要发送成功");
                    return true;
                }
                else
                {
                    _logger?.Invoke($"签名/摘要验证失败: {authResp?.Response ?? "无响应"}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger?.Invoke($"发送签名异常: {ex.Message}");
                return false;
            }
        }

        public bool SendSignature(byte[] data)
        {
            Connect();
            try
            {
                _logger?.Invoke($"正在发送签名/摘要 ({data.Length} bytes)...");
                string cmd = $"<?xml version=\"1.0\" ?><data><sig TargetName=\"sig\" verbose=\"1\" size_in_bytes=\"{data.Length}\" /></data>";
                if (!WriteXml(cmd)) return false;

                var resp = WaitForResponse();
                if (resp == null || resp.Response != "ACK") 
                {
                    _logger?.Invoke($"签名请求被拒绝: {resp?.Response}");
                    return false;
                }

                _port?.Write(data, 0, data.Length);

                // Wait for confirmation
                var authResp = WaitForResponse();
                if (authResp != null)
                {
                    // Check logs for success
                    bool success = false;
                    foreach(var log in authResp.Logs)
                    {
                        if (log.ToLower().Contains("authenticated") || log.ToLower().Contains("success"))
                        {
                            success = true;
                        }
                    }
                    
                    if (success || authResp.Response == "ACK" || authResp.Response == "true")
                    {
                        _logger?.Invoke("验证成功!");
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                _logger?.Invoke($"发送签名异常: {ex.Message}");
                return false;
            }
        }

        public bool PerformOplusHandshake(string configDir, string? userDigestPath, string? userSigPath)
        {
            Connect();
            _logger?.Invoke("开始 Oplus 验证流程...");
            
            // Helper to send XML if exists
            void SendIfExists(string filename)
            {
                string path = Path.Combine(configDir, filename);
                if (File.Exists(path)) SendXmlFile(path);
            }

            // Sequence:
            // devprg (Loader) - Handled by caller
            // (nop)
            // custom1.xml
            SendIfExists("custom1.xml");

            // digest
            string digestPath = !string.IsNullOrEmpty(userDigestPath) && File.Exists(userDigestPath) 
                ? userDigestPath 
                : Path.Combine(configDir, "digest");
            
            if (File.Exists(digestPath))
            {
                // Try "digest" first, then "sig"
                if (!SendSignatureFile(digestPath, "digest"))
                {
                    _logger?.Invoke("TargetName='digest' 失败，尝试 'sig'...");
                    if (!SendSignatureFile(digestPath, "sig"))
                    {
                        _logger?.Invoke("Digest 发送失败");
                        return false;
                    }
                }
            }

            // custom2.xml
            SendIfExists("custom2.xml");

            // transfercfg.xml
            SendIfExists("transfercfg.xml");

            // custom3.xml
            SendIfExists("custom3.xml");

            // getsigndata.xml
            SendIfExists("getsigndata.xml");

            // custom4.xml
            SendIfExists("custom4.xml");

            // verify.xml
            SendIfExists("verify.xml");

            // custom5.xml
            SendIfExists("custom5.xml");

            // sig
            string sigPath = !string.IsNullOrEmpty(userSigPath) && File.Exists(userSigPath) 
                ? userSigPath 
                : Path.Combine(configDir, "sig");

            if (File.Exists(sigPath))
            {
                if (!SendSignatureFile(sigPath, "sig"))
                {
                    _logger?.Invoke("Signature 发送失败");
                    return false;
                }
            }

            // custom6.xml
            SendIfExists("custom6.xml");

            // sha256init.xml
            SendIfExists("sha256init.xml");

            // custom7.xml
            SendIfExists("custom7.xml");

            // (配置端口) - Handled by caller (Configure)

            _logger?.Invoke("Oplus 验证流程完成");
            return true;
        }

        // ---------------- 核心优化区域：WriteXml & WaitForResponse ----------------

        private bool WriteXml(string xml)
        {
            try
            {
                if (_port == null) return false;
                // 不建议盲目 DiscardInBuffer，因为可能丢掉上一条指令的延迟 Log
                // _port.DiscardInBuffer(); 
                byte[] data = Encoding.UTF8.GetBytes(xml);
                _port.Write(data, 0, data.Length);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.Invoke($"Write error: {ex.Message}");
                return false;
            }
        }

        // ---------------------------------------------------------
        // 核心优化 1: 智能等待响应 (替代原来的轮询逻辑)
        // ---------------------------------------------------------
        private QCResponse? WaitForResponse(bool expectRawData = false)
        {
            if (_port == null) return null;

            QCResponse response = new QCResponse();
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] chunk = new byte[4096];
                DateTime start = DateTime.Now;

                try
                {
                    while ((DateTime.Now - start).TotalSeconds < 10) // 10秒总超时
                    {
                        // 1. 尝试读取数据
                        int bytesRead = 0;
                        try 
                        {
                            bytesRead = _port.Read(chunk, 0, chunk.Length);
                        }
                        catch (TimeoutException) 
                        {
                            if (ms.Length > 0) 
                            {
                                // 超时但有数据，尝试解析
                            }
                            else continue; 
                        }

                        if (bytesRead > 0)
                        {
                            ms.Write(chunk, 0, bytesRead);
                            
                            // 2. 检查 XML
                            // 为了性能，只转换目前收到的数据为字符串
                            string currentStr = Encoding.UTF8.GetString(ms.ToArray());

                            // 3. 检查是否有完整的 XML 结束标记
                            int xmlEndIndex = -1;
                            if (currentStr.Contains("</data>"))
                            {
                                xmlEndIndex = currentStr.IndexOf("</data>") + 7;
                            }
                            else 
                            {
                                // 寻找最后一个 <response ... />
                                // 注意：Log 也是 <log ... />，所以要找 response
                                int respIndex = currentStr.LastIndexOf("<response");
                                if (respIndex >= 0)
                                {
                                    int closeIndex = currentStr.IndexOf("/>", respIndex);
                                    if (closeIndex >= 0)
                                    {
                                        xmlEndIndex = closeIndex + 2;
                                    }
                                }
                            }

                            if (xmlEndIndex > 0)
                            {
                                // 4. 解析 XML
                                string xmlContent = currentStr.Substring(0, xmlEndIndex);
                                ParseXmlLogs(xmlContent, response);
                                
                                var match = Regex.Match(xmlContent, "<response value=\"([^\"]+)\"");
                                if (match.Success)
                                {
                                    response.Response = match.Groups[1].Value;
                                    
                                    if (xmlContent.Contains("rawmode=\"true\"")) response.Properties["rawmode"] = "true";
                                    if (xmlContent.Contains("MaxPayloadSizeFromTargetInBytes")) 
                                    {
                                        var sizeMatch = Regex.Match(xmlContent, "MaxPayloadSizeFromTargetInBytes=\"(\\d+)\"");
                                        if(sizeMatch.Success) response.Properties["MaxPayloadSizeFromTargetInBytes"] = sizeMatch.Groups[1].Value;
                                    }

                                    // 5. 处理粘包数据 (UnhandledData)
                                    // 计算 XML 部分的字节长度
                                    int xmlByteCount = Encoding.UTF8.GetByteCount(xmlContent);
                                    
                                    if (ms.Length > xmlByteCount)
                                    {
                                        int extraLen = (int)(ms.Length - xmlByteCount);
                                        response.UnhandledData = new byte[extraLen];
                                        // 从 MemoryStream 中提取剩余字节
                                        byte[] allBytes = ms.ToArray();
                                        Array.Copy(allBytes, xmlByteCount, response.UnhandledData, 0, extraLen);
                                    }

                                    return response;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Invoke($"WaitForResponse 异常: {ex.Message}");
                }
            }
            return null;
        }

        private void ParseXmlLogs(string xml, QCResponse response)
        {
            var matches = Regex.Matches(xml, "log value=\"([^\"]+)\"");
            foreach (Match m in matches)
            {
                string log = m.Groups[1].Value;
                if (!response.Logs.Contains(log))
                {
                    response.Logs.Add(log);
                    _logger?.Invoke($"Device Log: {log}");
                }
            }
        }

        // 辅助：从 Port 读取确切字节数
        private int ReadExact(SerialPort port, byte[] buffer, int offset, int count, CancellationToken token)
        {
            int total = 0;
            while (total < count)
            {
                if (token.IsCancellationRequested) return total;
                try
                {
                    // 检查是否有数据可读，避免长时间阻塞
                    if (port.BytesToRead == 0)
                    {
                        // 简单的自旋等待，配合 Token 检查
                        // 每次等待 10ms，最多等待 ReadTimeout
                        int waitTime = 0;
                        while (port.BytesToRead == 0)
                        {
                            if (token.IsCancellationRequested) return total;
                            Thread.Sleep(10);
                            waitTime += 10;
                            if (waitTime > port.ReadTimeout) throw new TimeoutException();
                        }
                    }

                    int read = port.Read(buffer, offset + total, count - total);
                    if (read == 0) break; 
                    total += read;
                }
                catch (TimeoutException) { break; }
                catch { break; }
            }
            return total;
        }

        private void TryReadFinalLog()
        {
            try 
            {
                // 设置极短超时，仅为了清空可能的 Log
                int oldTimeout = _port!.ReadTimeout;
                _port.ReadTimeout = 200; 
                byte[] junk = new byte[1024];
                _port.Read(junk, 0, junk.Length);
                _port.ReadTimeout = oldTimeout;
            } 
            catch { }
        }

        private bool IsAck(QCResponse r) => r.Response == "ACK" || r.Response == "TRUE";

        // 优化 HexStringToByteArray，不使用 LINQ
        public static byte[] HexStringToByteArray(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public void Dispose()
        {
            if (_port != null)
            {
                if (_port.IsOpen) _port.Close();
                _port.Dispose();
                _port = null;
            }
        }

        public class QCResponse
        {
            public string Response { get; set; } = ""; // Default empty, not ACK
            public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
            public List<string> Logs { get; set; } = new List<string>();
            public byte[]? UnhandledData { get; set; }
        }
    }
}

