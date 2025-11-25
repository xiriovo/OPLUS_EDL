using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace OPLUS_EDL
{
    public class GptParser
    {
        public class PartitionEntry
        {
            public string Name { get; set; } = "";
            public ulong FirstLba { get; set; }
            public ulong LastLba { get; set; }
        }

        public List<PartitionEntry> Partitions { get; private set; } = new List<PartitionEntry>();

        public bool Parse(byte[] data, int sectorSize)
        {
            Partitions.Clear();
            if (data == null || data.Length < sectorSize * 2) return false;

            try
            {
                using (var ms = new MemoryStream(data))
                using (var reader = new BinaryReader(ms))
                {
                    // 1. 跳过 MBR (LBA 0)
                    ms.Seek(sectorSize, SeekOrigin.Begin);

                    // 2. 读取 GPT Header (LBA 1)
                    byte[] signature = reader.ReadBytes(8);
                    string sigStr = Encoding.ASCII.GetString(signature);
                    if (sigStr != "EFI PART") return false;

                    ms.Seek(sectorSize + 80, SeekOrigin.Begin); // 跳到 Partition Entries Start LBA 偏移
                    ulong partEntryStartLba = reader.ReadUInt64();
                    uint numPartEntries = reader.ReadUInt32();
                    uint partEntrySize = reader.ReadUInt32();

                    // 3. 跳转到分区表项
                    long entryOffset = (long)(partEntryStartLba * (ulong)sectorSize);
                    if (entryOffset >= data.Length) return false; // 数据不够

                    ms.Seek(entryOffset, SeekOrigin.Begin);

                    for (int i = 0; i < numPartEntries; i++)
                    {
                        if (ms.Position + partEntrySize > data.Length) break;

                        long entryStart = ms.Position;
                        
                        // 读取 Type GUID (16 bytes)
                        byte[] typeGuid = reader.ReadBytes(16);
                        bool isEmpty = true;
                        foreach (var b in typeGuid) if (b != 0) isEmpty = false;
                        
                        if (!isEmpty)
                        {
                            ms.Seek(entryStart + 32, SeekOrigin.Begin); // First LBA
                            ulong firstLba = reader.ReadUInt64();
                            ulong lastLba = reader.ReadUInt64();
                            
                            ms.Seek(entryStart + 56, SeekOrigin.Begin); // Name
                            byte[] nameBytes = reader.ReadBytes(72);
                            string name = Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');

                            Partitions.Add(new PartitionEntry
                            {
                                Name = name,
                                FirstLba = firstLba,
                                LastLba = lastLba
                            });
                        }

                        ms.Seek(entryStart + partEntrySize, SeekOrigin.Begin);
                    }
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

