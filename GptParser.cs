using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;

namespace OPLUS_EDL
{
    public class GptParser
    {
        public class GptHeader
        {
            public byte[] Signature { get; set; } // 8 bytes
            public uint Revision { get; set; }
            public uint HeaderSize { get; set; }
            public uint Crc32 { get; set; }
            public uint Reserved { get; set; }
            public ulong CurrentLba { get; set; }
            public ulong BackupLba { get; set; }
            public ulong FirstUsableLba { get; set; }
            public ulong LastUsableLba { get; set; }
            public byte[] DiskGuid { get; set; } // 16 bytes
            public ulong PartEntryStartLba { get; set; }
            public uint NumPartEntries { get; set; }
            public uint PartEntrySize { get; set; }
            public uint Crc32PartEntries { get; set; }

            public GptHeader(byte[] data)
            {
                using (var reader = new BinaryReader(new MemoryStream(data)))
                {
                    Signature = reader.ReadBytes(8);
                    Revision = reader.ReadUInt32();
                    HeaderSize = reader.ReadUInt32();
                    Crc32 = reader.ReadUInt32();
                    Reserved = reader.ReadUInt32();
                    CurrentLba = reader.ReadUInt64();
                    BackupLba = reader.ReadUInt64();
                    FirstUsableLba = reader.ReadUInt64();
                    LastUsableLba = reader.ReadUInt64();
                    DiskGuid = reader.ReadBytes(16);
                    PartEntryStartLba = reader.ReadUInt64();
                    NumPartEntries = reader.ReadUInt32();
                    PartEntrySize = reader.ReadUInt32();
                    Crc32PartEntries = reader.ReadUInt32();
                }
            }
        }

        public class GptPartition
        {
            public byte[] Type { get; set; } // 16 bytes
            public byte[] Unique { get; set; } // 16 bytes
            public ulong FirstLba { get; set; }
            public ulong LastLba { get; set; }
            public ulong Flags { get; set; }
            public string Name { get; set; } // 72 bytes (UTF-16LE)

            public string TypeGuid => FormatGuid(Type);
            public string UniqueGuid => FormatGuid(Unique);

            public GptPartition(byte[] data)
            {
                using (var reader = new BinaryReader(new MemoryStream(data)))
                {
                    Type = reader.ReadBytes(16);
                    Unique = reader.ReadBytes(16);
                    FirstLba = reader.ReadUInt64();
                    LastLba = reader.ReadUInt64();
                    Flags = reader.ReadUInt64();
                    byte[] nameBytes = reader.ReadBytes(72);
                    Name = Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');
                }
            }

            private string FormatGuid(byte[] guid)
            {
                // GPT GUIDs are mixed endian: first 3 parts are LE, last 2 are BE (byte array)
                // But in C# Guid structure handles this if we pass byte array directly?
                // Actually standard GUID string representation: 
                // Data1 (4 bytes LE) - Data2 (2 bytes LE) - Data3 (2 bytes LE) - Data4 (2 bytes BE) - Data5 (6 bytes BE)
                // The raw bytes in GPT are Little Endian for the first 3 fields.
                // Let's just use the Guid class constructor which expects the bytes in memory order
                // If the bytes on disk are: 00 11 22 33 ...
                // Guid(bytes) will interpret them correctly if they match .NET's internal storage.
                // .NET Guid: int, short, short, byte, byte, byte, byte, byte, byte, byte, byte
                // This matches GPT format exactly (Little Endian for first 3, then bytes).
                return new Guid(guid).ToString();
            }
        }

        public GptHeader? Header { get; private set; }
        public List<GptPartition> Partitions { get; private set; } = new List<GptPartition>();
        public int SectorSize { get; private set; }

        public bool Parse(byte[] gptData, int sectorSize = 512)
        {
            SectorSize = sectorSize;
            if (gptData.Length < sectorSize + 0x5C) return false;

            // Header starts at LBA 1 (so offset = sectorSize)
            byte[] headerBytes = new byte[0x5C]; // 92 bytes
            Array.Copy(gptData, sectorSize, headerBytes, 0, 0x5C);
            
            Header = new GptHeader(headerBytes);

            string sig = Encoding.ASCII.GetString(Header.Signature);
            if (sig != "EFI PART") return false;

            long tableOffset;
            if (Header.PartEntryStartLba == 2)
            {
                // Standard GPT
                tableOffset = (long)Header.PartEntryStartLba * sectorSize;
            }
            else if (Header.PartEntryStartLba > 2)
            {
                 // Some devices might have it elsewhere, trust the LBA
                 tableOffset = (long)Header.PartEntryStartLba * sectorSize;
            }
            else 
            {
                // Fallback or error?
                tableOffset = sectorSize * 2;
            }

            // Check if we have enough data
            long requiredSize = tableOffset + (Header.NumPartEntries * Header.PartEntrySize);
            if (gptData.Length < requiredSize) return false;

            Partitions.Clear();
            for (int i = 0; i < Header.NumPartEntries; i++)
            {
                long entryOffset = tableOffset + (i * Header.PartEntrySize);
                byte[] entryBytes = new byte[Header.PartEntrySize];
                Array.Copy(gptData, entryOffset, entryBytes, 0, Header.PartEntrySize);

                // Check if empty (Type GUID is 0)
                bool isEmpty = true;
                for(int j=0; j<16; j++) if(entryBytes[j] != 0) { isEmpty = false; break; }
                if (isEmpty) continue;

                var part = new GptPartition(entryBytes);
                Partitions.Add(part);
            }

            return true;
        }

        public string PrintTable()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("GPT Table:");
            sb.AppendLine("-------------");
            foreach (var p in Partitions)
            {
                sb.AppendLine($"{p.Name,-20} Start: 0x{p.FirstLba * (ulong)SectorSize:X}, Len: 0x{(p.LastLba - p.FirstLba + 1) * (ulong)SectorSize:X}, Type: {p.TypeGuid}");
            }
            return sb.ToString();
        }
    }
}

