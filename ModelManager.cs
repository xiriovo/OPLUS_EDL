using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace OPLUS_EDL
{
    public class ModelConfig
    {
        public string Name { get; set; } = "";
        public string LoaderPath { get; set; } = "";
        public string AuthPath { get; set; } = "";
        public string FolderPath { get; set; } = "";

        public override string ToString() => Name;
    }

    public class ModelManager
    {
        private readonly string _modelsRoot;

        public List<ModelConfig> Models { get; private set; } = new List<ModelConfig>();

        public ModelManager(string baseDir)
        {
            _modelsRoot = Path.Combine(baseDir, "Models");
            if (!Directory.Exists(_modelsRoot))
            {
                try { Directory.CreateDirectory(_modelsRoot); } catch { }
            }
        }

        public void ScanModels()
        {
            Models.Clear();
            if (!Directory.Exists(_modelsRoot)) return;

            var dirs = Directory.GetDirectories(_modelsRoot);
            foreach (var dir in dirs)
            {
                var dirName = Path.GetFileName(dir);
                var config = new ModelConfig
                {
                    Name = dirName,
                    FolderPath = dir
                };

                // 自动查找 Loader (prog_firehose_*.elf)
                var loaders = Directory.GetFiles(dir, "prog_firehose_*.elf");
                if (loaders.Length > 0) config.LoaderPath = loaders[0];
                else 
                {
                    // 尝试找 .elf 或 .mbn
                    var elfs = Directory.GetFiles(dir, "*.elf");
                    if (elfs.Length > 0) config.LoaderPath = elfs[0];
                }

                // 自动查找 Auth (sign/melf)
                var melfs = Directory.GetFiles(dir, "*.melf");
                if (melfs.Length > 0) config.AuthPath = melfs[0];
                else
                {
                    var bins = Directory.GetFiles(dir, "*sign*.bin");
                    if (bins.Length > 0) config.AuthPath = bins[0];
                    else 
                    {
                        // 尝试找任何包含 sign 的文件
                        var signs = Directory.GetFiles(dir, "*sign*");
                        if (signs.Length > 0) config.AuthPath = signs[0];
                    }
                }

                Models.Add(config);
            }
        }
    }
}
