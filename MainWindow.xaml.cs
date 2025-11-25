using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Xml.Linq;
using System.Management;
using System.Collections.Concurrent;

namespace OPLUS_EDL
{
    public partial class MainWindow : Window
    {
        private string _baseDir = "";
        private string _binDir = "";
        private string _resDir = "";
        private string _edlDir = ""; // Path to edl-3.52.1
        
        // Detected device info
        private string _detectedMemoryName = "ufs"; // Default to UFS
        private int _detectedSectorSize = 4096;     // Default to 4096

        // Log buffering
        private readonly ConcurrentQueue<string> _logQueue = new ConcurrentQueue<string>();
        private readonly DispatcherTimer _logTimer;
        private bool _isRefreshing = false;

        public ObservableCollection<PartitionInfo> Partitions { get; set; } = new ObservableCollection<PartitionInfo>();

        private DiagClient _diagClient;
        private StreamingClient _streamingClient;
        private ModelManager _modelManager;

        public MainWindow()
        {
            try
            {
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                InitializeComponent();
                
                // Setup Log Timer
                _logTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(100)
                };
                _logTimer.Tick += ProcessLogQueue;
                _logTimer.Start();

                InitializePaths();
                
                // 初始化机型管理器
                _modelManager = new ModelManager(_baseDir);
                RefreshModels();

                // Fire and forget initial refresh without countdown
                _ = RefreshPortsAsync(false);
                
                PartList.ItemsSource = Partitions;
                
                // Do not load default paths or main.xml on startup as requested
                // Clear fields just in case
                LoaderTextBox.Text = "";
                DigestTextBox.Text = "";
                SignatureTextBox.Text = "";
                FlashPackText.Text = "";
                PatchText.Text = "";

                CheckDependencies();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"启动失败: {ex.Message}\n\n{ex.StackTrace}", "错误", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                System.Windows.Application.Current.Shutdown();
            }
        }

        private void RefreshModels()
        {
            _modelManager.ScanModels();
            ModelComboBox.ItemsSource = null;
            ModelComboBox.ItemsSource = _modelManager.Models;
            if (_modelManager.Models.Count > 0)
            {
                ModelComboBox.SelectedIndex = 0;
            }
        }

        private void RefreshModelsBtn_Click(object sender, RoutedEventArgs e)
        {
            RefreshModels();
        }

        private void ModelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ModelComboBox.SelectedItem is ModelConfig config)
            {
                if (!string.IsNullOrEmpty(config.LoaderPath)) LoaderTextBox.Text = config.LoaderPath;
                if (!string.IsNullOrEmpty(config.AuthPath)) SignatureTextBox.Text = config.AuthPath;
                Log($"已加载机型配置: {config.Name}");
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            KillRelatedProcesses();
            CleanupTempFiles();
        }

        private void CleanupTempFiles()
        {
            try
            {
                string[] files = { "cmd.xml", "tmp.bin", "port_trace.txt", "gpt_dump.bin", "temp_action.xml", "erase.xml" };
                foreach (var f in files)
                {
                    string path = Path.Combine(_binDir, f);
                    if (File.Exists(path)) File.Delete(path);
                }
            }
            catch { }
        }

        private void KillRelatedProcesses()
        {
            string[] processNames = { "lsusb" };
            foreach (string name in processNames)
            {
                try
                {
                    Process[] procs = Process.GetProcessesByName(name);
                    foreach (Process p in procs)
                    {
                        try
                        {
                            if (!p.HasExited)
                            {
                                p.Kill();
                                p.WaitForExit(1000);
                            }
                        }
                        catch { /* Ignore permission errors etc */ }
                    }
                }
                catch { /* Ignore */ }
            }
        }

        private void CheckDependencies()
        {
            List<string> missing = new List<string>();
            
            // Check bin root tools
            // if (!File.Exists(Path.Combine(_binDir, "cmd.xml"))) missing.Add("bin\\cmd.xml"); // Not strictly needed for native client

            // Native implementation does not require external EXEs
            
            if (missing.Count > 0)
            {
                string msg = "缺少关键依赖文件:\n" + string.Join("\n", missing) + "\n\n请确保工具完整解压且文件结构正确。";
                System.Windows.MessageBox.Show(msg, "依赖缺失", MessageBoxButton.OK, MessageBoxImage.Error);
                Log("错误: 缺失依赖: " + string.Join(", ", missing));
                
                // Disable controls
                PartList.IsEnabled = false;
                ReadGPTBtn.IsEnabled = false;
                ReadPartBtn.IsEnabled = false;
                WritePartBtn.IsEnabled = false;
                ErasePartBtn.IsEnabled = false;
                ResetBtn.IsEnabled = false;
                DeviceInfoBtn.IsEnabled = false;
                SwitchSlotBtn.IsEnabled = false;
                WipeDataBtn.IsEnabled = false;
                SendLoaderCB.IsEnabled = false;
            }
            else
            {
                Log("依赖检查通过。");
            }
        }

        private void InitializePaths()
        {
            string current = AppDomain.CurrentDomain.BaseDirectory;
            
            // Potential locations for resources
            string[] candidates = new[]
            {
                Path.Combine(current, "bin"),
                Path.Combine(current, "bin", "bin"), // Double bin structure
                Path.Combine(current, "..", "..", "..", "bin"), // Project root bin (if running from bin/Debug/net...)
                Path.Combine(current, "OPLUS_EDL_Tool_2.0", "bin")
            };

            foreach (var cand in candidates)
            {
                if (Directory.Exists(cand))
                {
                    _binDir = Path.GetFullPath(cand);
                    _baseDir = Directory.GetParent(_binDir)?.FullName ?? current;
                    _resDir = Path.Combine(_baseDir, "res");
                    Log($"找到工具资源: {_binDir}");
                    return;
                }
            }
            
            // Fallback search upwards for OPLUS_EDL_Tool_2.0 folder
            DirectoryInfo? di = new DirectoryInfo(current);
            while (di != null)
            {
                string check = Path.Combine(di.FullName, "OPLUS_EDL_Tool_2.0", "bin");
                if (Directory.Exists(check))
                {
                    _binDir = check;
                    _baseDir = Path.Combine(di.FullName, "OPLUS_EDL_Tool_2.0");
                    _resDir = Path.Combine(_baseDir, "res");
                    Log($"找到工具资源: {_binDir}");
                    return;
                }
                // Also check if the current dir IS the tool root (contains bin/fh_loader.exe)
                string checkRoot = Path.Combine(di.FullName, "bin");
                if (Directory.Exists(checkRoot))
                {
                    _binDir = checkRoot;
                    _baseDir = di.FullName;
                    _resDir = Path.Combine(_baseDir, "res");
                    Log($"找到工具资源: {_binDir}");
                    return;
                }

                di = di.Parent;
            }

            // Default fallback
            _baseDir = current;
            _binDir = Path.Combine(current, "bin");
            _resDir = Path.Combine(current, "res");
            
            // Search for edl-3.52.1
            string[] edlCandidates = new[]
            {
                Path.Combine(_baseDir, "edl-3.52.1"),
                Path.Combine(_baseDir, "..", "edl-3.52.1"),
                Path.Combine(_baseDir, "..", "..", "edl-3.52.1"),
                Path.Combine(current, "..", "..", "..", "..", "edl-3.52.1")
            };
            
            foreach (var cand in edlCandidates)
            {
                if (Directory.Exists(cand) && File.Exists(Path.Combine(cand, "edl.py")))
                {
                    _edlDir = Path.GetFullPath(cand);
                    Log($"找到 EDL 工具: {_edlDir}");
                    break;
                }
            }

            if (string.IsNullOrEmpty(_edlDir))
            {
                // Log("警告: 未找到 'edl-3.52.1' 文件夹。部分功能可能不可用。");
            }
        }

        private void Log(string message)
        {
            _logQueue.Enqueue($"[{DateTime.Now:HH:mm:ss}] {message}");
        }

        private void OnNativeLog(string message)
        {
            if (!string.IsNullOrEmpty(message))
            {
                _logQueue.Enqueue(message.TrimEnd());
            }
        }

        private void ProcessLogQueue(object? sender, EventArgs e)
        {
            if (_logQueue.IsEmpty) return;

            StringBuilder sb = new StringBuilder();
            while (_logQueue.TryDequeue(out string? msg))
            {
                sb.AppendLine(msg);
            }

            if (sb.Length > 0)
            {
                LogText.AppendText(sb.ToString());
                LogText.ScrollToEnd();
            }
        }

        private async void RefreshPortsButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isRefreshing) return;
            await RefreshPortsAsync(true);
        }

        private async Task RefreshPortsAsync(bool useCountdown = false)
        {
            if (_isRefreshing && useCountdown) return;
            
            _isRefreshing = true;
            int timeoutSeconds = useCountdown ? 60 : 0;
            bool foundEdl = false;

            if (useCountdown)
            {
                RefreshPortsButton.IsEnabled = false;
            }

            try
            {
                do
                {
                    await Dispatcher.InvokeAsync(() => PortComboBox.Items.Clear());
                    foundEdl = false;

                    // 1. Use WMI to find Qualcomm 9008 ports (Pure C#)
                    try
                    {
                        await Task.Run(() =>
                        {
                            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE Caption LIKE '%(COM%)'"))
                            {
                                foreach (var device in searcher.Get())
                                {
                                    string name = device["Caption"]?.ToString() ?? "";
                                    // Check for Qualcomm and 9008
                                    if (name.IndexOf("Qualcomm", StringComparison.OrdinalIgnoreCase) >= 0 && 
                                        name.IndexOf("9008", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        // Extract COM port
                                        var match = System.Text.RegularExpressions.Regex.Match(name, @"COM(\d+)");
                                        if (match.Success)
                                        {
                                            string portName = match.Value;
                                            Dispatcher.Invoke(() => 
                                            {
                                                if (!PortComboBox.Items.Contains(portName))
                                                {
                                                    PortComboBox.Items.Add(portName);
                                                    Log($"检测到 EDL 端口: {portName} ({name})");
                                                }
                                            });
                                            foundEdl = true;
                                        }
                                    }
                                }
                            }
                        });
                    }
                    catch (Exception ex)
                    {
                        Log($"警告: WMI 检测失败: {ex.Message}");
                    }

                    // 2. Fallback/Supplement with standard SerialPort detection
                    string[] allPorts = SerialPort.GetPortNames();
                    await Dispatcher.InvokeAsync(() =>
                    {
                        foreach (string port in allPorts)
                        {
                            if (!PortComboBox.Items.Contains(port))
                            {
                                PortComboBox.Items.Add(port);
                            }
                        }

                        if (PortComboBox.Items.Count > 0)
                            PortComboBox.SelectedIndex = 0;
                    });

                    if (foundEdl)
                    {
                        Log($"端口刷新完成。发现 EDL 设备。");
                        break;
                    }
                    else if (timeoutSeconds > 0)
                    {
                        await Dispatcher.InvokeAsync(() => RefreshPortsButton.Content = $"等待设备 ({timeoutSeconds})");
                        await Task.Delay(1000);
                        timeoutSeconds--;
                    }
                    else
                    {
                        Log($"端口刷新完成。发现 {allPorts.Length} 个串口。");
                    }

                } while (timeoutSeconds > 0);
            }
            finally
            {
                _isRefreshing = false;
                await Dispatcher.InvokeAsync(() => 
                {
                    RefreshPortsButton.IsEnabled = true;
                    RefreshPortsButton.Content = "刷新设备";
                });
            }
        }

        private void FlashPackBroswerBtn_Click(object sender, RoutedEventArgs e)
        {
            // Use a stricter filter by default to hide files like rawprogram0_BLANK_GPT.xml in the dialog
            // rawprogram?.xml matches rawprogram0.xml, rawprogram1.xml etc.
            // rawprogram??.xml matches rawprogram10.xml etc.
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog { 
                Filter = "Standard RawProgram (rawprogram0-9)|rawprogram?.xml;rawprogram??.xml|All RawProgram (*rawprogram*.xml)|*rawprogram*.xml|XML Files (*.xml)|*.xml|All files (*.*)|*.*", 
                Multiselect = true 
            };
            
            if (dlg.ShowDialog() == true)
            {
                // 1. First pass: Filter out explicitly unwanted files (BLANK_GPT, WIPE_PARTITIONS, etc.)
                var filteredFiles = new System.Collections.Generic.List<string>();
                foreach (var f in dlg.FileNames)
                {
                    string fname = System.IO.Path.GetFileName(f);
                    if (fname.IndexOf("BLANK_GPT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fname.IndexOf("WIPE_PARTITIONS", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        fname.IndexOf("wipe_rawprogram", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        continue; // Skip unwanted files
                    }
                    filteredFiles.Add(f);
                }

                // 2. Second pass: If any of the remaining files look like "rawprogram", prefer them.
                var rawProgramsOnly = new System.Collections.Generic.List<string>();
                foreach (var f in filteredFiles)
                {
                    if (System.IO.Path.GetFileName(f).IndexOf("rawprogram", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        rawProgramsOnly.Add(f);
                    }
                }

                // If we found valid rawprogram files, use ONLY them. 
                // Otherwise, fall back to the filtered list (user might have selected a custom named XML).
                var finalSelection = rawProgramsOnly.Count > 0 ? rawProgramsOnly : filteredFiles;

                FlashPackText.Text = string.Join(",", finalSelection);
                LoadPartitionsFromXml(finalSelection.ToArray());

                // Auto-detect patch files
                // Clear previous patch selection to ensure consistency with the new rawprogram selection
                PatchText.Text = string.Empty;
                var patchFiles = new System.Collections.Generic.List<string>();
                foreach (var file in finalSelection)
                {
                    string filename = System.IO.Path.GetFileName(file);
                    // Case-insensitive check for "rawprogram"
                    if (filename.IndexOf("rawprogram", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // Replace "rawprogram" with "patch" (case-insensitive)
                        string patchFilename = System.Text.RegularExpressions.Regex.Replace(filename, "rawprogram", "patch", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        string? dir = System.IO.Path.GetDirectoryName(file);
                        if (dir != null)
                        {
                            string patchPath = System.IO.Path.Combine(dir, patchFilename);
                            Log($"[自动补丁] 检查: {patchFilename}");

                            if (System.IO.File.Exists(patchPath))
                            {
                                patchFiles.Add(patchPath);
                                Log($"[自动补丁] 找到: {patchFilename}");
                            }
                            else
                            {
                                Log($"[自动补丁] 未找到: {patchFilename}");
                            }
                        }
                    }
                }

                if (patchFiles.Count > 0)
                {
                    PatchText.Text = string.Join(",", patchFiles);
                    Log($"自动检测到 {patchFiles.Count} 个补丁文件。");
                }
            }
        }

        private void PatchBrowserBtn_Click(object sender, RoutedEventArgs e)
        {
            // Use strict filter to hide unwanted patch files (e.g. patch0_noauth.xml)
            // patch.xml, patch0.xml, patch10.xml
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog { 
                Filter = "Standard Patch (patch0-9)|patch.xml;patch?.xml;patch??.xml|All Patch (*patch*.xml)|*patch*.xml|XML Files (*.xml)|*.xml|All files (*.*)|*.*", 
                Multiselect = true 
            };

            if (dlg.ShowDialog() == true)
            {
                var validPatches = new System.Collections.Generic.List<string>();
                foreach (var f in dlg.FileNames)
                {
                    string fname = System.IO.Path.GetFileName(f);
                    // Strict regex: ^patch\d*\.xml$ (matches patch.xml, patch0.xml, patch12.xml)
                    // This excludes patch0_noauth.xml, patch_special.xml, etc.
                    if (System.Text.RegularExpressions.Regex.IsMatch(fname, @"^patch\d*\.xml$", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                    {
                        validPatches.Add(f);
                    }
                }

                // If strict filter found nothing, fall back to user selection (assuming intentional override)
                if (validPatches.Count == 0)
                {
                    validPatches.AddRange(dlg.FileNames);
                }

                PatchText.Text = string.Join(",", validPatches);
            }
        }

        private void DigestBrowserBtn_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog { Filter = "ELF Files (*.elf)|*.elf|All files (*.*)|*.*" };
            if (dlg.ShowDialog() == true) DigestTextBox.Text = dlg.FileName;
        }

        private void SignatureBrowserBtn_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog { Filter = "BIN Files (*.bin)|*.bin|All files (*.*)|*.*" };
            if (dlg.ShowDialog() == true) SignatureTextBox.Text = dlg.FileName;
        }

        private void LoadPartitionsFromXml(string[] xmlPaths)
        {
            try
            {
                Partitions.Clear();
                foreach (string xmlPath in xmlPaths)
                {
                    if (!File.Exists(xmlPath)) continue;
                    XDocument doc = XDocument.Load(xmlPath);
                    var programs = doc.Descendants("program");
                    foreach (var prog in programs)
                    {
                        try
                        {
                            string filename = prog.Attribute("filename")?.Value ?? "";
                            if (string.IsNullOrWhiteSpace(filename)) continue;

                            Partitions.Add(new PartitionInfo
                            {
                                IsSelected = true,
                                Label = prog.Attribute("label")?.Value ?? "unknown",
                                Lun = int.Parse(prog.Attribute("physical_partition_number")?.Value ?? "0"),
                                StartSector = prog.Attribute("start_sector")?.Value ?? "0",
                                Size = prog.Attribute("size_in_KB")?.Value ?? "0", // Or num_partition_sectors
                                Filename = filename,
                                SectorSize = prog.Attribute("SECTOR_SIZE_IN_BYTES")?.Value ?? "4096",
                                NumSectors = prog.Attribute("num_partition_sectors")?.Value ?? ""
                            });
                        }
                        catch (Exception ex)
                        {
                            string label = prog.Attribute("label")?.Value ?? "unknown";
                            Log($"解析分区 '{label}' 错误: {ex.Message}");
                        }
                    }
                }
                Log($"从 {xmlPaths.Length} 个 XML 文件加载了 {Partitions.Count} 个分区。");
            }
            catch (Exception ex)
            {
                Log($"解析 XML 错误: {ex.Message}");
            }
        }

        private void LoaderBrowserBtn_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog { Filter = "Programmer (*.melf;*.elf;*.bin)|*.melf;*.elf;*.bin|All files (*.*)|*.*" };
            if (dlg.ShowDialog() == true) LoaderTextBox.Text = dlg.FileName;
        }

        private void SelectCB_CheckedChanged(object sender, RoutedEventArgs e)
        {
            bool isChecked = SelectCB.IsChecked == true;
            foreach (var part in Partitions)
            {
                part.IsSelected = isChecked;
            }
        }

        private void HeaderSelectAll_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.CheckBox cb)
            {
                bool isChecked = cb.IsChecked == true;
                foreach (var part in Partitions)
                {
                    part.IsSelected = isChecked;
                }
                // Sync the other checkbox
                if (SelectCB != null) SelectCB.IsChecked = isChecked;
            }
        }

        private void PartList_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (sender is System.Windows.Controls.ListView list && list.SelectedItem is PartitionInfo item)
            {
                Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog 
                { 
                    Filter = "Image Files (*.img;*.bin;*.elf)|*.img;*.bin;*.elf|All files (*.*)|*.*",
                    Title = $"选择要刷入 {item.Label} 的文件"
                };
                
                if (dlg.ShowDialog() == true)
                {
                    item.Filename = dlg.FileName;
                    item.IsSelected = true;
                    Log($"已关联文件到 {item.Label}: {System.IO.Path.GetFileName(dlg.FileName)}");
                }
            }
        }

        private Process? _currentProcess;
        private CancellationTokenSource? _cts;

        private void StopBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_cts != null)
            {
                _cts.Cancel();
                Log("已请求停止操作...");
            }

            if (_currentProcess != null && !_currentProcess.HasExited)
            {
                try
                {
                    _currentProcess.Kill();
                    Log("已请求停止进程。");
                }
                catch (Exception ex)
                {
                    Log($"停止进程失败: {ex.Message}");
                }
            }
        }

        private void SetUIBusy(bool isBusy)
        {
            Dispatcher.Invoke(() =>
            {
                // Disable/Enable main action buttons
                ReadGPTBtn.IsEnabled = !isBusy;
                ReadPartBtn.IsEnabled = !isBusy;
                WritePartBtn.IsEnabled = !isBusy;
                ErasePartBtn.IsEnabled = !isBusy;
                ResetBtn.IsEnabled = !isBusy;
                DeviceInfoBtn.IsEnabled = !isBusy;
                SwitchSlotBtn.IsEnabled = !isBusy;
                WipeDataBtn.IsEnabled = !isBusy;
                
                // Configuration buttons
                FlashPackBroswerBtn.IsEnabled = !isBusy;
                PatchBrowserBtn.IsEnabled = !isBusy;
                LoaderBrowserBtn.IsEnabled = !isBusy;
                DigestBrowserBtn.IsEnabled = !isBusy;
                SignatureBrowserBtn.IsEnabled = !isBusy;
                
                // Checkboxes
                SendLoaderCB.IsEnabled = !isBusy;
                UseOfficialLineCB.IsEnabled = !isBusy;
                SelectCB.IsEnabled = !isBusy;
                SkipSafeCB.IsEnabled = !isBusy;
                SkipDataCB.IsEnabled = !isBusy;
                
                // Port controls
                RefreshPortsButton.IsEnabled = !isBusy;
                PortComboBox.IsEnabled = !isBusy;

                // Stop button is enabled only when busy
                StopBtn.IsEnabled = isBusy;

                // Ensure PartList is always enabled to allow scrolling/selection even during operations if needed
                PartList.IsEnabled = true; 
            });
        }

        private async void ReadGPTBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port)) return;

                // 1. Send Loader if checked
                if (SendLoaderCB.IsChecked == true)
                {
                    bool success = await SendLoader(port, token);
                    if (!success) return;
                }

                await Task.Run(() =>
                {
                    try
                    {
                        if (token.IsCancellationRequested) return;

                        Log("正在读取 GPT 分区表...");
                        
                        using (var client = new FirehoseClient(port, Log))
                        {
                            var partitions = ReadGpt(client, "ufs", token); // Default try UFS then eMMC inside ReadGpt
                            
                            Dispatcher.Invoke(() =>
                            {
                                Partitions.Clear();
                                foreach (var p in partitions) Partitions.Add(p);
                                Log($"成功加载 {Partitions.Count} 个分区。");
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"读取/解析 GPT 错误: {ex.Message}");
                    }
                });
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        // ---------------------------------------------------------
        // 优化 MainWindow.xaml.cs (GPT 读取逻辑)
        // ---------------------------------------------------------
        private List<PartitionInfo> ReadGpt(FirehoseClient client, string defaultMemoryName, CancellationToken token = default)
        {
            Log("正在读取 GPT 分区表...");
            
            int sectorSize = 4096; // 默认尝试 4096 (UFS)
            if (_detectedSectorSize > 0) sectorSize = _detectedSectorSize;

            List<PartitionInfo> allPartitions = new List<PartitionInfo>();

            // 内部函数：读取指定 LUN 的 GPT
            List<PartitionInfo>? ReadLunGpt(int lun, int currentSectorSize)
            {
                if (token.IsCancellationRequested) return null;
                try 
                {
                    // 读取 GPT 头和分区表 (通常前 34 个扇区足够涵盖大多数情况，UFS 甚至更少)
                    // 为了保险，读取 34 个扇区 (34 * 4096 = 136KB)
                    int sectorsToRead = 34; 
                    
                    Log($"LUN {lun}: Reading {sectorsToRead} sectors...");
                    byte[]? buffer = client.ReadData(lun, 0, sectorsToRead, currentSectorSize, token, label: "gpt", filename: "gpt_lun" + lun + ".bin");
                    
                    if (buffer == null) return null;

                    var parser = new GptParser();
                    if (parser.Parse(buffer, currentSectorSize))
                    {
                        return parser.Partitions.Select(p => new PartitionInfo 
                        {
                            Label = p.Name,
                            Lun = lun,
                            StartSector = p.FirstLba.ToString(),
                            NumSectors = (p.LastLba - p.FirstLba + 1).ToString(),
                            SectorSize = currentSectorSize.ToString(),
                            Size = FormatSize((long)((p.LastLba - p.FirstLba + 1) * (ulong)currentSectorSize)),
                            SizeInKB = (long)((p.LastLba - p.FirstLba + 1) * (ulong)currentSectorSize / 1024),
                            IsSelected = true
                        }).ToList();
                    }
                }
                catch (Exception ex)
                {
                    Log($"LUN {lun} Read Error: {ex.Message}");
                }
                return null;
            }

            // 1. 尝试读取 LUN 0
            var lun0Parts = ReadLunGpt(0, sectorSize);
            
            // 如果失败且默认是 4096，尝试回退到 512
            if (lun0Parts == null && sectorSize == 4096)
            {
                Log("LUN 0 (4K) 读取失败，尝试 512 字节扇区...");
                lun0Parts = ReadLunGpt(0, 512);
                if (lun0Parts != null) sectorSize = 512;
            }

            if (lun0Parts != null)
            {
                allPartitions.AddRange(lun0Parts);
                Log($"LUN 0: 成功加载 {lun0Parts.Count} 个分区");

                // 2. 如果是 UFS，尝试读取 LUN 1-5
                // 通常 UFS 设备有 LUN 0-5 (甚至更多，但 0-5 是标准的)
                // 如果 LUN 0 读取成功，我们假设它是 UFS (或者 eMMC 只有一个 LUN)
                // 我们可以尝试读取 LUN 1，如果成功则继续，失败则停止
                for (int lun = 1; lun <= 5; lun++)
                {
                    var lunParts = ReadLunGpt(lun, sectorSize);
                    if (lunParts != null && lunParts.Count > 0)
                    {
                        allPartitions.AddRange(lunParts);
                        Log($"LUN {lun}: 成功加载 {lunParts.Count} 个分区");
                    }
                    else
                    {
                        // 如果 LUN 1 读取失败，可能不是 UFS 或者只有 LUN 0
                        if (lun == 1) break; 
                    }
                }
            }
            else
            {
                Log("无法读取分区表。请检查连接或 Firehose 程序员是否匹配。");
            }

            return allPartitions;
        }

        private string FormatSize(long bytes)
        {
            if (bytes >= 1024 * 1024 * 1024) return $"{(double)bytes / (1024 * 1024 * 1024):F2} GB";
            if (bytes >= 1024 * 1024) return $"{(double)bytes / (1024 * 1024):F2} MB";
            if (bytes >= 1024) return $"{(double)bytes / 1024:F2} KB";
            return $"{bytes} B";
        }

        private async void ReadPartBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            try
            {
                // Use OpenFileDialog with ValidateNames = false to simulate folder selection
                // Or just use System.Windows.Forms.FolderBrowserDialog
                using (var dialog = new System.Windows.Forms.FolderBrowserDialog())
                {
                    dialog.Description = "选择保存分区文件的文件夹";
                    dialog.UseDescriptionForTitle = true;
                    
                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        string dir = dialog.SelectedPath;
                        await PerformOperation("Read", dir);
                    }
                }
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        private async void WritePartBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            try
            {
                await PerformOperation("Write");
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        private async void ErasePartBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            try
            {
                await PerformOperation("Erase");
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        // ---------------------------------------------------------
        // 在 MainWindow 类中，替换原有的 PerformOperation 方法
        // ---------------------------------------------------------

        private async Task PerformOperation(string operation, string? customOutputDir = null)
        {
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            // 初始化 UI
            UpdateProgress(0, "准备就绪");
            string? port = await WaitForPortAsync();
            if (string.IsNullOrEmpty(port)) return;

            var selectedParts = Partitions.Where(p => p.IsSelected).ToList();
            if (selectedParts.Count == 0) { Log("未选择分区。"); return; }

            // 1. 发送引导 (Send Loader)
            if (SendLoaderCB.IsChecked == true)
            {
                UpdateProgress(0, "正在握手 (Sahara)...");
                bool success = await SendLoader(port, token);
                if (!success) return;
            }

            await Task.Run(() =>
            {
                try
                {
                    using (var client = new FirehoseClient(port, Log))
                    {
                        if (token.IsCancellationRequested) return;

                        Dispatcher.Invoke(() => SpeedText.Text = "正在配置 Firehose...");
                        RunConfigure(client);

                        // 如果是读取，刷新分区表以获取精确地址
                        List<PartitionInfo>? freshPartitions = null;
                        if (operation == "Read" || operation == "Erase")
                        {
                            freshPartitions = ReadGpt(client, "ufs", token);
                        }

                        // -------------------------------------------------
                        // 进度条核心优化逻辑
                        // -------------------------------------------------
                        
                        // 1. 计算总工作量 (字节)
                        long totalBytesJob = 0;
                        foreach (var part in selectedParts)
                        {
                            // 尝试获取精确大小
                            long size = part.SizeInKB * 1024;
                            
                            // 如果是写操作，以文件大小为准
                            if (operation == "Write" && File.Exists(part.Filename))
                            {
                                size = new FileInfo(part.Filename).Length;
                            }
                            // 如果是读/擦除，且有新分区表，用新分区表的大小
                            else if (freshPartitions != null)
                            {
                                var fresh = freshPartitions.FirstOrDefault(p => p.Label == part.Label && p.Lun == part.Lun);
                                if (fresh != null) size = fresh.SizeInKB * 1024;
                            }
                            
                            totalBytesJob += size;
                        }

                        // 2. 定义进度状态变量
                        long bytesProcessedGlobal = 0; // 已完成文件的总字节
                        long bytesProcessedCurrentFile = 0; // 当前文件已处理字节
                        
                        // 速度计算相关
                        DateTime startTime = DateTime.Now;
                        DateTime lastUpdateTime = DateTime.Now;
                        long lastBytesSample = 0;
                        
                        // 定义一个高频调用的本地函数，但在内部限流刷新 UI
                        void ReportProgress(long currentFileBytes, long totalFileBytes)
                        {
                            bytesProcessedCurrentFile = currentFileBytes;
                            long totalProcessed = bytesProcessedGlobal + bytesProcessedCurrentFile;

                            DateTime now = DateTime.Now;
                            double timeDelta = (now - lastUpdateTime).TotalSeconds;

                            // 限流：每 50ms 刷新一次 UI，或者是最后一次更新
                            if (timeDelta >= 0.05 || totalProcessed == totalBytesJob)
                            {
                                // 计算百分比
                                double percent = totalBytesJob > 0 ? (double)totalProcessed / totalBytesJob * 100.0 : 0;
                                if (percent > 100) percent = 100;

                                // 计算瞬时速度 (基于本次采样间隔)
                                double bytesDelta = totalProcessed - lastBytesSample;
                                double speedBps = bytesDelta / timeDelta;
                                string speedStr = FormatSpeed(speedBps);

                                // 切换到 UI 线程更新
                                Dispatcher.Invoke(() =>
                                {
                                    QCProgressBar.Value = percent;
                                    // 显示格式: "45.2 %  |  12.5 MB/s"
                                    SpeedText.Text = $"{percent:F1} %  |  {speedStr}";
                                });

                                // 更新采样点
                                lastUpdateTime = now;
                                lastBytesSample = totalProcessed;
                            }
                        }

                        // 3. 开始循环执行任务
                        foreach (var part in selectedParts)
                        {
                            if (token.IsCancellationRequested) break;

                            // 获取最新的分区信息 (地址/大小)
                            var targetPart = part;
                            if (freshPartitions != null)
                            {
                                var fresh = freshPartitions.FirstOrDefault(p => p.Label == part.Label && p.Lun == part.Lun);
                                if (fresh != null) targetPart = fresh;
                            }

                            long startSector = long.Parse(targetPart.StartSector);
                            
                            // ------ [Read] 读取 ------
                            if (operation == "Read")
                            {
                                string outputDir = string.IsNullOrEmpty(customOutputDir) 
                                    ? Path.Combine(_baseDir, $"readback_{startTime:yyyyMMdd_HHmmss}") 
                                    : customOutputDir;
                                Directory.CreateDirectory(outputDir);
                                
                                string outFile = Path.Combine(outputDir, targetPart.Label + ".bin");
                                long numSectors = long.Parse(targetPart.NumSectors);
                                long byteSize = numSectors * client.SectorSize;

                                Dispatcher.Invoke(() => Log($"正在读取 {targetPart.Label} ({FormatSize(byteSize)})..."));

                                using (var fs = new FileStream(outFile, FileMode.Create, FileAccess.Write, FileShare.Read, 1024 * 1024)) // 1MB File Buffer
                                {
                                    bool res = client.ReadDataToStream(targetPart.Lun, startSector, numSectors, fs, ReportProgress, client.SectorSize, token);
                                    if (!res) Log($"读取 {targetPart.Label} 失败");
                                }
                                
                                // 累加全局进度
                                bytesProcessedGlobal += byteSize;
                                // 重置当前文件进度，防止跳变
                                bytesProcessedCurrentFile = 0; 
                                // 强制刷新一次以确保进度条对齐
                                ReportProgress(0, 0); 
                                
                                // 生成 rawprogram (仅一次或最后生成)
                                if (part == selectedParts.Last())
                                {
                                    bool shouldGenerate = false;
                                    Dispatcher.Invoke(() => shouldGenerate = UseOfficialLineCB.IsChecked == true);

                                    if (shouldGenerate)
                                    {
                                        var groups = selectedParts.GroupBy(p => p.Lun);
                                        foreach (var group in groups)
                                        {
                                            string xmlName = $"rawprogram{group.Key}.xml";
                                            GenerateRawProgram(group.ToList(), Path.Combine(outputDir, xmlName));
                                            Dispatcher.Invoke(() => Log($"已生成 {xmlName}"));
                                        }
                                    }
                                }
                            }
                            // ------ [Write] 写入 ------
                            else if (operation == "Write")
                            {
                                string file = targetPart.Filename;
                                if (!File.Exists(file))
                                {
                                    Log($"跳过 {targetPart.Label}: 文件不存在");
                                    continue;
                                }

                                long fileSize = new FileInfo(file).Length;
                                Dispatcher.Invoke(() => Log($"正在写入 {targetPart.Label} ({FormatSize(fileSize)})..."));

                                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024))
                                {
                                    bool res = client.WriteDataFromStream(targetPart.Lun, startSector, fs, fileSize, ReportProgress, token);
                                    if (!res) Log($"写入 {targetPart.Label} 失败");
                                }

                                bytesProcessedGlobal += fileSize;
                                bytesProcessedCurrentFile = 0;
                                ReportProgress(0, 0);
                            }
                            // ------ [Erase] 擦除 ------
                            else if (operation == "Erase")
                            {
                                long numSectors = long.Parse(targetPart.NumSectors);
                                Dispatcher.Invoke(() => Log($"正在擦除 {targetPart.Label}..."));
                                
                                client.Erase(targetPart.Lun, startSector, numSectors);
                                
                                // 擦除很快，直接加进度
                                long partSize = numSectors * client.SectorSize;
                                bytesProcessedGlobal += partSize;
                                ReportProgress(0, 0); // Update UI
                            }
                        }

                        client.Reset();
                        Dispatcher.Invoke(() => 
                        { 
                            QCProgressBar.Value = 100; 
                            SpeedText.Text = "100 %  |  完成"; 
                            Log($"{operation} 全部完成。");
                        });
                    }
                }
                catch (Exception ex)
                {
                    Dispatcher.Invoke(() => Log($"操作异常: {ex.Message}"));
                }
            });
            SetUIBusy(false);
        }

        // 辅助方法：格式化速度
        private string FormatSpeed(double bytesPerSecond)
        {
            if (bytesPerSecond > 1024 * 1024) return $"{bytesPerSecond / (1024 * 1024):F2} MB/s";
            if (bytesPerSecond > 1024) return $"{bytesPerSecond / 1024:F2} KB/s";
            return $"{bytesPerSecond:F0} B/s";
        }




        private void GenerateRawProgram(List<PartitionInfo> parts, string outputPath)
        {
            XElement root = new XElement("data");
            foreach (var p in parts)
            {
                var el = new XElement("program");
                el.SetAttributeValue("SECTOR_SIZE_IN_BYTES", p.SectorSize);
                el.SetAttributeValue("file_sector_offset", "0");
                
                string fname = p.Filename;
                if (string.IsNullOrEmpty(fname)) fname = $"{p.Label}.img";
                el.SetAttributeValue("filename", fname);
                
                el.SetAttributeValue("label", p.Label);
                el.SetAttributeValue("num_partition_sectors", p.NumSectors);
                el.SetAttributeValue("physical_partition_number", p.Lun);
                el.SetAttributeValue("start_sector", p.StartSector);
                el.SetAttributeValue("sparse", "false");
                root.Add(el);
            }
            root.Save(outputPath);
        }


        private string GetExternalToolPath(string toolName)
        {
            string[] searchPaths = {
                Path.Combine(_binDir, toolName),
                Path.Combine(_baseDir, toolName),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, toolName),
                Path.Combine(Environment.CurrentDirectory, toolName)
            };

            foreach (var path in searchPaths)
            {
                if (File.Exists(path)) return path;
            }
            return "";
        }

        private async Task<bool> SendLoader(string port, CancellationToken token)
        {
            string devprg = "";
            Dispatcher.Invoke(() => devprg = LoaderTextBox.Text);
            
            if (!File.Exists(devprg)) { Log("未找到引导文件 (Programmer)。"); return false; }
            
            return await Task.Run(() =>
            {
                try
                {
                    if (token.IsCancellationRequested) return false;

                    // 1. Send Loader (External QSaharaServer)
                    Log("正在使用 QSaharaServer 发送 Loader...");
                    string saharaExe = GetExternalToolPath("QSaharaServer.exe");
                    if (string.IsNullOrEmpty(saharaExe))
                    {
                        Log($"错误: 未找到 QSaharaServer.exe，尝试使用 Native Sahara...");
                        // Fallback to Native if exe not found
                        using (var sahara = new SaharaClient(port, Log, (p, s) => {
                            Dispatcher.Invoke(() => {
                                QCProgressBar.Value = p;
                                SpeedText.Text = s;
                            });
                        }))
                        {
                            if (!sahara.ConnectAndUpload(devprg, token)) return false;
                        }
                    }
                    else
                    {
                        string args = $"-p {port} -s 13:\"{devprg}\"";
                        if (!RunExternalTool(saharaExe, args))
                        {
                            Log("Loader 发送失败 (QSaharaServer)。");
                            return false;
                        }
                    }

                    if (token.IsCancellationRequested) return false;

                    Log("Loader 发送成功！");
                    Thread.Sleep(1000); 
                    
                    // Check if Oplus Test Mode is enabled
                    bool useOplusTest = false;
                    Dispatcher.Invoke(() => useOplusTest = OplusTestModeCB.IsChecked == true);

                    using (var client = new FirehoseClient(port, Log))
                    {
                        // Try to configure first to establish session parameters
                        client.Configure();

                        if (useOplusTest)
                        {
                            Log("启用 Oplus 验证模式...");
                            string oplusTestDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "oplus_test");
                            if (!Directory.Exists(oplusTestDir)) oplusTestDir = Path.Combine(_binDir, "oplus_test");
                            if (!Directory.Exists(oplusTestDir)) oplusTestDir = Path.Combine(_baseDir, "oplus_test");
                            
                            if (!Directory.Exists(oplusTestDir))
                            {
                                Log($"错误: 未找到 oplus_test 文件夹。");
                                return false;
                            }

                            string userDigest = "";
                            string userSig = "";
                            Dispatcher.Invoke(() => {
                                userDigest = DigestTextBox.Text;
                                userSig = SignatureTextBox.Text;
                            });

                            if (!PerformOplusHandshakeNative(client, oplusTestDir, userDigest, userSig)) return false;
                        }
                        else
                        {
                            // Check if we need to send Digest/Signature (VIP)
                            string digest = "";
                            string sig = "";
                            Dispatcher.Invoke(() => {
                                digest = DigestTextBox.Text;
                                sig = SignatureTextBox.Text;
                            });

                            if ((!string.IsNullOrEmpty(digest) && File.Exists(digest)) || 
                                (!string.IsNullOrEmpty(sig) && File.Exists(sig)))
                            {
                                Log("检测到 Digest/Signature，正在发送 VIP 验证 (Native)...");
                                if (!PerformVipHandshakeNative(client, digest, sig)) return false;
                            }
                        }
                    }

                    // Auto-uncheck Send Loader upon success
                    Dispatcher.Invoke(() => SendLoaderCB.IsChecked = false);
                    
                    return true;
                }
                catch (Exception ex)
                {
                    Log($"SendLoader 异常: {ex.Message}");
                    return false;
                }
            });
        }

        /*
        private bool RunNativeTool(string toolName, string arguments)
        {
            return false;
        }
        */

        private bool RunExternalTool(string exePath, string arguments)
        {
            // Try Native Implementation First - REMOVED
            /*
            string toolName = Path.GetFileName(exePath);
            if (RunNativeTool(toolName, arguments))
            {
                return true;
            }
            */

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = _binDir
                };

                using (Process p = new Process())
                {
                    p.StartInfo = psi;
                    p.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log($"[{Path.GetFileNameWithoutExtension(exePath)}] {e.Data}"); };
                    p.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) Log($"[{Path.GetFileNameWithoutExtension(exePath)}] ERR: {e.Data}"); };
                    
                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    p.WaitForExit();
                    
                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Log($"执行 {Path.GetFileName(exePath)} 失败: {ex.Message}");
                return false;
            }
        }

        private bool PerformOplusHandshakeNative(FirehoseClient client, string configDir, string userDigest, string userSig)
        {
            // 1. Digest
            string digestPath = !string.IsNullOrEmpty(userDigest) && File.Exists(userDigest) ? userDigest : Path.Combine(configDir, "digest");
            if (File.Exists(digestPath))
            {
                byte[] data = File.ReadAllBytes(digestPath);
                if (!client.SendSignature(data)) return false;
            }

            // 2. XMLs
            string[] xmls = { "custom1.xml", "custom2.xml", "transfercfg.xml", "custom3.xml", "getsigndata.xml", "custom4.xml", "verify.xml", "custom5.xml" };
            foreach (var xml in xmls)
            {
                string path = Path.Combine(configDir, xml);
                if (File.Exists(path))
                {
                    string content = File.ReadAllText(path);
                    if (!client.SendRawXml(content)) return false;
                }
            }

            // 3. Sig
            string sigPath = !string.IsNullOrEmpty(userSig) && File.Exists(userSig) ? userSig : Path.Combine(configDir, "sig");
            if (File.Exists(sigPath))
            {
                byte[] data = File.ReadAllBytes(sigPath);
                if (!client.SendSignature(data)) return false;
            }

            // 4. More XMLs
            string[] moreXmls = { "custom6.xml", "sha256init.xml", "custom7.xml" };
            foreach (var xml in moreXmls)
            {
                string path = Path.Combine(configDir, xml);
                if (File.Exists(path))
                {
                    string content = File.ReadAllText(path);
                    if (!client.SendRawXml(content)) return false;
                }
            }

            return true;
        }

        private bool PerformVipHandshakeNative(FirehoseClient client, string digest, string sig)
        {
            if (!string.IsNullOrEmpty(digest) && File.Exists(digest))
            {
                byte[] data = File.ReadAllBytes(digest);
                if (!client.SendSignature(data)) return false;
            }

            if (!string.IsNullOrEmpty(sig) && File.Exists(sig))
            {
                byte[] data = File.ReadAllBytes(sig);
                if (!client.SendSignature(data)) return false;
            }
            
            return true;
        }





        private async Task PerformReboot(string tag)
        {
            // tag format: MODE_TARGET or just TARGET (auto-detect mode)
            // e.g. ADB_System, Fastboot_EDL, or System
            
            string mode = "";
            string target = "";

            string[] parts = tag.Split('_');
            if (parts.Length == 2)
            {
                mode = parts[0];
                target = parts[1];
            }
            else if (parts.Length == 1)
            {
                target = parts[0];
                // Auto-detect mode
                if (FastbootClient.IsConnected())
                {
                    mode = "Fastboot";
                }
                else
                {
                    // Check for EDL port
                    string? port = GetSelectedPort();
                    if (!string.IsNullOrEmpty(port))
                    {
                        mode = "EDL";
                    }
                    else
                    {
                        // Try to find a port if not selected
                        var ports = System.IO.Ports.SerialPort.GetPortNames();
                        if (ports.Length > 0) mode = "EDL"; // Assumption, will be verified later
                        else 
                        {
                            Log("未检测到设备 (Fastboot 或 EDL)。");
                            return;
                        }
                    }
                }
            }
            else return;

            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            await Task.Run(async () =>
            {
                try
                {
                    if (token.IsCancellationRequested) return;

                    if (mode == "ADB")
                    {
                        Log("ADB 模式在纯内置版本中暂不支持 (需实现 Native ADB)。");
                        return;
                    }
                    else if (mode == "Fastboot")
                    {
                        if (!FastbootClient.IsConnected()) { Log("未检测到 Fastboot 设备。"); return; }
                        Log($"正在执行 Fastboot 重启到 {target}...");

                        try
                        {
                            if (target == "EDL")
                            {
                                FastbootClient.RebootEdl();
                            }
                            else if (target == "Recovery")
                            {
                                FastbootClient.RebootRecovery();
                            }
                            else if (target == "Bootloader")
                            {
                                FastbootClient.RebootBootloader();
                            }
                            else if (target == "FastbootD")
                            {
                                FastbootClient.RebootFastbootD();
                            }
                            else if (target == "PowerOff")
                            {
                                FastbootClient.PowerOff();
                            }
                            else // System
                            {
                                FastbootClient.RebootSystem();
                            }
                            Log("Fastboot 重启命令已发送。");
                        }
                        catch (Exception ex)
                        {
                            Log($"Fastboot 操作失败: {ex.Message}");
                        }
                    }
                    else if (mode == "EDL")
                    {
                        string? port = await WaitForPortAsync();
                        if (string.IsNullOrEmpty(port)) return;

                        string imgDir = Path.Combine(_baseDir, "img");

                        if ((target == "Recovery" || target == "FastbootD") && !Directory.Exists(imgDir))
                        {
                            Log($"错误: 镜像目录未找到 {imgDir}");
                            return;
                        }

                        if (target == "System")
                        {
                            using (var client = new FirehoseClient(port, Log)) 
                            {
                                if (client.Reset()) Log("已发送重启到系统命令。");
                                else Log("重启命令发送失败 (Target rejected)。");
                            }
                        }
                        else if (target == "EDL")
                        {
                            using (var client = new FirehoseClient(port, Log)) 
                            {
                                if (client.SendRawXml("<?xml version=\"1.0\" ?><data><power value=\"reset_to_edl\"/></data>"))
                                    Log("已发送重启到 EDL 命令。");
                                else
                                    Log("重启到 EDL 失败。");
                            }
                        }
                        else if (target == "PowerOff")
                        {
                            using (var client = new FirehoseClient(port, Log)) 
                            {
                                if (client.SendRawXml("<?xml version=\"1.0\" ?><data><power value=\"poweroff\"/></data>"))
                                    Log("已发送关机命令。");
                                else
                                    Log("关机命令失败。");
                            }
                        }
                        else if (target == "Recovery" || target == "FastbootD")
                        {
                            var miscPart = Partitions.FirstOrDefault(p => p.Label == "misc");
                            if (miscPart == null)
                            {
                                Log("错误: 未找到 misc 分区信息。请先执行 '连接/读取分区表' 以定位 misc 分区。");
                                return;
                            }
                            
                            string imgName = target == "Recovery" ? "misc_torecovery.img" : "misc_tofastbootd.img";
                            string imgPath = Path.Combine(imgDir, imgName);
                            if (!File.Exists(imgPath)) 
                            {
                                Log($"错误: 未找到镜像文件 {imgPath}");
                                return;
                            }
                            
                            using (var client = new FirehoseClient(port, Log))
                            {
                                if (client.Configure())
                                {
                                    Log($"正在写入 {imgName} 到 misc...");
                                    using(var fs = File.OpenRead(imgPath))
                                    {
                                        if (client.WriteDataFromStream(miscPart.Lun, long.Parse(miscPart.StartSector), fs, fs.Length, null, token))
                                        {
                                            Log("写入成功，正在重启...");
                                            client.Reset();
                                        }
                                        else
                                        {
                                            Log("写入 misc 失败。");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                { 
                    Log($"重启操作失败: {ex.Message}"); 
                }
            });
        }

        // --- Helpers ---

        private void RunConfigure(FirehoseClient client)
        {
            // Use native Firehose Client
            try
            {
                // Connect is called inside Configure
                bool success = client.Configure();
                if (success) 
                {
                    Log("设备配置成功 (Native Firehose)");
                    _detectedMemoryName = client.MemoryName;
                    _detectedSectorSize = client.SectorSize;
                    Log($"检测到存储类型: {_detectedMemoryName}, 扇区大小: {_detectedSectorSize}");
                }
                else 
                {
                    Log("设备配置失败 (Native Firehose)");
                }
            }
            catch (Exception ex)
            {
                Log($"配置错误: {ex.Message}");
            }
        }


        private void DevMgrBtn_Click(object sender, RoutedEventArgs e)
        {
            try 
            { 
                Process.Start(new ProcessStartInfo 
                { 
                    FileName = "devmgmt.msc", 
                    UseShellExecute = true 
                }); 
            }
            catch (Exception ex) { Log("打开设备管理器错误: " + ex.Message); }
        }

        private async void DeviceInfoBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            
            try
            {
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port)) return;

                // 1. Send Loader if checked
                if (SendLoaderCB.IsChecked == true)
                {
                    UpdateProgress(0, "正在发送引导...");
                    bool success = await SendLoader(port, token);
                    if (!success) return;
                }

                await Task.Run(() =>
                {
                    try
                    {
                        using (var client = new FirehoseClient(port, Log))
                        {
                            if (token.IsCancellationRequested) return;
                            
                            Dispatcher.Invoke(() => SpeedText.Text = "正在读取信息...");
                            RunConfigure(client);

                            var info = client.GetStorageInfo();
                            if (info != null)
                            {
                                Log("================ 设备存储信息 ================");
                                foreach (var kvp in info)
                                {
                                    Log($"{kvp.Key}: {kvp.Value}");
                                }
                                Log("==============================================");
                            }
                            else
                            {
                                Log("读取存储信息失败。");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() => Log($"读取信息异常: {ex.Message}"));
                    }
                });
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        private async void WipeMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem item && item.Tag is string tag)
            {
                if (tag == "EraseUserdata")
                {
                    var userdata = Partitions.FirstOrDefault(p => p.Label.ToLower() == "userdata");
                    if (userdata != null)
                    {
                        userdata.IsSelected = true;
                        await PerformOperation("Erase");
                    }
                    else
                    {
                        Log("未找到 userdata 分区，请先读取分区表。");
                    }
                }
                else if (tag == "EraseFrp")
                {
                    var frp = Partitions.FirstOrDefault(p => p.Label.ToLower() == "frp" || p.Label.ToLower() == "config");
                    if (frp != null)
                    {
                        frp.IsSelected = true;
                        await PerformOperation("Erase");
                    }
                    else
                    {
                        Log("未找到 FRP 相关分区 (frp/config)，请先读取分区表。");
                    }
                }
            }
        }

        private void ResetBtn_Click(object sender, RoutedEventArgs e)
        {
            if (ResetBtn.ContextMenu != null)
                ResetBtn.ContextMenu.IsOpen = true;
        }

        private async void RebootMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem item && item.Tag is string tag)
            {
                SetUIBusy(true);
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port)) { SetUIBusy(false); return; }

                await Task.Run(() =>
                {
                    try
                    {
                        using (var client = new FirehoseClient(port, Log))
                        {
                            RunConfigure(client);
                            
                            string powerVal = "reset";
                            if (tag == "Recovery") powerVal = "reset_to_recovery"; 
                            else if (tag == "Bootloader") powerVal = "reset_to_bootloader"; 
                            else if (tag == "EDL") powerVal = "reset_to_edl";
                            else if (tag == "PowerOff") powerVal = "poweroff";
                            
                            string xml = $"<?xml version=\"1.0\" ?><data><power value=\"{powerVal}\"/></data>";
                            if (client.SendRawXml(xml))
                                Log($"已发送电源命令: {powerVal}");
                            else
                                Log($"发送电源命令失败: {powerVal}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() => Log($"重启异常: {ex.Message}"));
                    }
                });
                SetUIBusy(false);
            }
        }

        private void SwitchSlotBtn_Click(object sender, RoutedEventArgs e)
        {
            if (SwitchSlotBtn.ContextMenu != null)
                SwitchSlotBtn.ContextMenu.IsOpen = true;
        }

        private async void SlotMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem item && item.Tag is string tag)
            {
                SetUIBusy(true);
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port)) { SetUIBusy(false); return; }

                await Task.Run(() =>
                {
                    try
                    {
                        using (var client = new FirehoseClient(port, Log))
                        {
                            RunConfigure(client);
                            if (client.SetActiveSlot(tag))
                                Log($"已切换到 Slot {tag}");
                            else
                                Log($"切换 Slot {tag} 失败 (可能不支持)");
                        }
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() => Log($"切换槽位异常: {ex.Message}"));
                    }
                });
                SetUIBusy(false);
            }
        }



        private void WipeDataBtn_Click(object sender, RoutedEventArgs e)
        {
             if (sender is System.Windows.Controls.Button btn && btn.ContextMenu != null)
            {
                btn.ContextMenu.PlacementTarget = btn;
                btn.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
                btn.ContextMenu.IsOpen = true;
            }
        }



        private async Task<string?> WaitForPortAsync()
        {
            string? port = null;
            await Dispatcher.InvokeAsync(() =>
            {
                if (PortComboBox.SelectedItem is string s) port = s;
            });

            if (string.IsNullOrEmpty(port))
            {
                Log("请先选择端口。");
                return null;
            }
            return port;
        }

        private void UpdateProgress(double value, string? speedText = null)
        {
            Dispatcher.Invoke(() =>
            {
                QCProgressBar.Value = value;
                if (speedText != null) SpeedText.Text = speedText;
            });
        }

        private async void SendAuthBtn_Click(object sender, RoutedEventArgs e)
        {
            SetUIBusy(true);
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            try
            {
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port)) return;

                bool success = await SendLoader(port, token);
                if (success)
                {
                    Log("引导/验证流程执行完毕。");
                }
                else
                {
                    Log("引导/验证流程失败。");
                }
            }
            finally
            {
                SetUIBusy(false);
            }
        }

        private void TitleBar_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left)
                this.DragMove();
        }

        private void MinimizeBtn_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void SearchPartBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (sender is System.Windows.Controls.TextBox box)
            {
                string filter = box.Text.Trim();
                var view = System.Windows.Data.CollectionViewSource.GetDefaultView(PartList.ItemsSource);
                if (view != null)
                {
                    view.Filter = (obj) =>
                    {
                        if (string.IsNullOrEmpty(filter)) return true;
                        if (obj is PartitionInfo p)
                        {
                            return p.Label.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
                        }
                        return false;
                    };
                    view.Refresh();
                }
            }
        }

        private void ClearLog_Click(object sender, RoutedEventArgs e)
        {
            LogText.Clear();
        }

        // New UI Event Handlers
        private void MinimizeButton_Click(object sender, RoutedEventArgs e) => MinimizeBtn_Click(sender, e);
        private void CloseButton_Click(object sender, RoutedEventArgs e) => CloseBtn_Click(sender, e);



        private string? GetSelectedPort()
        {
            if (PortComboBox.SelectedItem == null)
            {
                Log("请先选择端口");
                return null;
            }
            string? selected = PortComboBox.SelectedItem.ToString();
            if (selected == null) return null;

            // Extract COM port (e.g., "COM3 - ...")
            int dashIndex = selected.IndexOf(" -");
            if (dashIndex > 0)
            {
                return selected.Substring(0, dashIndex);
            }
            return selected;
        }

        private async void DiagConnectBtn_Click(object sender, RoutedEventArgs e)
        {
            string portName = GetSelectedPort();
            if (string.IsNullOrEmpty(portName)) return;

            try
            {
                SerialPort port = new SerialPort(portName, 115200);
                port.Open();
                _diagClient = new DiagClient(port, Log, (p, m) => { });
                if (_diagClient.Connect())
                {
                    Log("Diag Connected!");
                }
                else
                {
                    Log("Diag Connection Failed.");
                    port.Close();
                }
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
        }

        private void DiagReadNVBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_diagClient == null) return;
            // Example: Read IMEI (Item 550)
            byte[] data = _diagClient.ReadNV(550);
            if (data != null)
            {
                Log($"NV 550: {BitConverter.ToString(data)}");
            }
            else
            {
                Log("Failed to read NV 550");
            }
        }

        private void DiagWriteNVBtn_Click(object sender, RoutedEventArgs e)
        {
             if (_diagClient == null) return;
             Log("Write NV not fully implemented in UI yet.");
        }

        private void DiagSwitchEDLBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_diagClient == null) return;
            _diagClient.SwitchToEDL();
            Log("Switch command sent.");
        }

        private async void StreamConnectBtn_Click(object sender, RoutedEventArgs e)
        {
            string portName = GetSelectedPort();
            if (string.IsNullOrEmpty(portName)) return;

            try
            {
                SerialPort port = new SerialPort(portName, 115200);
                port.Open();
                _streamingClient = new StreamingClient(port, Log, (p, m) => { });
                if (_streamingClient.Connect())
                {
                    Log("Streaming Connected!");
                }
                else
                {
                    Log("Streaming Connection Failed.");
                    port.Close();
                }
            }
            catch (Exception ex)
            {
                Log($"Error: {ex.Message}");
            }
        }

        private void StreamReadTableBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_streamingClient == null) return;
            byte[] table = _streamingClient.ReadPartitionTable();
            if (table != null)
            {
                Log($"Partition Table Read: {table.Length} bytes");
            }
            else
            {
                Log("Failed to read partition table");
            }
        }
    }

    public class IncompleteGptException : Exception
    {
        public int SectorsNeeded { get; }
        public int SectorSize { get; }
        public IncompleteGptException(int sectors, int size) : base($"Need {sectors} sectors") 
        { 
            SectorsNeeded = sectors; 
            SectorSize = size;
        }
    }

   

    public class PartitionInfo : System.ComponentModel.INotifyPropertyChanged
    {
        private bool _isSelected;
        private string _filename = "";

        public bool IsSelected 
 
        { 
            get => _isSelected; 
            set { _isSelected = value; OnPropertyChanged(nameof(IsSelected)); } 
        }
        
        public string Label { get; set; } = "";
        public int Lun { get; set; } = 0;
        public string StartSector { get; set; } = "";
        public string NumSectors { get; set; } = "";
        public string SectorSize { get; set; } = "4096";
        public string Size { get; set; } = "";
        
        public string Filename 
        { 
            get => _filename; 
            set { _filename = value; OnPropertyChanged(nameof(Filename)); } 
        }

        public long SizeInKB { get; set; }

        public string FormattedSize
        {
            get
            {
                if (double.TryParse(Size, out double kb))
                {
                    if (kb >= 1024 * 1024) return $"{kb / (1024 * 1024):F2} GB";
                    if (kb >= 1024) return $"{kb / 1024:F2} MB";
                    return $"{kb:F2} KB";
                }
                return "0 KB";
            }
        }

        public string StartAddress
        {
            get
            {
                if (long.TryParse(StartSector, out long start) && int.TryParse(SectorSize, out int size))
                {
                    return $"0x{(start * size):X}";
                }
                return "0x0";
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string name) => PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
    }
}

