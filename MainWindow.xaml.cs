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
        // private NativeMethods.LogCallback _logCallback; // Removed C++ Native Call


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

                // Initialize Native Logging
                try
                {
                    // _logCallback = new NativeMethods.LogCallback(OnNativeLog);
                    // NativeMethods.set_log_callback(_logCallback);
                }
                catch (Exception ex)
                {
                    System.Windows.MessageBox.Show($"加载原生库失败 (日志功能将受限): {ex.Message}", "警告", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                }

                InitializePaths();
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

        private List<PartitionInfo> ReadGpt(FirehoseClient client, string defaultMemoryName, CancellationToken token = default)
        {
            Log("正在读取 GPT 分区表 (使用 GptParser)...");
            
            // Optimization: Try to read without configure first (like fh_loader --skip_configure)
            // This avoids resetting state or causing errors on some devices after auth.
            // We assume UFS/4096 initially as it's most common for these devices.
            int sectorSize = 4096;
            string memoryName = "ufs";
            bool configured = false;

            if (_detectedSectorSize > 0)
            {
                sectorSize = _detectedSectorSize;
                memoryName = _detectedMemoryName;
            }

            List<PartitionInfo> allPartitions = new List<PartitionInfo>();

            // Helper function to read GPT for a specific LUN
            List<PartitionInfo>? ReadLunGpt(int lun, int currentSectorSize)
            {
                if (token.IsCancellationRequested) return null;
                try 
                {
                    // Reuse existing client
                    // OPLUS Mechanism: Read fixed size with label "gptbackup0"
                    // UFS (4096): 6 sectors (LBA 0-5) -> MBR + Header + 4 sectors of entries (128 entries)
                    // eMMC (512): 34 sectors (LBA 0-33) -> MBR + Header + 32 sectors of entries (128 entries)
                    int sectorsToRead = currentSectorSize == 4096 ? 6 : 34;
                    
                    Log($"LUN {lun}: Reading {sectorsToRead} sectors (gptbackup0)...");
                    byte[]? buffer = client.ReadData(lun, 0, sectorsToRead, currentSectorSize, token, label: "gptbackup0", filename: "gpt_backup0.bin");
                    
                    if (buffer == null) return null;

                    // Parse with GptParser
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
                            Size = (((double)(p.LastLba - p.FirstLba + 1) * currentSectorSize) / 1024.0).ToString("F2"),
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

            // 2. Try Read LUN 0 (Fast Path)
            var lun0Parts = ReadLunGpt(0, sectorSize);
            
            // 3. If failed, try Configure and Retry
            if (lun0Parts == null)
            {
                Log("直接读取失败，尝试发送配置命令...");
                RunConfigure(client);
                configured = true;
                sectorSize = _detectedSectorSize > 0 ? _detectedSectorSize : 4096;
                memoryName = !string.IsNullOrEmpty(_detectedMemoryName) ? _detectedMemoryName : "ufs";
                
                lun0Parts = ReadLunGpt(0, sectorSize);
            }

            if (lun0Parts != null)
            {
                allPartitions.AddRange(lun0Parts);
                Log($"LUN 0: 成功加载 {lun0Parts.Count} 个分区");
            }
            else
            {
                Log("LUN 0: 读取失败");
                // Try fallback to 512 bytes if we haven't configured and failed with 4096
                if (!configured && sectorSize == 4096)
                {
                     Log("尝试使用 512 字节扇区大小...");
                     lun0Parts = ReadLunGpt(0, 512);
                     if (lun0Parts != null)
                     {
                         sectorSize = 512;
                         allPartitions.AddRange(lun0Parts);
                         Log($"LUN 0: 成功加载 {lun0Parts.Count} 个分区 (512B)");
                     }
                }
            }

            // 4. If UFS, read LUN 1-5
            if (memoryName == "ufs" && lun0Parts != null)
            {
                for (int lun = 1; lun <= 5; lun++)
                {
                    var lunParts = ReadLunGpt(lun, sectorSize);
                    if (lunParts != null)
                    {
                        allPartitions.AddRange(lunParts);
                        Log($"LUN {lun}: 成功加载 {lunParts.Count} 个分区");
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return allPartitions;
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

        private async Task PerformOperation(string operation, string? customOutputDir = null)
        {
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            UpdateProgress(0, "等待端口...");
            string? port = await WaitForPortAsync();
            if (string.IsNullOrEmpty(port)) return;

            var selectedParts = Partitions.Where(p => p.IsSelected).ToList();
            if (selectedParts.Count == 0) { Log("未选择分区。"); return; }

            // 1. Send Loader if checked
            if (SendLoaderCB.IsChecked == true)
            {
                UpdateProgress(5, "正在发送引导...");
                bool success = await SendLoader(port, token);
                if (!success) return;
                UpdateProgress(15, "引导发送完成");
            }
            else
            {
                UpdateProgress(15, "跳过引导");
            }

            // 2. Generate XML (for Read/Write temp usage) - Removed
            // string tempXml = Path.Combine(_binDir, "temp_action.xml");
            // if (operation != "Erase")
            // {
            //    GenerateXml(selectedParts, tempXml, operation);
            // }

            // 3. Execute
            await Task.Run(() =>
            {
                try
                {
                    using (var client = new FirehoseClient(port, Log))
                    {
                        if (token.IsCancellationRequested) return;

                        UpdateProgress(20, "正在配置设备...");
                        Log("正在配置...");
                        RunConfigure(client);
                        
                        // Ensure defaults if configure failed or returned partial info
                        if (string.IsNullOrEmpty(_detectedMemoryName)) _detectedMemoryName = "ufs";
                        if (_detectedSectorSize == 0) _detectedSectorSize = 4096;

                        // Refresh Partition Table to ensure correct addresses
                        UpdateProgress(25, "正在刷新分区表...");
                        Log("正在刷新分区表以获取最新地址...");
                        var freshPartitions = ReadGpt(client, _detectedMemoryName, token);
                        
                        if (freshPartitions == null || freshPartitions.Count == 0)
                        {
                            Log("警告: 刷新分区表失败，将尝试使用现有信息。");
                        }
                        else
                        {
                            Log($"分区表刷新成功，找到 {freshPartitions.Count} 个分区。");
                        }

                    UpdateProgress(30, "准备开始...");

                    long totalSizeKB = selectedParts.Sum(p => p.SizeInKB);
                    long lastProcessedKB = 0;
                    DateTime lastTime = DateTime.Now;
                    
                    Action<string> progressHandler = (line) =>
                    {
                        // Parse percentage: "12.50 %"
                        if (line.Contains("%"))
                        {
                            var match = System.Text.RegularExpressions.Regex.Match(line, @"(\d+\.?\d*)\s*%");
                            if (match.Success && double.TryParse(match.Groups[1].Value, out double percent))
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    // Scale 0-100% to 30-100%
                                    double scaledPercent = 30 + (percent * 0.7);
                                    QCProgressBar.Value = scaledPercent;
                                    
                                    // Calculate Speed
                                    DateTime now = DateTime.Now;
                                    double elapsedSeconds = (now - lastTime).TotalSeconds;
                                    if (elapsedSeconds >= 0.5) // Update speed every 0.5s
                                    {
                                        long currentProcessedKB = (long)(totalSizeKB * (percent / 100.0));
                                        long deltaKB = currentProcessedKB - lastProcessedKB;
                                        double speedKBps = deltaKB / elapsedSeconds;
                                        
                                        string speedStr;
                                        if (speedKBps > 1024 * 1024) speedStr = $"{speedKBps / (1024 * 1024):F2} GB/s";
                                        else if (speedKBps > 1024) speedStr = $"{speedKBps / 1024:F2} MB/s";
                                        else speedStr = $"{speedKBps:F2} KB/s";
                                        
                                        SpeedText.Text = speedStr;
                                        
                                        lastProcessedKB = currentProcessedKB;
                                        lastTime = now;
                                    }
                                });
                            }
                        }
                    };

                    // Reuse existing client
                    {
                        if (operation == "Read")
                        {
                            string outputDir;
                            if (!string.IsNullOrEmpty(customOutputDir))
                            {
                                outputDir = customOutputDir;
                            }
                            else
                            {
                                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                                outputDir = Path.Combine(_baseDir, $"readback_{timestamp}");
                            }
                            Directory.CreateDirectory(outputDir);
                            Log($"正在读取到 {outputDir}...");

                            foreach (var part in selectedParts)
                            {
                                if (token.IsCancellationRequested)
                                {
                                    Log("操作已取消。");
                                    break;
                                }

                                // Use fresh info if available
                                var targetPart = part;
                                if (freshPartitions != null)
                                {
                                    var fresh = freshPartitions.FirstOrDefault(p => p.Label == part.Label && p.Lun == part.Lun);
                                    if (fresh != null) 
                                    {
                                        targetPart = fresh;
                                        // Log($"使用最新地址: {targetPart.Label} @ {targetPart.StartSector}");
                                    }
                                    else
                                    {
                                        Log($"警告: 新分区表中未找到 {part.Label}，使用旧地址。");
                                    }
                                }

                                string outFile = Path.Combine(outputDir, targetPart.Label + ".bin");
                                Log($"正在读取 {targetPart.Label} ({targetPart.Size} KB)...");
                                
                                using (var fs = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                                {
                                    long start = long.Parse(targetPart.StartSector);
                                    long num = long.Parse(targetPart.NumSectors);
                                    
                                    long fileLastBytes = 0;
                                    DateTime fileLastTime = DateTime.Now;

                                    bool success = client.ReadDataToStream(targetPart.Lun, start, num, fs, (current, total) => {
                                         Dispatcher.Invoke(() => {
                                            double percent = (double)current / total * 100.0;
                                            QCProgressBar.Value = 30 + (percent * 0.7);
                                            
                                            DateTime now = DateTime.Now;
                                            double elapsed = (now - fileLastTime).TotalSeconds;
                                            if (elapsed >= 0.1)
                                            {
                                                double speed = (current - fileLastBytes) / elapsed;
                                                SpeedText.Text = speed > 1048576 ? $"{speed/1048576:F2} MB/s" : $"{speed/1024:F2} KB/s";
                                                fileLastBytes = current;
                                                fileLastTime = now;
                                            }
                                         });
                                    }, null, token, label: targetPart.Label, filename: targetPart.Label + ".bin");
                                    
                                    if (!success)
                                    {
                                        Log($"读取 {targetPart.Label} 失败");
                                    }
                                }
                            }
                            
                            GenerateRawProgram(selectedParts, Path.Combine(outputDir, "rawprogram.xml"));
                            Log($"已生成 rawprogram.xml 到 {outputDir}");
                        }
                        else if (operation == "Write")
                        {
                            foreach (var part in selectedParts)
                            {
                                if (token.IsCancellationRequested)
                                {
                                    Log("操作已取消。");
                                    break;
                                }

                                // Use fresh info if available
                                var targetPart = part;
                                if (freshPartitions != null)
                                {
                                    var fresh = freshPartitions.FirstOrDefault(p => p.Label == part.Label && p.Lun == part.Lun);
                                    if (fresh != null) targetPart = fresh;
                                }

                                string file = targetPart.Filename;
                                if (string.IsNullOrEmpty(file) || !File.Exists(file)) 
                                {
                                    Log($"跳过 {targetPart.Label}: 未指定文件");
                                    continue;
                                }
                                
                                Log($"正在写入 {targetPart.Label}...");
                                using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read))
                                {
                                    long start = long.Parse(targetPart.StartSector);
                                    
                                    long fileLastBytes = 0;
                                    DateTime fileLastTime = DateTime.Now;

                                    bool success = client.WriteDataFromStream(targetPart.Lun, start, fs, fs.Length, (current, total) => {
                                         Dispatcher.Invoke(() => {
                                            double percent = (double)current / total * 100.0;
                                            QCProgressBar.Value = 30 + (percent * 0.7);
                                            
                                            DateTime now = DateTime.Now;
                                            double elapsed = (now - fileLastTime).TotalSeconds;
                                            if (elapsed >= 0.1)
                                            {
                                                double speed = (current - fileLastBytes) / elapsed;
                                                SpeedText.Text = speed > 1048576 ? $"{speed/1048576:F2} MB/s" : $"{speed/1024:F2} KB/s";
                                                fileLastBytes = current;
                                                fileLastTime = now;
                                            }
                                         });
                                    }, token, label: targetPart.Label, filename: targetPart.Label + ".bin");
                                    
                                    if (!success)
                                    {
                                        Log($"写入 {targetPart.Label} 失败");
                                        return;
                                    }
                                }
                            }

                            string patchFiles = "";
                            Dispatcher.Invoke(() => patchFiles = PatchText.Text);
                            if (!string.IsNullOrEmpty(patchFiles))
                            {
                                foreach(var patchFile in patchFiles.Split(','))
                                {
                                    if(File.Exists(patchFile))
                                    {
                                        Log($"正在应用补丁 {Path.GetFileName(patchFile)}...");
                                        string xml = File.ReadAllText(patchFile);
                                        client.SendRawXml(xml);
                                    }
                                }
                            }
                        }
                        else if (operation == "Erase")
                        {
                            foreach (var part in selectedParts)
                            {
                                if (token.IsCancellationRequested)
                                {
                                    Log("操作已取消。");
                                    break;
                                }

                                Log($"正在擦除 {part.Label}...");
                                long start = long.Parse(part.StartSector);
                                long num = long.Parse(part.NumSectors);
                                if (!client.Erase(part.Lun, start, num))
                                {
                                    Log($"擦除 {part.Label} 失败");
                                }
                            }
                        }
                        
                        client.Reset();
                    }
                    } // End using client

                    Log($"{operation} 完成。");
                    Dispatcher.Invoke(() => { QCProgressBar.Value = 100; SpeedText.Text = "完成"; });
                }
                catch (Exception ex)
                {
                    Log($"错误: {ex.Message}");
                }
            });
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



        private void ResetBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.ContextMenu != null)
            {
                btn.ContextMenu.PlacementTarget = btn;
                btn.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
                btn.ContextMenu.IsOpen = true;
            }
        }

        private async void RebootMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem item && item.Tag is string mode)
            {
                SetUIBusy(true);
                try
                {
                    await PerformReboot(mode);
                }
                finally
                {
                    SetUIBusy(false);
                }
            }
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
            string? port = await WaitForPortAsync();
            if (string.IsNullOrEmpty(port))
            {
                SetUIBusy(false);
                return;
            }

            await Task.Run(() =>
            {
                try
                {
                    Log("正在尝试读取设备信息 (Sahara/Firehose)...");
                    
                    // 1. Try Sahara Mode First
                    Dictionary<string, string>? saharaInfo = null;
                    try
                    {
                        using (var sahara = new SaharaClient(port, (s) => { }, null))
                        {
                            saharaInfo = sahara.GetDeviceInfo();
                        }
                    }
                    catch { /* Ignore Sahara errors, might be in Firehose mode */ }

                    if (saharaInfo != null && saharaInfo.Count > 0)
                    {
                        Log("================ 设备信息 (Sahara) ================");
                        if (saharaInfo.ContainsKey("Serial")) Log($"Serial:      {saharaInfo["Serial"]}");
                        if (saharaInfo.ContainsKey("HWID"))   Log($"HWID:        {saharaInfo["HWID"]}");
                        if (saharaInfo.ContainsKey("PKHash")) Log($"PKHash:      {saharaInfo["PKHash"]}");
                        if (saharaInfo.ContainsKey("SBLVersion")) Log($"SBL Version: {saharaInfo["SBLVersion"]}");
                        Log("===================================================");
                        return;
                    }

                    // 2. Fallback to Firehose Mode
                    StringBuilder logBuffer = new StringBuilder();
                    Action<string> capturingLogger = (s) => {
                        Log(s);
                        logBuffer.AppendLine(s);
                    };

                    using (var client = new FirehoseClient(port, capturingLogger))
                    {
                        client.Configure();
                    }
                    string output = logBuffer.ToString();
                    
                    // Parse output
                    string psn = ParseLogValue(output, "INFO: PSN:");
                    string socId = ParseLogValue(output, "INFO: Chip serial num:");
                    string chipId = ParseLogValue(output, "CHIPID:");
                    
                    // Clean up SOCID (remove 0x prefix if needed, handle hex)
                    // qctool.bat does some complex sed replacement to uppercase, C# is easier.
                    if (!string.IsNullOrEmpty(socId)) socId = socId.ToUpper().Replace("0X", "");

                    // Try to construct ChipID if missing (logic from qctool.bat)
                    if (string.IsNullOrEmpty(chipId) && !string.IsNullOrEmpty(psn) && !string.IsNullOrEmpty(socId))
                    {
                        chipId = psn + socId;
                        // qctool checks length, we can just log it
                    }

                    // Lock state
                    string lockState = "Unknown";
                    if (output.Contains("Lock state: locked")) lockState = "Locked";
                    else if (output.Contains("Lock state: unlock")) lockState = "Unlocked";

                    Log("================ 设备信息 ================");
                    Log($"PSN:       {psn}");
                    Log($"SOC ID:    {socId}");
                    Log($"Chip ID:   {chipId}");
                    Log($"BL Lock:   {lockState}");
                    Log("==========================================");

                }
                catch (Exception ex)
                {
                    Log($"读取设备信息失败: {ex.Message}");
                }
            });
            SetUIBusy(false);
        }

        private string ParseLogValue(string log, string key)
        {
            // Simple parser: find key, read until end of line or next token
            // qctool uses 'tokens=7' etc.
            // Example: INFO: PSN: 123456
            try
            {
                int idx = log.IndexOf(key);
                if (idx == -1) return "";
                
                string sub = log.Substring(idx + key.Length).Trim();
                int endLine = sub.IndexOfAny(new[] { '\r', '\n' });
                if (endLine != -1) sub = sub.Substring(0, endLine);
                
                // Remove extra quotes or spaces
                return sub.Trim('\'', ' ', '\t');
            }
            catch { return ""; }
        }

        private void SwitchSlotBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.Button btn && btn.ContextMenu != null)
            {
                btn.ContextMenu.PlacementTarget = btn;
                btn.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
                btn.ContextMenu.IsOpen = true;
            }
        }

        private async void SlotMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is System.Windows.Controls.MenuItem item && item.Tag is string slot)
            {
                SetUIBusy(true);
                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port))
                {
                    SetUIBusy(false);
                    return;
                }

                await Task.Run(() =>
                {
                    try
                    {
                        Log($"正在切换到 Slot {slot.ToUpper()}...");
                        
                        // Determine value: A=1, B=2
                        string value = "0";
                        if (slot.ToLower() == "a") value = "1";
                        else if (slot.ToLower() == "b") value = "2";

                        using (var client = new FirehoseClient(port, Log))
                        {
                            if (client.SetBootableStorageDrive(int.Parse(value)))
                            {
                                Log($"成功发送切换 Slot {slot.ToUpper()} 命令 (LUN {value})。");
                                Log("请重启设备以生效。");
                            }
                            else
                            {
                                Log("切换 Slot 失败。");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"切换 Slot 失败: {ex.Message}");
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

        private async void WipeMenuItem_Click(object sender, RoutedEventArgs e)
        {
             if (sender is System.Windows.Controls.MenuItem item && item.Tag is string tag)
            {
                SetUIBusy(true);
                _cts = new CancellationTokenSource();
                var token = _cts.Token;

                string? port = await WaitForPortAsync();
                if (string.IsNullOrEmpty(port))
                {
                    SetUIBusy(false);
                    return;
                }

                await Task.Run(() =>
                {
                    try
                    {
                        using (var client = new FirehoseClient(port, Log))
                        {
                            if (token.IsCancellationRequested) return;

                            Log($"正在执行: {item.Header}...");
                            
                            // Ensure configured
                            RunConfigure(client);

                            if (tag == "EraseUserdata")
                            {
                                Log("正在读取 GPT 以定位 userdata...");
                                var parts = ReadGpt(client, "ufs", token);
                                if (token.IsCancellationRequested) return;

                                var userdata = parts.FirstOrDefault(p => p.Label.ToLower() == "userdata");
                                
                                if (userdata != null)
                                {
                                    if (client.Erase(userdata.Lun, long.Parse(userdata.StartSector), long.Parse(userdata.NumSectors)))
                                        Log("Userdata 擦除完成。");
                                    else
                                        Log("Userdata 擦除失败。");
                                }
                                else
                                {
                                    Log("未找到 userdata 分区。");
                                }
                            }
                            else
                            {
                                // Misc wipes (Oppo, Mi, etc.)
                                // We will erase the misc partition to reset it.
                                
                                Log("正在读取 GPT 以定位 misc...");
                                var parts = ReadGpt(client, "ufs", token);
                                if (token.IsCancellationRequested) return;

                                var misc = parts.FirstOrDefault(p => p.Label.ToLower() == "misc");
                                
                                if (misc != null)
                                {
                                    if (client.Erase(misc.Lun, long.Parse(misc.StartSector), long.Parse(misc.NumSectors)))
                                        Log($"Misc ({tag}) 擦除完成。");
                                    else
                                        Log("Misc 擦除失败。");
                                }
                                else
                                {
                                    Log("未找到 misc 分区。");
                                }
                            }
                            
                            client.Reset();
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"操作失败: {ex.Message}");
                    }
                });
                SetUIBusy(false);
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

        private async void RebootSystemBtn_Click(object sender, RoutedEventArgs e) => await PerformReboot("System");
        private async void RebootRecBtn_Click(object sender, RoutedEventArgs e) => await PerformReboot("Recovery");
        private async void RebootBootloaderBtn_Click(object sender, RoutedEventArgs e) => await PerformReboot("Bootloader");
        private async void RebootEdlBtn_Click(object sender, RoutedEventArgs e) => await PerformReboot("EDL");

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

        public long SizeInKB
        {
            get
            {
                if (double.TryParse(Size, out double s)) return (long)s;
                return 0;
            }
        }

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

