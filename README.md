# OPLUS EDL Tool 2.0

这是一个基于 C# WPF 开发的高通 (Qualcomm) EDL/Firehose 刷机工具，专为 OnePlus 和 OPPO 设备优化，同时也支持通用的高通设备。

## 主要功能

### 1. 分区管理
*   **读取分区表 (Read GPT)**: 自动识别存储类型 (UFS/eMMC) 和扇区大小 (4096/512)，列出所有分区信息。
*   **读写擦除**:
    *   **读取 (Read)**: 备份指定分区到本地文件。支持批量读取。
    *   **写入 (Write)**: 将本地镜像文件刷入指定分区。
    *   **擦除 (Erase)**: 格式化/擦除指定分区数据。
*   **XML 生成**: 读取分区时，自动根据 LUN 生成标准的 `rawprogram0.xml`, `rawprogram1.xml` 等，可直接用于 QFIL 刷机。

### 2. 设备交互
*   **Firehose 协议**: 内置原生 Firehose 客户端，支持 Configure, Peek, Poke 等命令。
*   **握手验证**:
    *   支持发送 Programmer (Loader)。
    *   **OPLUS 验证**: 支持 OPPO/OnePlus 特有的 VIP 验证和 Oplus 验证模式 (需配合 `oplus_test` 文件夹)。
*   **设备信息**: 读取存储芯片信息 (UFS/eMMC Info)。

### 3. 高级功能
*   **多 LUN 支持**: 完美支持 UFS 多 LUN 架构 (LUN0 - LUN5)。
*   **槽位切换**: 支持 A/B 分区槽位切换 (Set Active Slot)。
*   **重启控制**: 支持重启到 System, Recovery, Bootloader, EDL, FastbootD 等模式。
*   **QFIL 兼容**: 支持加载官方 `rawprogram.xml` 和 `patch.xml` 进行刷机。

## 使用说明

1.  **连接设备**: 将手机进入 EDL 模式 (9008) 并连接电脑。
2.  **选择端口**: 点击“刷新设备”并选择对应的 COM 端口。
3.  **加载引导**:
    *   在“引导路径”中选择对应的 `.elf` 或 `.melf` Firehose Programmer。
    *   勾选“发送引导” (Send Loader)。
4.  **读取分区**: 点击“读取分区表”获取设备分区布局。
5.  **执行操作**:
    *   在列表中勾选需要操作的分区。
    *   点击“读取”、“写入”或“擦除”按钮执行操作。

## 开发环境

*   **语言**: C# (.NET 6.0 / .NET 8.0)
*   **框架**: WPF (Windows Presentation Foundation)
*   **依赖**:
    *   无需外部 `fh_loader.exe`，核心逻辑已原生实现。
    *   部分特殊功能可能依赖 `QSaharaServer.exe` (可选)。

## 注意事项

*   本工具涉及底层分区操作，请谨慎使用。
*   擦除关键分区 (如 xbl, abl, boot) 可能导致设备无法启动。
*   OPLUS 验证功能需要对应的验证文件 (Digest/Signature)。
