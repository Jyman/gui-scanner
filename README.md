# 系统危险排查 

一款基于 Python + CustomTkinter 的 Windows 系统安全扫描工具，专注于检测常见的恶意软件持久化手段和异常状态。提供现代化图形界面、HTML 报告导出，以及单文件 exe 打包分发。

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.12+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 截图

启动后默认显示统计卡片和扫描结果列表。左侧导航选择具体模块，或点击「全 部 扫 描」执行完整检查。

---

## 功能特性

### 十个内置扫描模块

| # | 模块 | 检测内容 |
|---|------|---------|
| 1 | 🔍 隐藏进程扫描 | 运行进程的可执行文件带有 Hidden / System 文件属性 |
| 2 | 📋 注册表启动项 | `HKLM/HKCU` 的 `Run` / `RunOnce` 各路径，含 WOW64 |
| 3 | ⏱ 计划任务扫描 | 非 Microsoft 路径下的计划任务，标记隐藏任务 |
| 4 | ⚙ 服务异常检测 | 非标准路径、用户目录、临时目录下的服务可执行文件 |
| 5 | 🔗 WMI 持久化 | `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` |
| 6 | 🧬 DLL 注入检测 | 系统关键进程加载的非信任目录 DLL（含浏览器进程） |
| 7 | 🌐 网络连接检查 | 异常外连：可疑进程发起、高危端口、ESTABLISHED 状态 |
| 8 | 📡 Hosts 文件检查 | hosts 文件中安全敏感域名被劫持、loopback 重定向 |
| 9 | 🧩 浏览器扩展 | Chrome / Edge / Brave / Firefox 全部扩展枚举，高权限标红 |
| 10 | 💠 PowerShell 持久化 | profile 文件中的 `IEX`、Base64、Defender 排除等可疑模式 |

每条结果按严重等级分类：**安全 / 可疑 / 危险**，对应绿 / 琥珀 / 红三色。

### 用户界面

- **Soft Paper 浅色主题**，护眼柔和配色
- **侧栏导航**：点击模块仅扫描该项；右下角「全部扫描」一键检测全部
- **可点击筛选卡片**：顶部统计卡（总数 / 安全 / 可疑 / 危险）点击后按等级筛选，再点取消
- **结果行右键菜单**：
  - 复制名称 / 详情 / 路径
  - 打开所在文件夹（自动定位文件）
  - 在 VirusTotal 搜索
  - 加入 / 移出白名单
- **行悬停高亮**，列表选中状态清晰可见
- **HTML 报告**：一键导出到桌面，独立可分享

### 白名单系统

- 已确认安全的项目可加入本地白名单，存储于 `%LOCALAPPDATA%\yinhu\whitelist.json`
- 加入后该项在所有未来扫描中自动降级为 **安全**，详情末尾标注 `[白名单]`
- 通过右键菜单随时移出

### 管理员权限处理

- 启动时自动检测；非管理员模式下显示橙色横幅，提示部分检测结果可能不完整
- 横幅内置「重启提权」按钮，一键 UAC 重启
- 也可在不提权的受限模式下使用（不会强制弹 UAC）

### 单文件 exe

- PyInstaller 打包为单一 `yinhu.exe`（约 18 MB）
- 内嵌自定义图标（盾牌 + 放大镜 + 对勾）
- 自带 UAC 管理员清单（双击运行触发权限请求）
- 可拷贝到任意 Windows 机器直接运行，无需 Python 环境

---

## 快速开始

### 方式 A：直接运行 exe（推荐）

下载 `dist/yinhu.exe`，双击即可，会自动请求管理员权限。

### 方式 B：源码运行

依赖：[uv](https://docs.astral.sh/uv/) 包管理器。

```bash
# 克隆仓库
git clone https://github.com/Jyman/gui-scanner.git
cd gui-scanner

# 安装依赖
uv sync

# 启动 GUI
uv run python -m yinhu
```

Windows 用户路径含中文时，使用项目根目录的 `run.bat` 启动可绕过 GBK 编码问题。

### 方式 C：自行打包 exe

```bash
uv add --dev pyinstaller
uv run python -m PyInstaller yinhu.spec --clean --noconfirm
```

打包产物在 `dist/yinhu.exe`。

---

## 项目结构

```
.
├── src/yinhu/
│   ├── __main__.py            # 入口
│   ├── app.py                 # 启动流程 + 管理员检测
│   ├── whitelist.py           # 白名单持久化
│   ├── ui/
│   │   ├── main_window.py     # 主窗口
│   │   ├── scan_panel.py      # 结果列表
│   │   ├── context_menu.py    # 自定义右键菜单
│   │   └── theme.py           # 配色与字体
│   ├── scanners/
│   │   ├── base.py            # Scanner / ScanResult / Severity
│   │   ├── process.py
│   │   ├── registry.py
│   │   ├── tasks.py
│   │   ├── services.py
│   │   ├── wmi.py
│   │   ├── dll_injection.py
│   │   ├── network.py
│   │   ├── hosts.py
│   │   ├── browser_extensions.py
│   │   └── powershell_profile.py
│   └── report/html_export.py  # HTML 报告生成
├── assets/yinhu.ico           # 应用图标（多分辨率）
├── generate_icon.py           # 图标生成脚本
├── yinhu.spec                 # PyInstaller 配置
├── hidden_scanner.ps1         # 原始 PowerShell 脚本（参考）
├── run.bat                    # Windows 启动器
├── pyproject.toml
└── README.md
```

---

## 检测能力详解

### 隐藏进程扫描
枚举所有运行进程，读取可执行文件的 NTFS 属性（`FILE_ATTRIBUTE_HIDDEN` / `FILE_ATTRIBUTE_SYSTEM`）。带任一属性的进程标为 **危险**，其余为 **安全**。

### 注册表启动项
覆盖六条经典自启动路径：
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` / `RunOnce`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` / `RunOnce`
- `HKLM\SOFTWARE\WOW6432Node\...\Run` / `RunOnce`

解析每条值的目标可执行路径（支持引号、环境变量、`PATH` 查找），并检查文件属性。

### 计划任务
通过 PowerShell 调用 `Get-ScheduledTask`，过滤 Microsoft 内置任务路径，剩余的标为 **可疑**，含明确隐藏标记的标为 **危险**。

### 服务异常
列出 Win32 服务，识别可执行路径不在 `C:\Windows`、`C:\Program Files`、`C:\Program Files (x86)` 下的服务（如 `AppData`、`Temp`、`Users` 子目录），按位置敏感度评级。

### WMI 持久化
查询 `root\subscription` 命名空间下的 `__EventFilter`、`__EventConsumer` 和 `__FilterToConsumerBinding`。任何非默认条目都标为 **危险**，因为这是经典的 fileless 后门手法。

### DLL 注入检测
对 `explorer.exe`、`lsass.exe`、`svchost.exe`、`chrome.exe`、`msedge.exe` 等关键进程枚举已加载模块，标记非系统目录、非 Program Files 的 DLL。

### 网络连接
通过 `psutil` 列出所有 `ESTABLISHED` 状态的网络连接，标记：
- 由 `powershell.exe`、`rundll32.exe`、`mshta.exe`、`certutil.exe` 等可疑进程发起的连接（**危险**）
- 目标端口为 4444、5555、6666、31337、1080 等已知后门端口（**危险**）
- 外部公网 IP 连接（**可疑**）

### Hosts 文件
解析 `C:\Windows\System32\drivers\etc\hosts`，对包含安全软件域名、微软更新域名、流行网站的条目标红，特别警惕重定向到 `127.0.0.1` 的劫持行为。

### 浏览器扩展
读取 Chromium 系（Chrome / Edge / Brave / Chromium）的 `User Data\<profile>\Extensions` 目录下所有扩展 manifest，以及 Firefox 的 `extensions.json`。请求 `<all_urls>`、`tabs`、`webRequest`、`cookies`、`debugger` 等高权限的扩展标为 **可疑**。

### PowerShell Profile
检查 `Documents\WindowsPowerShell\` 和 `Documents\PowerShell\` 下的 profile 文件，正则匹配：
- `IEX` / `Invoke-Expression`（动态执行）
- Base64 编码命令
- `Add-MpPreference ExclusionPath`（绕过 Defender）
- `Set-MpPreference -Disable*`（禁用 Defender）
- `Register-ScheduledTask`、注册表自启动写入等

任一命中即标为 **危险**。

---

## HTML 报告

点击侧栏底部「导出报告」生成 HTML 文件到桌面，文件名格式：`system_threat_report_<时间戳>.html`。报告包含：
- 顶部统计卡片
- 按等级颜色分组的完整结果表格
- 来源、名称、详情三列

---

## 技术栈

- **Python 3.12+**
- **CustomTkinter** — 现代化 Tk UI 框架
- **psutil** — 跨平台进程 / 网络枚举
- **Pillow** — 图标生成
- **PyInstaller** — exe 打包
- 标准库：`winreg`、`subprocess`、`ctypes`（管理员检测）

---

## 已知限制

- 仅支持 Windows，依赖 `winreg`、Windows API
- 部分检测项需要管理员权限（如 WMI、服务、网络连接），受限模式下数据可能不完整
- DLL 注入检测基于启发式规则（路径白名单），并非真正的内存扫描，可能漏报伪装良好的注入
- HTML 报告未做加密处理，包含本机系统信息，请勿随意分享

---

## 路线图

- [ ] 扫描进度条与可中断扫描
- [ ] 定时计划扫描（开机后台运行）
- [ ] 一键处置：终止进程、删除启动项、隔离文件
- [ ] 数字签名检查（验证可执行文件签名状态）
- [ ] 扫描历史对比（新增持久化项告警）
- [ ] Sigma 规则导入

欢迎 issue / PR。

---

## License

MIT

---

## 友情链接

- [LINUX DO](https://linux.do/)
