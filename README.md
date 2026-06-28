# 图片隐写加密工作台

面向 Windows 10 / Windows 11 的中文桌面隐写工具。项目采用 WPF / .NET 8 开发，支持在图片中嵌入加密文本或文件，并在嵌入前做载体适配性检测，只有通过门禁的图片才允许执行隐写。

## 主要能力

- 中文图形界面
- AES-256-GCM 认证加密
- ChaCha20-Poly1305 认证加密
- ML-KEM-1024 + AES-256-GCM 后量子接收者模式
- 载体图片适配性检测
- 仅在高纹理、高方差区域执行低占用嵌入
- 使用口令或接收者公钥指纹派生的散列布局分散写入位置
- 支持文本载荷与任意文件载荷
- 输出单文件 EXE 与带图标安装包

## 加密算法

本项目把图片隐写和载荷加密分层处理：隐写层负责降低可见性和直接分析特征，加密层负责防止载荷内容被破译。

当前支持三种配置：

| 配置 | 用途 | 说明 |
| --- | --- | --- |
| AES-256-GCM | 默认推荐 | 标准 AEAD 认证加密，兼容旧版 `PES2` 图片 |
| ChaCha20-Poly1305 | 强备选 | RFC 8439 定义的现代 AEAD 方案 |
| ML-KEM-1024 + AES-256-GCM | 后量子接收者模式 | 使用接收者公钥封装随机内容密钥，再用 AES-256-GCM 加密载荷 |

参考依据：

- [NIST SP 800-38D：GCM / GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 8439：ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
- [NIST FIPS 203：ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

## 后量子模式

ML-KEM 是密钥封装机制，不是直接加密图片或文件内容的算法。软件中的后量子模式采用混合设计：

1. 生成 ML-KEM-1024 公钥和私钥。
2. 发送方选择接收者公钥。
3. 软件随机生成内容加密密钥。
4. 用 ML-KEM-1024 封装内容密钥。
5. 用 AES-256-GCM 加密压缩后的载荷。
6. 接收方使用 ML-KEM 私钥提取并解封内容密钥。

私钥文件不会自动加口令保护，请离线妥善保存。私钥丢失后，后量子接收者模式图片中的载荷无法恢复。

## 高对抗隐写方案说明

本项目不是简单顺序 LSB，而是采用更保守的高对抗配置：

1. 先分析图片尺寸、纹理覆盖率、方差和梯度。
2. 不满足阈值的图片直接拒绝嵌入。
3. 只在强纹理块中启用低占用 LSB Matching。
4. 使用口令或接收者公钥指纹生成散列布局，打散实际写入位置。
5. 控制可用预算，避免载荷占用率过高。

这比普通 LSB 更难被直接分析，但不能承诺对专业隐写分析、取证设备或针对性样本对比绝对不可检测。

## 使用提示

- 隐写输出必须保持为 PNG。
- 不要把隐写输出重新保存为 JPEG。
- 优先使用纹理丰富的自然照片。
- 不建议使用大面积纯色、截图、扁平插画或经过强压缩的图片。
- 后量子模式需要公钥嵌入、私钥提取；普通密码无法提取后量子模式图片。

## 运行环境

- Windows 10 / Windows 11
- .NET 8 SDK（本地开发）
- GitHub Actions Windows Runner（云端构建）

## 项目结构

```text
PictureEncryptionApp/                WPF 应用源码
PictureEncryptionApp/Assets/         应用与安装包图标资源
PictureEncryptionApp/Services/       隐写与加解密核心逻辑
installer/PictureEncryptionApp.iss   Inno Setup 安装包脚本
.github/workflows/                   GitHub Actions 工作流
global.json                          .NET SDK 版本锁定
```

## 本地开发

构建：

```powershell
dotnet build .\PictureEncryptionApp\PictureEncryptionApp.csproj
```

发布单文件 EXE：

```powershell
dotnet publish .\PictureEncryptionApp\PictureEncryptionApp.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o .\Release\publish
```

## Git 分支约定

- 默认开发分支：`master`
- 当前仓库不再使用 `main`

## GitHub Actions 自动构建

工作流文件：

- [`.github/workflows/windows-package.yml`](./.github/workflows/windows-package.yml)

支持两种触发方式：

1. 手动触发 `workflow_dispatch`
2. 推送 `v*` 标签自动触发

当通过 `v*` 标签触发构建时，工作流会自动创建 GitHub Release，并上传：

- `PictureEncryptionApp.exe`
- `PictureEncryptionApp-Setup-<version>.exe`

## 安全声明

本项目提供的是增强型图片隐写和强加密封装方案，不是“绝对不可检测”或“绝对不可破解”的证明。攻击者如果取得弱密码、私钥文件、原始载体图、或可进行专业隐写检测，仍可能造成安全风险。
