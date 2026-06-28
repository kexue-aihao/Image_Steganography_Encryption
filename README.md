# 图片隐写加密工作台

面向 Windows 10 / Windows 11 的中文桌面隐写工具。项目采用 WPF 开发，支持在图片中嵌入加密文本或文件，并在嵌入前先做载体适配性检测，只有通过门禁的图片才允许执行隐写。

## 主要能力

- 中文图形界面
- AES-GCM 载荷加密
- 载体图片适配性检测
- 仅在高纹理、高方差区域执行嵌入
- 使用口令相关的随机散列布局分散写入位置
- 支持文本载荷与任意文件载荷
- 输出单文件 EXE 与带图标安装包

## 高对抗隐写方案说明

本项目不是简单顺序 LSB，而是采用更保守的高对抗配置：

1. 先分析图片尺寸、纹理覆盖率、方差和梯度。
2. 不满足阈值的图片直接拒绝嵌入。
3. 只在强纹理块中启用低占用 LSB Matching。
4. 使用口令和盐值生成散列布局，打散实际写入位置。
5. 控制可用预算，避免载荷占用率过高。

这比普通 LSB 更难被直接分析，但不能承诺对专业隐写分析或取证设备绝对不可检测。

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

说明：

- 隐写输出必须保持为 PNG。
- 不要再另存为 JPEG。
- 更适合使用纹理丰富的照片，不适合大面积纯色、截图、扁平插画。

## Git 分支约定

- 默认开发分支：`master`
- 当前仓库不再使用 `main`

## GitHub Actions 自动构建

工作流文件：

- [`.github/workflows/windows-package.yml`](./.github/workflows/windows-package.yml)

支持两种触发方式：

1. 手动触发 `workflow_dispatch`
2. 推送 `v*` 标签自动触发

### 手动触发

在 GitHub Actions 页面运行 `Windows Package`，并填写版本号，例如：

- `0.1.0`
- `0.1.0-rc1`

### 标签触发

当你希望通过打 tag 直接编译时，使用下面的流程：

```powershell
git checkout master
git pull origin master
git tag v0.1.0
git push origin master
git push origin v0.1.0
```

工作流会自动：

1. 检出源码
2. 安装 .NET 8 SDK
3. 构建 WPF 工程
4. 发布单文件 EXE
5. 安装 Inno Setup
6. 生成安装包
7. 上传构建产物

### 产物内容

工作流产物中包含：

- `PictureEncryptionApp.exe`
- `PictureEncryptionApp-Setup-<version>.exe`

## 安装包说明

安装包脚本位于：

- [`installer/PictureEncryptionApp.iss`](./installer/PictureEncryptionApp.iss)

安装包特性：

- 应用名称、快捷方式和安装目标为中文
- 安装程序图标与应用程序图标一致
- 默认安装到 `Program Files`
- 可选创建桌面快捷方式

## 安全声明

本项目提供的是增强型图片隐写方案，不是“绝对不可检测”的方案。对于专业隐写分析、取证设备或针对性样本对比，任何基于图片像素修改的隐写都存在被识别的可能。
