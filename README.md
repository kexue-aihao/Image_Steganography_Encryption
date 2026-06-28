# 图片隐写加密工作台

面向 Windows 10 / Windows 11 的桌面隐写工具，当前项目采用 WPF 开发，核心能力包括：

- 中文图形化界面
- AES-GCM 载荷加密
- 自适应载体适配性门禁
- 面向高对抗场景的低占用随机化 LSB Matching
- 支持文本和任意文件两种载荷

## 当前打包形态

当前仓库内提供的是源码工程，不是安装包。

- 应用程序主体：`PictureEncryptionApp`
- 应用图标：`E:\Picture_Encryption\PictureEncryptionApp\Assets\AppIcon.ico`
- 安装包脚本：`E:\Picture_Encryption\installer\PictureEncryptionApp.iss`
- GitHub Actions 工作流：`E:\Picture_Encryption\.github\workflows\windows-package.yml`

本次已按你的要求把“发布编译”留给 GitHub 工作流处理，本机不执行正式发布。

## 高对抗隐写方案说明

当前方案不是简单顺序 LSB，而是增加了以下限制与增强：

- 先分析图片是否适合作为载体
- 只有通过门禁的图片才能继续嵌入
- 只在高纹理、高方差区域写入
- 使用口令相关的散列打乱写入位置
- 控制载荷占用率，限制在保守预算内

这比普通 LSB 更难被直接分析，但不能承诺对专业隐写分析设备绝对不可检测。

## 本地开发构建

```powershell
dotnet build .\PictureEncryptionApp\PictureEncryptionApp.csproj
```

## GitHub Actions 打包

已配置手动触发工作流：

- 工作流名称：`Windows Package`
- 触发方式：`workflow_dispatch`
- 输入参数：`app_version`

工作流会执行以下步骤：

1. 检出仓库
2. 安装 .NET 8 SDK
3. 还原并构建 WPF 工程
4. 发布单文件 EXE
5. 安装 Inno Setup
6. 编译带图标的安装包
7. 上传 EXE 与安装包产物

## 说明

- 隐写输出必须保持为 PNG。
- 不要再另存为 JPEG。
- 更适合使用纹理丰富的照片，不适合大面积纯色、截图、扁平插画。
- 未通过门禁的图片会被禁止执行隐写嵌入。
