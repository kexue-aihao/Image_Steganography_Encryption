using Microsoft.Win32;
using PictureEncryptionApp.Services;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PictureEncryptionApp;

public partial class MainWindow : Window
{
    private CarrierAssessment? _currentAssessment;
    private string? _currentAssessmentPath;
    private bool _isBusy;

    public MainWindow()
    {
        InitializeComponent();
        InitializeViewState();
    }

    private void InitializeViewState()
    {
        EncryptionProfileComboBox.ItemsSource = PictureSteganographyService.SupportedEncryptionProfiles
            .Select(profile => new EncryptionProfileOption(profile))
            .ToList();
        EncryptionProfileComboBox.DisplayMemberPath = nameof(EncryptionProfileOption.DisplayName);
        EncryptionProfileComboBox.SelectedValuePath = nameof(EncryptionProfileOption.Profile);
        EncryptionProfileComboBox.SelectedValue = EncryptionProfile.Aes256Gcm;

        EmbedTextRadioButton.IsChecked = true;
        EmbedFilePanel.Visibility = Visibility.Collapsed;
        EmbedStatusTextBox.Text = "就绪。请选择载体图片，开始适配性分析。";
        EmbedAssessmentTextBox.Text = "只有载体通过自适应适配性门禁后，才能启用嵌入流程。";
        EmbedCapacityTextBlock.Text = "尚未选择载体图片。";
        EmbedSupportTextBlock.Text = "适配性门禁正在等待图片输入。";
        UpdateEncryptionProfileUi();
        ExtractPasswordRadioButton.IsChecked = true;
        ExtractPrivateKeyPanel.Visibility = Visibility.Collapsed;
        ExtractResultTextBox.Text = string.Empty;
        ExtractMetadataTextBlock.Text = "尚未开始提取。";
        ExtractOutputFolderTextBox.Text = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        UpdateEmbedActionState();
    }

    private void BrowseEmbedCarrierButton_Click(object sender, RoutedEventArgs e)
    {
        string? path = SelectFile("选择载体图片", "图片文件|*.png;*.bmp;*.jpg;*.jpeg;*.tif;*.tiff|所有文件|*.*");
        if (path is null)
        {
            return;
        }

        EmbedCarrierPathTextBox.Text = path;
        if (string.IsNullOrWhiteSpace(EmbedOutputPathTextBox.Text))
        {
            EmbedOutputPathTextBox.Text = BuildDefaultStegoOutputPath(path);
        }

        LoadPreview(path, EmbedPreviewImage);
        InvalidateCarrierAssessment();
        UpdateEmbedAssessment();
    }

    private void BrowseEmbedSecretFileButton_Click(object sender, RoutedEventArgs e)
    {
        string? path = SelectFile("选择秘密文件", "所有文件|*.*");
        if (path is null)
        {
            return;
        }

        EmbedSecretFilePathTextBox.Text = path;
        UpdateEmbedAssessment();
    }

    private void BrowseRecipientPublicKeyButton_Click(object sender, RoutedEventArgs e)
    {
        string? path = SelectFile("选择接收者 ML-KEM 公钥", "PEM 密钥|*.pem|所有文件|*.*");
        if (path is null)
        {
            return;
        }

        RecipientPublicKeyPathTextBox.Text = path;
        UpdateEmbedAssessment();
    }

    private void BrowseEmbedOutputButton_Click(object sender, RoutedEventArgs e)
    {
        string initialPath = string.IsNullOrWhiteSpace(EmbedOutputPathTextBox.Text)
            ? BuildDefaultStegoOutputPath(EmbedCarrierPathTextBox.Text)
            : EmbedOutputPathTextBox.Text;

        var dialog = new SaveFileDialog
        {
            Title = "保存隐写图片",
            Filter = "PNG 图片|*.png",
            FileName = Path.GetFileName(initialPath),
            InitialDirectory = GetExistingDirectory(initialPath),
            AddExtension = true,
            DefaultExt = ".png",
        };

        if (dialog.ShowDialog() == true)
        {
            EmbedOutputPathTextBox.Text = dialog.FileName;
        }
    }

    private async void EmbedActionButton_Click(object sender, RoutedEventArgs e)
    {
        if (!ValidateEmbedInputs(
                out string carrierPath,
                out EncryptionProfile encryptionProfile,
                out string password,
                out string? recipientPublicKeyPath,
                out string outputPath,
                out string? secretFilePath,
                out string? secretText,
                out long requiredContainerBytes))
        {
            return;
        }

        ToggleBusyState(isBusy: true);
        EmbedStatusTextBox.Text = "正在加密载荷并嵌入到自适应载体布局中...";

        try
        {
            EmbedResult result = await Task.Run(() =>
            {
                if (encryptionProfile == EncryptionProfile.MlKem1024Aes256Gcm)
                {
                    return secretFilePath is null
                        ? PictureSteganographyService.EmbedTextForRecipient(carrierPath, secretText!, recipientPublicKeyPath!, outputPath)
                        : PictureSteganographyService.EmbedFileForRecipient(carrierPath, secretFilePath, recipientPublicKeyPath!, outputPath);
                }

                return secretFilePath is null
                    ? PictureSteganographyService.EmbedText(carrierPath, secretText!, password, outputPath, encryptionProfile)
                    : PictureSteganographyService.EmbedFile(carrierPath, secretFilePath, password, outputPath, encryptionProfile);
            });

            EmbedStatusTextBox.Text =
                $"处理完成。{Environment.NewLine}" +
                $"输出文件：{result.OutputPath}{Environment.NewLine}" +
                $"加密算法：{PictureSteganographyService.GetEncryptionProfileDisplayName(result.EncryptionProfile)}{Environment.NewLine}" +
                $"载体评分：{result.Assessment.SecurityScore}/100{Environment.NewLine}" +
                $"已用自适应预算：{FormatBytes(requiredContainerBytes)} / 推荐 {FormatBytes(result.Assessment.RecommendedContainerBytes)}{Environment.NewLine}" +
                $"秘密数据大小：{FormatBytes(result.SecretBytes)}{Environment.NewLine}" +
                $"加密容器大小：{FormatBytes(result.EmbeddedPackageBytes)}{Environment.NewLine}" +
                "输出文件必须保持为 PNG 格式；若再次另存为 JPEG，隐藏数据通常会被破坏。";

            ExtractImagePathTextBox.Text = result.OutputPath;
            LoadPreview(result.OutputPath, ExtractPreviewImage);
            if (string.IsNullOrWhiteSpace(ExtractOutputFolderTextBox.Text))
            {
                ExtractOutputFolderTextBox.Text = Path.GetDirectoryName(result.OutputPath) ?? string.Empty;
            }
        }
        catch (Exception ex)
        {
            EmbedStatusTextBox.Text = $"处理失败：{ex.Message}";
        }
        finally
        {
            ToggleBusyState(isBusy: false);
        }
    }

    private async void GeneratePostQuantumKeysButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择 ML-KEM 密钥保存目录",
            InitialDirectory = GetExistingDirectory(EmbedOutputPathTextBox.Text),
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        ToggleBusyState(isBusy: true);
        EmbedStatusTextBox.Text = "正在生成 ML-KEM-1024 后量子密钥对...";

        try
        {
            PostQuantumKeyPairResult result = await Task.Run(() =>
                PictureSteganographyService.GenerateMlKem1024KeyPair(dialog.FolderName));

            RecipientPublicKeyPathTextBox.Text = result.PublicKeyPath;
            EmbedStatusTextBox.Text =
                $"ML-KEM-1024 密钥对已生成。{Environment.NewLine}" +
                $"公钥：{result.PublicKeyPath}{Environment.NewLine}" +
                $"私钥：{result.PrivateKeyPath}{Environment.NewLine}" +
                $"公钥指纹：{result.Fingerprint}{Environment.NewLine}" +
                $"公钥大小：{FormatBytes(result.PublicKeyBytes)}，私钥大小：{FormatBytes(result.PrivateKeyBytes)}{Environment.NewLine}" +
                "请妥善保存私钥；丢失私钥后无法提取后量子模式图片中的载荷。";
            UpdateEmbedAssessment();
        }
        catch (Exception ex)
        {
            EmbedStatusTextBox.Text = $"生成密钥失败：{ex.Message}";
        }
        finally
        {
            ToggleBusyState(isBusy: false);
        }
    }

    private void BrowseExtractImageButton_Click(object sender, RoutedEventArgs e)
    {
        string? path = SelectFile("选择隐写图片", "图片文件|*.png;*.bmp;*.jpg;*.jpeg;*.tif;*.tiff|所有文件|*.*");
        if (path is null)
        {
            return;
        }

        ExtractImagePathTextBox.Text = path;
        if (string.IsNullOrWhiteSpace(ExtractOutputFolderTextBox.Text))
        {
            ExtractOutputFolderTextBox.Text = Path.GetDirectoryName(path) ?? string.Empty;
        }

        LoadPreview(path, ExtractPreviewImage);
        ExtractMetadataTextBlock.Text = "隐写图片已载入，可以开始提取。";
    }

    private void BrowseExtractFolderButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择恢复文件保存目录",
            InitialDirectory = GetExistingDirectory(ExtractOutputFolderTextBox.Text),
        };

        if (dialog.ShowDialog() == true)
        {
            ExtractOutputFolderTextBox.Text = dialog.FolderName;
        }
    }

    private void BrowseExtractPrivateKeyButton_Click(object sender, RoutedEventArgs e)
    {
        string? path = SelectFile("选择接收者 ML-KEM 私钥", "PEM 密钥|*.pem|所有文件|*.*");
        if (path is null)
        {
            return;
        }

        ExtractPrivateKeyPathTextBox.Text = path;
    }

    private async void ExtractActionButton_Click(object sender, RoutedEventArgs e)
    {
        string imagePath = ExtractImagePathTextBox.Text.Trim();
        string password = ExtractPasswordBox.Password;
        string privateKeyPath = ExtractPrivateKeyPathTextBox.Text.Trim();
        bool usePrivateKey = ExtractPrivateKeyRadioButton.IsChecked == true;
        string outputFolder = string.IsNullOrWhiteSpace(ExtractOutputFolderTextBox.Text)
            ? (Path.GetDirectoryName(imagePath) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))
            : ExtractOutputFolderTextBox.Text.Trim();

        if (!File.Exists(imagePath))
        {
            ExtractMetadataTextBlock.Text = "请先选择有效的隐写图片。";
            return;
        }

        if (!usePrivateKey && string.IsNullOrWhiteSpace(password))
        {
            ExtractMetadataTextBlock.Text = "请输入嵌入时使用的密码。";
            return;
        }

        if (usePrivateKey && !File.Exists(privateKeyPath))
        {
            ExtractMetadataTextBlock.Text = "请选择有效的 ML-KEM 私钥文件。";
            return;
        }

        ToggleBusyState(isBusy: true);
        ExtractMetadataTextBlock.Text = "正在提取并解密隐藏载荷...";
        ExtractResultTextBox.Text = string.Empty;

        try
        {
            ExtractResult result = await Task.Run(() =>
                usePrivateKey
                    ? PictureSteganographyService.ExtractWithPrivateKey(imagePath, privateKeyPath, outputFolder)
                    : PictureSteganographyService.Extract(imagePath, password, outputFolder));

            if (result.PayloadKind == PayloadKind.Text)
            {
                ExtractMetadataTextBlock.Text =
                    $"提取完成。算法：{PictureSteganographyService.GetEncryptionProfileDisplayName(result.EncryptionProfile)}。载荷类型：文本。大小：{FormatBytes(result.DataBytes)}";
                ExtractResultTextBox.Text = result.TextContent ?? string.Empty;
            }
            else
            {
                ExtractMetadataTextBlock.Text =
                    $"提取完成。算法：{PictureSteganographyService.GetEncryptionProfileDisplayName(result.EncryptionProfile)}。载荷类型：文件。大小：{FormatBytes(result.DataBytes)}。已保存到：{result.SavedFilePath}";
                ExtractResultTextBox.Text =
                    $"恢复文件：{result.FileName}{Environment.NewLine}{result.SavedFilePath}";
            }
        }
        catch (Exception ex)
        {
            ExtractMetadataTextBlock.Text = $"处理失败：{ex.Message}";
            ExtractResultTextBox.Text = string.Empty;
        }
        finally
        {
            ToggleBusyState(isBusy: false);
        }
    }

    private void EmbedModeToggle_Checked(object sender, RoutedEventArgs e)
    {
        if (EmbedTextPanel is null || EmbedFilePanel is null)
        {
            return;
        }

        bool isTextMode = EmbedTextRadioButton.IsChecked == true;
        EmbedTextPanel.Visibility = isTextMode ? Visibility.Visible : Visibility.Collapsed;
        EmbedFilePanel.Visibility = isTextMode ? Visibility.Collapsed : Visibility.Visible;
        UpdateEmbedAssessment();
    }

    private void EmbedInputChanged(object sender, RoutedEventArgs e)
    {
        if (EmbedSecretTextBox is null || EmbedSupportTextBlock is null)
        {
            return;
        }

        UpdateEmbedAssessment();
    }

    private void EncryptionProfileComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PasswordModePanel is null)
        {
            return;
        }

        UpdateEncryptionProfileUi();
        UpdateEmbedAssessment();
    }

    private void ExtractModeToggle_Checked(object sender, RoutedEventArgs e)
    {
        if (ExtractPasswordPanel is null || ExtractPrivateKeyPanel is null)
        {
            return;
        }

        bool usePrivateKey = ExtractPrivateKeyRadioButton.IsChecked == true;
        ExtractPasswordPanel.Visibility = usePrivateKey ? Visibility.Collapsed : Visibility.Visible;
        ExtractPrivateKeyPanel.Visibility = usePrivateKey ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateEncryptionProfileUi()
    {
        EncryptionProfile profile = GetSelectedEncryptionProfile();
        bool isPostQuantum = profile == EncryptionProfile.MlKem1024Aes256Gcm;
        PasswordModePanel.Visibility = isPostQuantum ? Visibility.Collapsed : Visibility.Visible;
        RecipientPublicKeyPanel.Visibility = isPostQuantum ? Visibility.Visible : Visibility.Collapsed;
        EncryptionProfileDescriptionTextBlock.Text = profile switch
        {
            EncryptionProfile.Aes256Gcm => "标准认证加密模式，兼容旧版隐写图片；适合大多数场景。",
            EncryptionProfile.ChaCha20Poly1305 => "另一种现代 AEAD 方案，提供认证加密，适合作为 AES-GCM 的强备选。",
            EncryptionProfile.MlKem1024Aes256Gcm => "使用 ML-KEM-1024 封装随机内容密钥，再用 AES-256-GCM 加密载荷；提取时需要接收者私钥。",
            _ => string.Empty,
        };
    }

    private void UpdateEmbedAssessment()
    {
        string carrierPath = EmbedCarrierPathTextBox.Text.Trim();
        if (!File.Exists(carrierPath))
        {
            _currentAssessment = null;
            _currentAssessmentPath = null;
            EmbedCapacityTextBlock.Text = "尚未选择载体图片。";
            EmbedSupportTextBlock.Text = "适配性门禁正在等待图片输入。";
            EmbedSupportTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(15, 118, 110));
            EmbedAssessmentTextBox.Text = "当前高对抗隐写方案要求先输入一张具备足够纹理的图片，才能解锁嵌入。";
            UpdateEmbedActionState();
            return;
        }

        try
        {
            CarrierAssessment assessment = GetOrCreateAssessment(carrierPath);
            long requiredBytes = GetRequestedContainerBytes();
            bool hasPayload = requiredBytes > 0;
            bool capacityOk = !hasPayload || requiredBytes <= assessment.RecommendedContainerBytes;

            EmbedCapacityTextBlock.Text =
                $"图片尺寸：{assessment.Width} x {assessment.Height} | 合格纹理块：{assessment.EligibleBlockCount}/{assessment.TotalBlockCount} ({assessment.TextureCoverage:P0}) | 推荐容器预算：{FormatBytes(assessment.RecommendedContainerBytes)}";

            if (assessment.IsSupported && capacityOk)
            {
                EmbedSupportTextBlock.Text = $"适配性门禁：通过。安全评分 {assessment.SecurityScore}/100。";
                EmbedSupportTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(15, 118, 110));
            }
            else if (assessment.IsSupported)
            {
                EmbedSupportTextBlock.Text = $"适配性门禁：载体通过，但当前请求载荷超过推荐高对抗预算（{FormatBytes(requiredBytes)} > {FormatBytes(assessment.RecommendedContainerBytes)}）。";
                EmbedSupportTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(180, 83, 9));
            }
            else
            {
                EmbedSupportTextBlock.Text = $"适配性门禁：拒绝。安全评分 {assessment.SecurityScore}/100。";
                EmbedSupportTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            }

            EmbedAssessmentTextBox.Text = BuildAssessmentText(assessment, requiredBytes, capacityOk);
        }
        catch (Exception ex)
        {
            _currentAssessment = null;
            _currentAssessmentPath = null;
            EmbedCapacityTextBlock.Text = $"载体分析失败：{ex.Message}";
            EmbedSupportTextBlock.Text = "适配性门禁：不可用。";
            EmbedSupportTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(185, 28, 28));
            EmbedAssessmentTextBox.Text = "当前载体无法完成分析。";
        }

        UpdateEmbedActionState();
    }

    private CarrierAssessment GetOrCreateAssessment(string carrierPath)
    {
        if (_currentAssessment is not null && string.Equals(_currentAssessmentPath, carrierPath, StringComparison.OrdinalIgnoreCase))
        {
            return _currentAssessment;
        }

        _currentAssessment = PictureSteganographyService.InspectCarrier(carrierPath);
        _currentAssessmentPath = carrierPath;
        return _currentAssessment;
    }

    private string BuildAssessmentText(CarrierAssessment assessment, long requiredBytes, bool capacityOk)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"判定结果：{assessment.Verdict}");
        builder.AppendLine($"加密算法：{PictureSteganographyService.GetEncryptionProfileDisplayName(GetSelectedEncryptionProfile())}");
        builder.AppendLine($"安全评分：{assessment.SecurityScore}/100");
        builder.AppendLine($"自适应容量：{FormatBytes(assessment.AdaptiveCapacityBytes)}");
        builder.AppendLine($"推荐高对抗预算：{FormatBytes(assessment.RecommendedContainerBytes)}");
        builder.AppendLine($"合格区域平均方差：{assessment.AverageEligibleVariance:0.0}");
        builder.AppendLine($"合格区域平均梯度：{assessment.AverageEligibleGradient:0.0}");

        if (requiredBytes > 0)
        {
            builder.AppendLine($"当前请求加密容器：{FormatBytes(requiredBytes)}");
            builder.AppendLine(capacityOk
                ? "当前请求载荷落在锁定的低占用预算范围内。"
                : "当前请求载荷对于该载体而言过大，不符合高对抗配置。");
        }

        builder.Append(assessment.Guidance);
        return builder.ToString();
    }

    private long GetRequestedContainerBytes()
    {
        if (EmbedTextRadioButton.IsChecked == true)
        {
            string text = EmbedSecretTextBox.Text;
            return string.IsNullOrEmpty(text)
                ? 0
                : PictureSteganographyService.EstimateRequiredContainerBytes(
                    PayloadKind.Text,
                    fileName: null,
                    dataLength: Encoding.UTF8.GetByteCount(text),
                    GetSelectedEncryptionProfile());
        }

        string filePath = EmbedSecretFilePathTextBox.Text.Trim();
        return File.Exists(filePath)
            ? PictureSteganographyService.EstimateRequiredContainerBytes(
                PayloadKind.File,
                filePath,
                new FileInfo(filePath).Length,
                GetSelectedEncryptionProfile())
            : 0;
    }

    private bool ValidateEmbedInputs(
        out string carrierPath,
        out EncryptionProfile encryptionProfile,
        out string password,
        out string? recipientPublicKeyPath,
        out string outputPath,
        out string? secretFilePath,
        out string? secretText,
        out long requiredContainerBytes)
    {
        carrierPath = EmbedCarrierPathTextBox.Text.Trim();
        encryptionProfile = GetSelectedEncryptionProfile();
        password = EmbedPasswordBox.Password;
        recipientPublicKeyPath = null;
        outputPath = EnsurePngPath(EmbedOutputPathTextBox.Text.Trim(), carrierPath);
        secretFilePath = null;
        secretText = null;
        requiredContainerBytes = 0;

        if (!File.Exists(carrierPath))
        {
            EmbedStatusTextBox.Text = "请选择有效的载体图片。";
            return false;
        }

        CarrierAssessment assessment = GetOrCreateAssessment(carrierPath);
        if (!assessment.IsSupported)
        {
            EmbedStatusTextBox.Text = "该图片未通过适配性门禁。请改用更大、纹理更丰富的照片。";
            return false;
        }

        bool isPostQuantum = encryptionProfile == EncryptionProfile.MlKem1024Aes256Gcm;
        if (isPostQuantum)
        {
            recipientPublicKeyPath = RecipientPublicKeyPathTextBox.Text.Trim();
            if (!File.Exists(recipientPublicKeyPath))
            {
                EmbedStatusTextBox.Text = "后量子接收者模式需要选择有效的 ML-KEM 公钥文件。";
                return false;
            }
        }
        else if (string.IsNullOrWhiteSpace(password))
        {
            EmbedStatusTextBox.Text = "请输入密码。";
            return false;
        }

        if (!isPostQuantum && password != EmbedConfirmPasswordBox.Password)
        {
            EmbedStatusTextBox.Text = "两次输入的密码不一致。";
            return false;
        }

        if (EmbedTextRadioButton.IsChecked == true)
        {
            secretText = EmbedSecretTextBox.Text;
            if (string.IsNullOrEmpty(secretText))
            {
                EmbedStatusTextBox.Text = "请输入要嵌入的文本内容。";
                return false;
            }

            requiredContainerBytes = PictureSteganographyService.EstimateRequiredContainerBytes(
                PayloadKind.Text,
                fileName: null,
                dataLength: Encoding.UTF8.GetByteCount(secretText),
                encryptionProfile);
        }
        else
        {
            secretFilePath = EmbedSecretFilePathTextBox.Text.Trim();
            if (!File.Exists(secretFilePath))
            {
                EmbedStatusTextBox.Text = "请选择有效的秘密文件。";
                return false;
            }

            requiredContainerBytes = PictureSteganographyService.EstimateRequiredContainerBytes(
                PayloadKind.File,
                secretFilePath,
                new FileInfo(secretFilePath).Length,
                encryptionProfile);
        }

        if (requiredContainerBytes > assessment.RecommendedContainerBytes)
        {
            EmbedStatusTextBox.Text =
                $"当前请求载荷超过该图片的推荐高对抗预算（{FormatBytes(requiredContainerBytes)} > {FormatBytes(assessment.RecommendedContainerBytes)}）。";
            return false;
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            EmbedStatusTextBox.Text = "请选择输出路径。";
            return false;
        }

        EmbedOutputPathTextBox.Text = outputPath;
        return true;
    }

    private void ToggleBusyState(bool isBusy)
    {
        _isBusy = isBusy;
        GeneratePostQuantumKeysButton.IsEnabled = !isBusy;
        ExtractActionButton.IsEnabled = !isBusy;
        UpdateEmbedActionState();
    }

    private void UpdateEmbedActionState()
    {
        bool carrierSupported = _currentAssessment?.IsSupported == true;
        EmbedActionButton.IsEnabled = !_isBusy && carrierSupported;
    }

    private void InvalidateCarrierAssessment()
    {
        _currentAssessment = null;
        _currentAssessmentPath = null;
    }

    private EncryptionProfile GetSelectedEncryptionProfile()
    {
        return EncryptionProfileComboBox.SelectedValue is EncryptionProfile profile
            ? profile
            : EncryptionProfile.Aes256Gcm;
    }

    private static string? SelectFile(string title, string filter)
    {
        var dialog = new OpenFileDialog
        {
            Title = title,
            Filter = filter,
            CheckFileExists = true,
        };

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    private static string BuildDefaultStegoOutputPath(string? carrierPath)
    {
        if (string.IsNullOrWhiteSpace(carrierPath))
        {
            return string.Empty;
        }

        string directory = Path.GetDirectoryName(carrierPath) ?? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string baseName = Path.GetFileNameWithoutExtension(carrierPath);
        return Path.Combine(directory, $"{baseName}-stego.png");
    }

    private static string EnsurePngPath(string currentPath, string carrierPath)
    {
        if (string.IsNullOrWhiteSpace(currentPath))
        {
            return BuildDefaultStegoOutputPath(carrierPath);
        }

        return Path.ChangeExtension(currentPath, ".png");
    }

    private static string GetExistingDirectory(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            string directory = Directory.Exists(path)
                ? path
                : Path.GetDirectoryName(path) ?? string.Empty;

            if (Directory.Exists(directory))
            {
                return directory;
            }
        }

        return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    }

    private static string FormatBytes(long bytes)
    {
        string[] suffixes = ["B", "KB", "MB", "GB"];
        double size = bytes;
        int suffixIndex = 0;

        while (size >= 1024 && suffixIndex < suffixes.Length - 1)
        {
            size /= 1024;
            suffixIndex++;
        }

        return $"{size:0.##} {suffixes[suffixIndex]}";
    }

    private static void LoadPreview(string imagePath, Image imageControl)
    {
        using var stream = File.OpenRead(imagePath);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = stream;
        bitmap.EndInit();
        bitmap.Freeze();
        imageControl.Source = bitmap;
    }

    private sealed record EncryptionProfileOption(EncryptionProfile Profile)
    {
        public string DisplayName => PictureSteganographyService.GetEncryptionProfileDisplayName(Profile);
    }
}
