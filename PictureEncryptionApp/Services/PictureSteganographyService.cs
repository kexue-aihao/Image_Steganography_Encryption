using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PictureEncryptionApp.Services;

public enum PayloadKind : byte
{
    Text = 1,
    File = 2,
}

public sealed record CarrierAssessment(
    int Width,
    int Height,
    bool IsSupported,
    int SecurityScore,
    long TotalCapacityBytes,
    long AdaptiveCapacityBytes,
    long RecommendedContainerBytes,
    int EligibleBlockCount,
    int TotalBlockCount,
    double TextureCoverage,
    double AverageEligibleVariance,
    double AverageEligibleGradient,
    string Verdict,
    string Guidance);

public sealed record EmbedResult(
    string OutputPath,
    CarrierAssessment Assessment,
    PayloadKind PayloadKind,
    long SecretBytes,
    long EmbeddedPackageBytes);

public sealed record ExtractResult(
    PayloadKind PayloadKind,
    string? FileName,
    long DataBytes,
    string? TextContent,
    string? SavedFilePath);

public static class PictureSteganographyService
{
    private const int HeaderSize = 32;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int Pbkdf2Iterations = 350_000;
    private const byte CurrentVersion = 2;
    private const int BlockSize = 8;
    private const int MinimumDimension = 512;
    private const int MinimumRecommendedContainerBytes = 2_048;
    private const int MinimumEligibleBlocks = 64;
    private const double MinimumTextureCoverage = 0.18;
    private const double MinimumEligibleVariance = 90.0;
    private const double MinimumEligibleGradient = 14.0;
    private const double RecommendedUtilizationRatio = 0.18;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("PES2");

    public static CarrierAssessment InspectCarrier(string imagePath)
    {
        var bitmap = LoadBitmap(imagePath);
        return AnalyzeCarrier(bitmap);
    }

    public static long EstimateRequiredContainerBytes(PayloadKind payloadKind, string? fileName, long dataLength)
    {
        if (dataLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(dataLength));
        }

        int fileNameBytes = payloadKind == PayloadKind.File && !string.IsNullOrWhiteSpace(fileName)
            ? Encoding.UTF8.GetByteCount(Path.GetFileName(fileName))
            : 0;

        long plainPayloadBytes = 1 + 1 + 2 + 8 + fileNameBytes + dataLength;
        long compressionAllowance = Math.Max(96, plainPayloadBytes / 100);
        return HeaderSize + NonceSize + TagSize + plainPayloadBytes + compressionAllowance;
    }

    public static EmbedResult EmbedText(string carrierImagePath, string text, string password, string outputPath)
    {
        if (string.IsNullOrEmpty(text))
        {
            throw new InvalidOperationException("文本载荷不能为空。");
        }

        return EmbedInternal(
            carrierImagePath,
            PayloadKind.Text,
            fileName: null,
            data: Encoding.UTF8.GetBytes(text),
            password,
            outputPath);
    }

    public static EmbedResult EmbedFile(string carrierImagePath, string secretFilePath, string password, string outputPath)
    {
        if (!File.Exists(secretFilePath))
        {
            throw new FileNotFoundException("未找到秘密文件。", secretFilePath);
        }

        return EmbedInternal(
            carrierImagePath,
            PayloadKind.File,
            Path.GetFileName(secretFilePath),
            File.ReadAllBytes(secretFilePath),
            password,
            outputPath);
    }

    public static ExtractResult Extract(string stegoImagePath, string password, string outputDirectory)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("密码不能为空。");
        }

        if (!File.Exists(stegoImagePath))
        {
            throw new FileNotFoundException("未找到隐写图片。", stegoImagePath);
        }

        var bitmap = LoadBitmap(stegoImagePath);
        CandidateLayout layout = BuildCandidateLayout(bitmap);
        if (layout.CandidateByteIndices.Length < HeaderSize * 8)
        {
            throw new InvalidOperationException("该图片未提供足够的自适应载体位置，无法容纳有效头部信息。");
        }

        byte[] header = ReadCandidateBits(bitmap.Pixels, layout.CandidateByteIndices, HeaderSize, candidateStartIndex: 0);
        ValidateHeader(header, layout.CandidateByteIndices.Length, out var salt, out int encryptedPackageLength);

        byte[] encryptedPackage = ReadScatteredCandidateBits(
            bitmap.Pixels,
            layout.CandidateByteIndices,
            encryptedPackageLength,
            headerBitCount: HeaderSize * 8,
            password,
            salt);

        if (encryptedPackageLength < NonceSize + TagSize)
        {
            throw new InvalidOperationException("嵌入容器不完整。");
        }

        byte[] nonce = encryptedPackage.AsSpan(0, NonceSize).ToArray();
        byte[] tag = encryptedPackage.AsSpan(NonceSize, TagSize).ToArray();
        byte[] ciphertext = encryptedPackage.AsSpan(NonceSize + TagSize).ToArray();

        byte[] key = DeriveAesKey(password, salt);
        try
        {
            byte[] compressedPayload = new byte[ciphertext.Length];
            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Decrypt(nonce, ciphertext, tag, compressedPayload);
            }

            byte[] plainPayload = Decompress(compressedPayload);
            return DecodePayload(plainPayload, outputDirectory);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("密码校验失败，或隐藏载荷已经损坏。", ex);
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidOperationException("载荷解压失败。图片可能在嵌入后被修改过。", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static EmbedResult EmbedInternal(
        string carrierImagePath,
        PayloadKind payloadKind,
        string? fileName,
        byte[] data,
        string password,
        string outputPath)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("密码不能为空。");
        }

        var bitmap = LoadBitmap(carrierImagePath);
        CandidateLayout layout = BuildCandidateLayout(bitmap);
        CarrierAssessment assessment = layout.Assessment;
        if (!assessment.IsSupported)
        {
            throw new InvalidOperationException("该图片未通过自适应适配性门禁。");
        }

        byte[] plainPayload = BuildPlainPayload(payloadKind, fileName, data);
        byte[] compressedPayload = Compress(plainPayload);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] key = DeriveAesKey(password, salt);

        byte[] ciphertext = new byte[compressedPayload.Length];
        byte[] tag = new byte[TagSize];

        try
        {
            using (var aes = new AesGcm(key, TagSize))
            {
                aes.Encrypt(nonce, compressedPayload, ciphertext, tag);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        byte[] encryptedPackage = BuildEncryptedPackage(nonce, tag, ciphertext);
        byte[] header = BuildHeader(salt, encryptedPackage.Length, layout.CandidateByteIndices.Length);
        long requiredContainerBytes = header.Length + encryptedPackage.Length;

        if (requiredContainerBytes > assessment.RecommendedContainerBytes)
        {
            throw new InvalidOperationException(
                $"当前请求载荷超过允许的高对抗载体预算（{FormatBytes(requiredContainerBytes)} > {FormatBytes(assessment.RecommendedContainerBytes)}）。");
        }

        long totalBitsRequired = (long)requiredContainerBytes * 8L;
        if (totalBitsRequired > layout.CandidateByteIndices.Length)
        {
            throw new InvalidOperationException(
                $"自适应载体容量不足。需要 {FormatBytes(requiredContainerBytes)}，当前可用 {FormatBytes(assessment.AdaptiveCapacityBytes)}。");
        }

        var adjustmentBits = DeterministicBitSource.Create(password, salt, "adjust-v2");
        WriteCandidateBitsMatching(bitmap.Pixels, layout.CandidateByteIndices, header, candidateStartIndex: 0, adjustmentBits);
        WriteScatteredCandidateBitsMatching(
            bitmap.Pixels,
            layout.CandidateByteIndices,
            encryptedPackage,
            headerBitCount: HeaderSize * 8,
            password,
            salt,
            adjustmentBits);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        SaveAsPng(bitmap, outputPath);

        return new EmbedResult(
            outputPath,
            assessment,
            payloadKind,
            data.LongLength,
            requiredContainerBytes);
    }

    private static byte[] BuildPlainPayload(PayloadKind payloadKind, string? fileName, byte[] data)
    {
        byte[] fileNameBytes = payloadKind == PayloadKind.File && !string.IsNullOrWhiteSpace(fileName)
            ? Encoding.UTF8.GetBytes(Path.GetFileName(fileName))
            : Array.Empty<byte>();

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write((byte)payloadKind);
        writer.Write((byte)0);
        writer.Write((ushort)fileNameBytes.Length);
        writer.Write((long)data.Length);
        writer.Write(fileNameBytes);
        writer.Write(data);
        writer.Flush();
        return stream.ToArray();
    }

    private static ExtractResult DecodePayload(byte[] plainPayload, string outputDirectory)
    {
        using var stream = new MemoryStream(plainPayload);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: false);

        PayloadKind payloadKind = (PayloadKind)reader.ReadByte();
        _ = reader.ReadByte();
        ushort fileNameLength = reader.ReadUInt16();
        long dataLength = reader.ReadInt64();

        if (dataLength < 0 || dataLength > int.MaxValue)
        {
            throw new InvalidOperationException("嵌入载荷长度无效。");
        }

        byte[] fileNameBytes = reader.ReadBytes(fileNameLength);
        if (fileNameBytes.Length != fileNameLength)
        {
            throw new InvalidOperationException("嵌入载荷元数据不完整。");
        }

        byte[] data = reader.ReadBytes((int)dataLength);
        if (data.Length != dataLength)
        {
            throw new InvalidOperationException("嵌入载荷正文不完整。");
        }

        string fileName = fileNameBytes.Length == 0 ? string.Empty : Encoding.UTF8.GetString(fileNameBytes);

        if (payloadKind == PayloadKind.Text)
        {
            return new ExtractResult(
                payloadKind,
                fileName,
                data.LongLength,
                Encoding.UTF8.GetString(data),
                null);
        }

        Directory.CreateDirectory(outputDirectory);
        string safeFileName = GetSafeFileName(fileName);
        string savedPath = GetUniqueOutputPath(outputDirectory, safeFileName);
        File.WriteAllBytes(savedPath, data);
        return new ExtractResult(payloadKind, safeFileName, data.LongLength, null, savedPath);
    }

    private static string GetSafeFileName(string? fileName)
    {
        string safeFileName = string.IsNullOrWhiteSpace(fileName) ? "隐藏数据.bin" : Path.GetFileName(fileName);
        return string.IsNullOrWhiteSpace(safeFileName) ? "隐藏数据.bin" : safeFileName;
    }

    private static string GetUniqueOutputPath(string directory, string fileName)
    {
        string baseName = Path.GetFileNameWithoutExtension(fileName);
        string extension = Path.GetExtension(fileName);
        string candidate = Path.Combine(directory, fileName);
        int suffix = 1;

        while (File.Exists(candidate))
        {
            candidate = Path.Combine(directory, $"{baseName} ({suffix}){extension}");
            suffix++;
        }

        return candidate;
    }

    private static byte[] BuildEncryptedPackage(byte[] nonce, byte[] tag, byte[] ciphertext)
    {
        byte[] package = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(package.AsSpan(0, NonceSize));
        tag.CopyTo(package.AsSpan(NonceSize, TagSize));
        ciphertext.CopyTo(package.AsSpan(NonceSize + TagSize));
        return package;
    }

    private static byte[] BuildHeader(byte[] salt, int encryptedPackageLength, int candidateCount)
    {
        byte[] header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        header[4] = CurrentVersion;
        header[5] = BlockSize;
        header[6] = 1;
        salt.CopyTo(header.AsSpan(8, SaltSize));
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(24, sizeof(int)), encryptedPackageLength);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(28, sizeof(int)), candidateCount);
        return header;
    }

    private static void ValidateHeader(byte[] header, int candidateCount, out byte[] salt, out int encryptedPackageLength)
    {
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new InvalidOperationException("在该图片中未找到有效的自适应隐写标记。");
        }

        if (header[4] != CurrentVersion)
        {
            throw new InvalidOperationException($"不支持的隐写配置版本：{header[4]}。");
        }

        if (header[5] != BlockSize)
        {
            throw new InvalidOperationException("载体布局配置与当前自适应引擎不匹配。");
        }

        salt = header.AsSpan(8, SaltSize).ToArray();
        encryptedPackageLength = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(24, sizeof(int)));
        int recordedCandidateCount = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(28, sizeof(int)));

        if (encryptedPackageLength <= 0)
        {
            throw new InvalidOperationException("嵌入容器长度无效。");
        }

        if (recordedCandidateCount != candidateCount)
        {
            throw new InvalidOperationException("嵌入后载体适配性指纹发生变化，图片很可能被变换或重新压缩过。");
        }

        int remainingCandidateBits = candidateCount - (HeaderSize * 8);
        if ((long)encryptedPackageLength * 8L > remainingCandidateBits)
        {
            throw new InvalidOperationException("嵌入容器长度超过自适应载体布局上限。");
        }
    }

    private static byte[] DeriveAesKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32);
    }

    private static byte[] Compress(byte[] input)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(input);
        }

        return output.ToArray();
    }

    private static byte[] Decompress(byte[] input)
    {
        using var inputStream = new MemoryStream(input);
        using var deflate = new DeflateStream(inputStream, CompressionMode.Decompress, leaveOpen: false);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }

    private static void WriteCandidateBitsMatching(
        byte[] pixels,
        int[] candidateByteIndices,
        byte[] data,
        int candidateStartIndex,
        DeterministicBitSource adjustmentBits)
    {
        for (long bitIndex = 0; bitIndex < (long)data.Length * 8L; bitIndex++)
        {
            int candidateIndex = checked(candidateStartIndex + (int)bitIndex);
            int desiredBit = GetBit(data, bitIndex);
            ApplyLsbMatching(pixels, candidateByteIndices[candidateIndex], desiredBit, adjustmentBits);
        }
    }

    private static byte[] ReadCandidateBits(
        byte[] pixels,
        int[] candidateByteIndices,
        int byteCount,
        int candidateStartIndex)
    {
        byte[] data = new byte[byteCount];

        for (long bitIndex = 0; bitIndex < (long)byteCount * 8L; bitIndex++)
        {
            int candidateIndex = checked(candidateStartIndex + (int)bitIndex);
            int bit = pixels[candidateByteIndices[candidateIndex]] & 0x01;
            SetBit(data, bitIndex, bit);
        }

        return data;
    }

    private static void WriteScatteredCandidateBitsMatching(
        byte[] pixels,
        int[] candidateByteIndices,
        byte[] data,
        int headerBitCount,
        string password,
        byte[] salt,
        DeterministicBitSource adjustmentBits)
    {
        int remainingCandidates = candidateByteIndices.Length - headerBitCount;
        long requiredBits = (long)data.Length * 8L;
        if (requiredBits > remainingCandidates)
        {
            throw new InvalidOperationException("嵌入容器超过自适应载体布局上限。");
        }

        var permutation = CreateScatterPermutation(password, salt, remainingCandidates);

        for (long bitIndex = 0; bitIndex < requiredBits; bitIndex++)
        {
            int candidateIndex = headerBitCount + permutation.GetPosition(bitIndex);
            int desiredBit = GetBit(data, bitIndex);
            ApplyLsbMatching(pixels, candidateByteIndices[candidateIndex], desiredBit, adjustmentBits);
        }
    }

    private static byte[] ReadScatteredCandidateBits(
        byte[] pixels,
        int[] candidateByteIndices,
        int byteCount,
        int headerBitCount,
        string password,
        byte[] salt)
    {
        int remainingCandidates = candidateByteIndices.Length - headerBitCount;
        long requiredBits = (long)byteCount * 8L;
        if (requiredBits > remainingCandidates)
        {
            throw new InvalidOperationException("嵌入容器超过当前可用的自适应载体布局上限。");
        }

        var permutation = CreateScatterPermutation(password, salt, remainingCandidates);
        byte[] data = new byte[byteCount];

        for (long bitIndex = 0; bitIndex < requiredBits; bitIndex++)
        {
            int candidateIndex = headerBitCount + permutation.GetPosition(bitIndex);
            int bit = pixels[candidateByteIndices[candidateIndex]] & 0x01;
            SetBit(data, bitIndex, bit);
        }

        return data;
    }

    private static void ApplyLsbMatching(byte[] pixels, int byteIndex, int desiredBit, DeterministicBitSource adjustmentBits)
    {
        int currentValue = pixels[byteIndex];
        if ((currentValue & 0x01) == desiredBit)
        {
            return;
        }

        if (currentValue == 0)
        {
            pixels[byteIndex] = 1;
            return;
        }

        if (currentValue == 255)
        {
            pixels[byteIndex] = 254;
            return;
        }

        pixels[byteIndex] = adjustmentBits.NextBit()
            ? (byte)(currentValue + 1)
            : (byte)(currentValue - 1);
    }

    private static ScatterPermutation CreateScatterPermutation(string password, byte[] salt, int modulus)
    {
        if (modulus <= 0)
        {
            throw new InvalidOperationException("当前自适应载体布局没有可用于载荷写入的位置。");
        }

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] marker = Encoding.ASCII.GetBytes("scatter-v2");
        byte[] seedMaterial = new byte[passwordBytes.Length + salt.Length + marker.Length];
        passwordBytes.CopyTo(seedMaterial, 0);
        salt.CopyTo(seedMaterial, passwordBytes.Length);
        marker.CopyTo(seedMaterial, passwordBytes.Length + salt.Length);

        byte[] hash = SHA256.HashData(seedMaterial);
        ulong rawStep = BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(0, sizeof(ulong)));
        ulong rawOffset = BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(sizeof(ulong), sizeof(ulong)));
        int step = (int)(rawStep % (uint)modulus);
        if (step == 0)
        {
            step = 1;
        }

        while (GreatestCommonDivisor(step, modulus) != 1)
        {
            step++;
            if (step >= modulus)
            {
                step = 1;
            }
        }

        int offset = (int)(rawOffset % (uint)modulus);
        return new ScatterPermutation(step, offset, modulus);
    }

    private static int GreatestCommonDivisor(int left, int right)
    {
        while (right != 0)
        {
            int remainder = left % right;
            left = right;
            right = remainder;
        }

        return Math.Abs(left);
    }

    private static int GetBit(byte[] data, long bitIndex)
    {
        int byteIndex = (int)(bitIndex / 8);
        int shift = 7 - (int)(bitIndex % 8);
        return (data[byteIndex] >> shift) & 0x01;
    }

    private static void SetBit(byte[] data, long bitIndex, int bit)
    {
        int byteIndex = (int)(bitIndex / 8);
        int shift = 7 - (int)(bitIndex % 8);
        if (bit == 1)
        {
            data[byteIndex] |= (byte)(1 << shift);
        }
    }

    private static CarrierAssessment AnalyzeCarrier(LoadedBitmap bitmap)
    {
        BlockAnalysis blockAnalysis = AnalyzeBlocks(bitmap);
        return CreateAssessment(bitmap, blockAnalysis);
    }

    private static CandidateLayout BuildCandidateLayout(LoadedBitmap bitmap)
    {
        BlockAnalysis blockAnalysis = AnalyzeBlocks(bitmap);
        CarrierAssessment assessment = CreateAssessment(bitmap, blockAnalysis);
        int[] candidateByteIndices = BuildCandidateByteIndices(bitmap, blockAnalysis);
        return new CandidateLayout(assessment, candidateByteIndices);
    }

    private static BlockAnalysis AnalyzeBlocks(LoadedBitmap bitmap)
    {
        int blocksX = (bitmap.Width + BlockSize - 1) / BlockSize;
        int blocksY = (bitmap.Height + BlockSize - 1) / BlockSize;
        int totalBlocks = blocksX * blocksY;
        bool[] eligibleBlocks = new bool[totalBlocks];
        double[] luminance = BuildLuminanceMap(bitmap);

        int eligibleBlockCount = 0;
        long candidateCount = 0;
        double varianceSum = 0;
        double gradientSum = 0;

        for (int blockY = 0; blockY < blocksY; blockY++)
        {
            for (int blockX = 0; blockX < blocksX; blockX++)
            {
                int blockIndex = (blockY * blocksX) + blockX;
                BlockMetrics metrics = MeasureBlock(luminance, bitmap.Width, bitmap.Height, blockX * BlockSize, blockY * BlockSize);
                bool eligible = metrics.Variance >= MinimumEligibleVariance && metrics.Gradient >= MinimumEligibleGradient;

                if (!eligible)
                {
                    continue;
                }

                eligibleBlocks[blockIndex] = true;
                eligibleBlockCount++;
                varianceSum += metrics.Variance;
                gradientSum += metrics.Gradient;
                candidateCount += metrics.PixelCount * 3L;
            }
        }

        return new BlockAnalysis(
            blocksX,
            blocksY,
            totalBlocks,
            eligibleBlocks,
            eligibleBlockCount,
            checked((int)candidateCount),
            eligibleBlockCount == 0 ? 0 : varianceSum / eligibleBlockCount,
            eligibleBlockCount == 0 ? 0 : gradientSum / eligibleBlockCount);
    }

    private static double[] BuildLuminanceMap(LoadedBitmap bitmap)
    {
        double[] luminance = new double[bitmap.Width * bitmap.Height];

        for (int y = 0; y < bitmap.Height; y++)
        {
            int rowOffset = y * bitmap.Stride;
            int luminanceOffset = y * bitmap.Width;
            for (int x = 0; x < bitmap.Width; x++)
            {
                int pixelOffset = rowOffset + (x * 4);
                byte blue = bitmap.Pixels[pixelOffset];
                byte green = bitmap.Pixels[pixelOffset + 1];
                byte red = bitmap.Pixels[pixelOffset + 2];
                luminance[luminanceOffset + x] = (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
            }
        }

        return luminance;
    }

    private static BlockMetrics MeasureBlock(double[] luminance, int width, int height, int startX, int startY)
    {
        int endX = Math.Min(startX + BlockSize, width);
        int endY = Math.Min(startY + BlockSize, height);
        double sum = 0;
        double sumSquares = 0;
        double gradientSum = 0;
        int pixelCount = 0;

        for (int y = startY; y < endY; y++)
        {
            int rowOffset = y * width;
            for (int x = startX; x < endX; x++)
            {
                double value = luminance[rowOffset + x];
                sum += value;
                sumSquares += value * value;
                pixelCount++;

                int left = x == 0 ? x : x - 1;
                int right = x == width - 1 ? x : x + 1;
                int up = y == 0 ? y : y - 1;
                int down = y == height - 1 ? y : y + 1;

                double gx = luminance[rowOffset + right] - luminance[rowOffset + left];
                double gy = luminance[(down * width) + x] - luminance[(up * width) + x];
                gradientSum += Math.Abs(gx) + Math.Abs(gy);
            }
        }

        if (pixelCount == 0)
        {
            return new BlockMetrics(0, 0, 0);
        }

        double mean = sum / pixelCount;
        double variance = Math.Max(0, (sumSquares / pixelCount) - (mean * mean));
        double gradient = gradientSum / pixelCount;
        return new BlockMetrics(variance, gradient, pixelCount);
    }

    private static CarrierAssessment CreateAssessment(LoadedBitmap bitmap, BlockAnalysis analysis)
    {
        double textureCoverage = analysis.TotalBlocks == 0 ? 0 : analysis.EligibleBlockCount / (double)analysis.TotalBlocks;
        long totalCapacityBytes = ((long)bitmap.Width * bitmap.Height * 3L) / 8L;
        long adaptiveCapacityBytes = analysis.CandidateCount / 8L;
        long recommendedContainerBytes = Math.Max(0, (long)Math.Floor(adaptiveCapacityBytes * RecommendedUtilizationRatio));

        bool isSupported =
            bitmap.Width >= MinimumDimension &&
            bitmap.Height >= MinimumDimension &&
            analysis.EligibleBlockCount >= MinimumEligibleBlocks &&
            textureCoverage >= MinimumTextureCoverage &&
            recommendedContainerBytes >= MinimumRecommendedContainerBytes;

        int securityScore = ComputeSecurityScore(bitmap, textureCoverage, recommendedContainerBytes, analysis);
        string verdict = isSupported
            ? "支持当前锁定的自适应嵌入配置。"
            : "未通过自适应适配性门禁。";
        string guidance = BuildGuidance(bitmap, textureCoverage, recommendedContainerBytes, analysis, isSupported);

        return new CarrierAssessment(
            bitmap.Width,
            bitmap.Height,
            isSupported,
            securityScore,
            totalCapacityBytes,
            adaptiveCapacityBytes,
            recommendedContainerBytes,
            analysis.EligibleBlockCount,
            analysis.TotalBlocks,
            textureCoverage,
            analysis.AverageVariance,
            analysis.AverageGradient,
            verdict,
            guidance);
    }

    private static int ComputeSecurityScore(
        LoadedBitmap bitmap,
        double textureCoverage,
        long recommendedContainerBytes,
        BlockAnalysis analysis)
    {
        double dimensionScore = Clamp((Math.Min(bitmap.Width, bitmap.Height) - 384.0) / 768.0, 0, 1) * 25.0;
        double coverageScore = Clamp(textureCoverage / 0.45, 0, 1) * 35.0;
        double varianceScore = Clamp(analysis.AverageVariance / 220.0, 0, 1) * 20.0;
        double gradientScore = Clamp(analysis.AverageGradient / 28.0, 0, 1) * 10.0;
        double budgetScore = Clamp(recommendedContainerBytes / 32_768.0, 0, 1) * 10.0;
        return (int)Math.Round(dimensionScore + coverageScore + varianceScore + gradientScore + budgetScore);
    }

    private static string BuildGuidance(
        LoadedBitmap bitmap,
        double textureCoverage,
        long recommendedContainerBytes,
        BlockAnalysis analysis,
        bool isSupported)
    {
        var notes = new List<string>();

        if (bitmap.Width < MinimumDimension || bitmap.Height < MinimumDimension)
        {
            notes.Add($"请使用更大的载体图片。当前锁定配置要求图片宽和高至少达到 {MinimumDimension} 像素。");
        }

        if (textureCoverage < MinimumTextureCoverage)
        {
            notes.Add("图片过于平滑。建议改用纹理密集的照片，例如植被、织物、头发、建筑或自然噪声丰富的场景。");
        }

        if (analysis.EligibleBlockCount < MinimumEligibleBlocks)
        {
            notes.Add("高方差纹理块数量过少，不足以支撑稀疏高对抗嵌入。");
        }

        if (recommendedContainerBytes < MinimumRecommendedContainerBytes)
        {
            notes.Add($"安全加密容器预算过小（{FormatBytes(recommendedContainerBytes)}）。");
        }

        if (isSupported)
        {
            notes.Add($"推荐加密容器预算：{FormatBytes(recommendedContainerBytes)}。");
            notes.Add("载荷只会分散写入强纹理块，并采用随机化低占用 LSB Matching。");
        }

        notes.Add("任何图片隐写系统都无法保证对专业隐写取证或隐写分析设备绝对不可见。本方案只是增强对抗能力，不构成绝对安全证明。");
        return string.Join(Environment.NewLine, notes);
    }

    private static int[] BuildCandidateByteIndices(LoadedBitmap bitmap, BlockAnalysis analysis)
    {
        int[] candidateByteIndices = new int[analysis.CandidateCount];
        int writeIndex = 0;

        for (int blockY = 0; blockY < analysis.BlocksY; blockY++)
        {
            for (int blockX = 0; blockX < analysis.BlocksX; blockX++)
            {
                int blockIndex = (blockY * analysis.BlocksX) + blockX;
                if (!analysis.EligibleBlocks[blockIndex])
                {
                    continue;
                }

                int startX = blockX * BlockSize;
                int startY = blockY * BlockSize;
                int endX = Math.Min(startX + BlockSize, bitmap.Width);
                int endY = Math.Min(startY + BlockSize, bitmap.Height);

                for (int y = startY; y < endY; y++)
                {
                    int rowOffset = y * bitmap.Stride;
                    for (int x = startX; x < endX; x++)
                    {
                        int pixelOffset = rowOffset + (x * 4);
                        candidateByteIndices[writeIndex++] = pixelOffset;
                        candidateByteIndices[writeIndex++] = pixelOffset + 1;
                        candidateByteIndices[writeIndex++] = pixelOffset + 2;
                    }
                }
            }
        }

        return candidateByteIndices;
    }

    private static double Clamp(double value, double min, double max)
    {
        if (value < min)
        {
            return min;
        }

        if (value > max)
        {
            return max;
        }

        return value;
    }

    private static LoadedBitmap LoadBitmap(string imagePath)
    {
        if (!File.Exists(imagePath))
        {
            throw new FileNotFoundException("未找到图片文件。", imagePath);
        }

        using var stream = File.OpenRead(imagePath);
        var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        BitmapSource frame = decoder.Frames[0];
        var converted = new FormatConvertedBitmap(frame, PixelFormats.Bgra32, null, 0);
        int stride = converted.PixelWidth * 4;
        byte[] pixels = new byte[stride * converted.PixelHeight];
        converted.CopyPixels(pixels, stride, 0);
        return new LoadedBitmap(pixels, converted.PixelWidth, converted.PixelHeight, stride, converted.DpiX, converted.DpiY);
    }

    private static void SaveAsPng(LoadedBitmap bitmap, string outputPath)
    {
        var outputBitmap = BitmapSource.Create(
            bitmap.Width,
            bitmap.Height,
            bitmap.DpiX,
            bitmap.DpiY,
            PixelFormats.Bgra32,
            palette: null,
            bitmap.Pixels,
            bitmap.Stride);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(outputBitmap));

        using var fileStream = File.Create(outputPath);
        encoder.Save(fileStream);
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

    private sealed record LoadedBitmap(byte[] Pixels, int Width, int Height, int Stride, double DpiX, double DpiY);

    private sealed record CandidateLayout(CarrierAssessment Assessment, int[] CandidateByteIndices);

    private sealed record BlockMetrics(double Variance, double Gradient, int PixelCount);

    private sealed record BlockAnalysis(
        int BlocksX,
        int BlocksY,
        int TotalBlocks,
        bool[] EligibleBlocks,
        int EligibleBlockCount,
        int CandidateCount,
        double AverageVariance,
        double AverageGradient);

    private sealed record ScatterPermutation(int Step, int Offset, int Modulus)
    {
        public int GetPosition(long bitIndex)
        {
            return (int)(((bitIndex * Step) + Offset) % Modulus);
        }
    }

    private sealed class DeterministicBitSource
    {
        private ulong _state0;
        private ulong _state1;

        private DeterministicBitSource(ulong state0, ulong state1)
        {
            _state0 = state0 == 0 && state1 == 0 ? 0x9E3779B97F4A7C15UL : state0;
            _state1 = state1 == 0 && state0 == 0 ? 0xBF58476D1CE4E5B9UL : state1;
        }

        public static DeterministicBitSource Create(string password, byte[] salt, string marker)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] markerBytes = Encoding.ASCII.GetBytes(marker);
            byte[] seedMaterial = new byte[passwordBytes.Length + salt.Length + markerBytes.Length];
            passwordBytes.CopyTo(seedMaterial, 0);
            salt.CopyTo(seedMaterial, passwordBytes.Length);
            markerBytes.CopyTo(seedMaterial, passwordBytes.Length + salt.Length);
            byte[] hash = SHA256.HashData(seedMaterial);
            ulong state0 = BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(0, sizeof(ulong)));
            ulong state1 = BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(sizeof(ulong), sizeof(ulong)));
            return new DeterministicBitSource(state0, state1);
        }

        public bool NextBit()
        {
            ulong result = NextUInt64();
            return (result & 0x01UL) == 0x01UL;
        }

        private ulong NextUInt64()
        {
            ulong s1 = _state0;
            ulong s0 = _state1;
            _state0 = s0;
            s1 ^= s1 << 23;
            _state1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
            return _state1 + s0;
        }
    }
}
