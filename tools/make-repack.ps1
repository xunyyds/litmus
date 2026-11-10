<#
.SYNOPSIS
    模拟「用户修补了靶包」：往 APK 里塞一个文件并用**另一把密钥**重签。

.DESCRIPTION
    这是 Litmus 的核心场景最小复现：不需要 Frida / XPatch / root，
    只要换签名 + 改内容，就应该被 pkg.* 三条 A 级向量和 CLI 平面全部抓住。

    产物用于对照实验：
        litmus.py run --label C1-clean
        pwsh -File tools/make-repack.ps1
        litmus.py run --label C2-repack --baseline runs/C1-clean-*/run.json
    然后看 run.json 里的 score / blindSpots。

.PARAMETER InputApk
    原始靶包（默认 canary/out/litmus-canary-0.1.0.apk）

.PARAMETER OutApk
    产出的「被修补」包（默认 canary/out/demo-repacked.apk）

.PARAMETER Payload
    塞进去的文件内容（默认一行说明文字）
#>
[CmdletBinding()]
param(
    [string]$InputApk = '',
    [string]$OutApk = '',
    [string]$Payload = 'this file was injected by the "user" to simulate a repack'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
if (-not $InputApk) { $InputApk = Join-Path $RepoRoot 'canary\out\litmus-canary-0.1.0.apk' }
if (-not $OutApk) { $OutApk = Join-Path $RepoRoot 'canary\out\demo-repacked.apk' }
if (-not (Test-Path $InputApk)) { throw "找不到输入 APK：$InputApk" }

$JdkHome = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { Split-Path (Split-Path (Get-Command javac).Source -Parent) -Parent }
$SdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
           elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME }
           else { throw '请设置 ANDROID_SDK_ROOT 或 ANDROID_HOME' }
$BuildTools = (Get-ChildItem (Join-Path $SdkRoot 'build-tools') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
$Keytool = Join-Path $JdkHome 'bin\keytool.exe'
$ZipAlign = Join-Path $BuildTools 'zipalign.exe'
$ApkSigner = Join-Path $BuildTools 'apksigner.bat'
$env:JAVA_HOME = $JdkHome

$KeyDir = Join-Path $RepoRoot 'canary\out\keys'
if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null }
$Ks = Join-Path $KeyDir 'repacker.p12'
if (-not (Test-Path $Ks)) {
    Write-Host '==> 生成「用户自己的」签名密钥（与靶包原签名不同）' -ForegroundColor Cyan
    & $Keytool -genkeypair -keystore $Ks -storetype PKCS12 -storepass repack-pw -keypass repack-pw `
        -alias repacker -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=Repacker, O=NotLitmus, C=CN" -noprompt 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'keytool 生成失败' }
}

$work = Join-Path $RepoRoot 'canary\out\demo'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $work | Out-Null
$tampered = Join-Path $work 'tampered.apk'

Write-Host '==> 1/3 往 APK 里注入一个文件（改内容）' -ForegroundColor Cyan
Copy-Item $InputApk $tampered -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$zip = [System.IO.Compression.ZipFile]::Open($tampered, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    $old = $zip.GetEntry('assets/injected-by-user.txt')
    if ($old) { $old.Delete() }
    $entry = $zip.CreateEntry('assets/injected-by-user.txt', [System.IO.Compression.CompressionLevel]::Optimal)
    $s = $entry.Open()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Payload + "`n")
    $s.Write($bytes, 0, $bytes.Length)
    $s.Dispose()
} finally { $zip.Dispose() }

Write-Host '==> 2/3 zipalign' -ForegroundColor Cyan
$aligned = Join-Path $work 'aligned.apk'
& $ZipAlign -p -f 4 $tampered $aligned 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'zipalign 失败' }

Write-Host '==> 3/3 用另一把密钥重签（改签名）' -ForegroundColor Cyan
if (Test-Path $OutApk) { Remove-Item $OutApk -Force }
& $ApkSigner sign --ks $Ks --ks-key-alias repacker `
    --ks-pass pass:repack-pw --key-pass pass:repack-pw `
    --min-sdk-version 26 --v1-signing-enabled false `
    --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false `
    --out $OutApk $aligned 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'apksigner 签名失败' }

$origSha = (Get-FileHash -Algorithm SHA256 $InputApk).Hash.ToLowerInvariant()
$newSha = (Get-FileHash -Algorithm SHA256 $OutApk).Hash.ToLowerInvariant()
$origFp = (python (Join-Path $PSScriptRoot 'zipfp.py') $InputApk).Trim()
$newFp = (python (Join-Path $PSScriptRoot 'zipfp.py') $OutApk).Trim()

Write-Host ''
Write-Host "原包   sha256=$($origSha.Substring(0,16))…  zipFp=$($origFp.Substring(0,16))…" -ForegroundColor DarkGray
Write-Host "修补包 sha256=$($newSha.Substring(0,16))…  zipFp=$($newFp.Substring(0,16))…" -ForegroundColor DarkGray
Write-Host ''
Write-Host "下一步：" -ForegroundColor Green
Write-Host "  adb -s emulator-5554 install -r `"$OutApk`"" -ForegroundColor Green
Write-Host "  python cli/litmus.py run --serial emulator-5554 --label C2-repack --no-install --baseline runs/C1-clean-*/run.json" -ForegroundColor Green
