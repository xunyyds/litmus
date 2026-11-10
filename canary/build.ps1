<#
.SYNOPSIS
    Litmus 靶包（canary）手工构建脚本：aapt2 + javac + d8 + clang++ + zipalign + apksigner，不依赖 gradle。

.DESCRIPTION
    产出：
      out/litmus-canary-<ver>.apk        靶包
      out/build-info.json               构建元数据（apkSha256 / certSha256 / zipFingerprint）
      out/keys/litmus.p12                自举的签名密钥（首次构建生成，之后复用）

    为什么不用 gradle：目标机没有 gradle/kotlinc，且安全工具的构建链越短越可信。
    native 为什么直接调 clang++ 而不是走 cmake：本机沙箱里 ninja/make 执行规则会挂死
    （`couldn't create signal pipe`），而 clang++ 单命令编译 0.5s 就完事。
    canary/jni/CMakeLists.txt 保留，给 IDE / 其它平台用。

    签名自举：首次构建用 keytool 生成 PKCS12；证书 SHA-256 在**签名前**就能算出来，
    因此可以烘进 assets/litmus-build.properties 作为「原始证书期望值」。
    APK 自身的 SHA-256 / Zip 指纹产生于签名之后，烘不进自己 —— 由 cli 平面比对。

.PARAMETER OutDir
    输出目录，默认 canary/out。

.PARAMETER Serial
    adb 设备序列号；不传则要求恰好一台在线设备。

.PARAMETER Install
    构建完安装到设备（覆盖安装）。

.PARAMETER Uninstall
    先卸载再装（清数据，用于干净基线）。

.PARAMETER NoNative
    跳过 native 探针（liblitmusprobe.so），Java 侧 native 向量会降级成 UNKNOWN。

.PARAMETER Debuggable
    构建 debug 版（清单加 android:debuggable，env.debuggable 会命中 TAMPERED）。

.PARAMETER Screenshot
    安装启动后截图到 out/ui-home.png。

.PARAMETER Logcat
    构建安装后 dump 最近的 LitmusReport 日志。

.EXAMPLE
    pwsh -File canary/build.ps1 -Install -Screenshot -Logcat -Serial emulator-5554
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [string]$Serial = '',
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$NoNative,
    [switch]$Debuggable,
    [switch]$Screenshot,
    [switch]$Logcat,
    [switch]$KeepWork,
    [int]$MinSdk = 26,
    [int]$TargetSdk = 35,
    [string]$CompileSdk = '',
    [string]$Abis = 'arm64-v8a,x86_64',
    [string]$Version = '0.1.0'
)

$ErrorActionPreference = 'Stop'

$CanaryDir = $PSScriptRoot
$RepoRoot = Split-Path $CanaryDir -Parent
if (-not $OutDir) { $OutDir = Join-Path $CanaryDir 'out' }
$Work = Join-Path $OutDir 'work'
$GenDir = Join-Path $Work 'gen'
$ClassesDir = Join-Path $Work 'classes'
$DexDir = Join-Path $Work 'dex'
$AssetsWork = Join-Path $Work 'assets'
$NatOut = Join-Path $Work 'native'

$script:stepNo = 0
function Write-Step([string]$msg) {
    $script:stepNo++
    Write-Host ""
    Write-Host ("[{0:d2}] {1}" -f $script:stepNo, $msg) -ForegroundColor Cyan
}
function Write-Ok([string]$msg) { Write-Host "     $msg" -ForegroundColor DarkGray }
function Write-Warn2([string]$msg) { Write-Host "     ! $msg" -ForegroundColor Yellow }
function Fail([string]$msg) { throw "[litmus-build] $msg" }
function Write-Utf8([string]$path, [string]$text) {
    $dir = Split-Path $path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}
function Get-Sha256Hex([string]$path) { return (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant() }
function New-Dir([string]$path) { if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null } }

# ================================================================ 01 环境
Write-Step '定位 JDK / Android SDK / build-tools'

# 工具链全部靠环境自动探测：公开仓库里不写死任何盘符
$JdkHome = if ($env:JAVA_HOME) { $env:JAVA_HOME } else {
    $javacCmd = Get-Command javac -ErrorAction SilentlyContinue
    if ($javacCmd) { Split-Path (Split-Path $javacCmd.Source -Parent) -Parent } else { '' }
}
$SdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
           elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME }
           else { '' }
if (-not $SdkRoot -or -not (Test-Path $SdkRoot)) {
    Fail '找不到 Android SDK：请设置 ANDROID_SDK_ROOT 或 ANDROID_HOME'
}
if (-not $JdkHome -or -not (Test-Path (Join-Path $JdkHome 'bin\javac.exe'))) {
    Fail '找不到 JDK（需要 11+）：请设置 JAVA_HOME'
}

$BuildTools = if ($env:ANDROID_BUILD_TOOLS) { $env:ANDROID_BUILD_TOOLS } else {
    $bt = Get-ChildItem (Join-Path $SdkRoot 'build-tools') -Directory -ErrorAction SilentlyContinue |
          Sort-Object { [version]($_.Name -replace '[^0-9\.].*$','') } -Descending | Select-Object -First 1
    if ($bt) { $bt.FullName } else { '' }
}
if (-not $BuildTools) { Fail "在 $SdkRoot\build-tools 下找不到任何 build-tools" }

# 未指定编译平台时取已安装的最高版本
if (-not $CompileSdk) {
    $plat = Get-ChildItem (Join-Path $SdkRoot 'platforms') -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^android-\d' } |
            Sort-Object { [int](($_.Name -replace '^android-','') -split '\.')[0] } -Descending |
            Select-Object -First 1
    if (-not $plat) { Fail "在 $SdkRoot\platforms 下找不到 android-* 平台" }
    $CompileSdk = $plat.Name
}
$NdkRoot = if ($env:ANDROID_NDK) { $env:ANDROID_NDK } else { Join-Path $SdkRoot 'ndk\28.2.13676358' }

$JavacExe = Join-Path $JdkHome 'bin\javac.exe'
$KeytoolExe = Join-Path $JdkHome 'bin\keytool.exe'
$Aapt2 = Join-Path $BuildTools 'aapt2.exe'
$D8 = Join-Path $BuildTools 'd8.bat'
$ZipAlign = Join-Path $BuildTools 'zipalign.exe'
$ApkSigner = Join-Path $BuildTools 'apksigner.bat'
$AndroidJar = Join-Path $SdkRoot "platforms\$CompileSdk\android.jar"
$Adb = Join-Path $SdkRoot 'platform-tools\adb.exe'

foreach ($t in @(
        @{ n = 'javac.exe'; p = $JavacExe }, @{ n = 'keytool.exe'; p = $KeytoolExe },
        @{ n = 'aapt2.exe'; p = $Aapt2 }, @{ n = 'd8.bat'; p = $D8 },
        @{ n = 'zipalign.exe'; p = $ZipAlign }, @{ n = 'apksigner.bat'; p = $ApkSigner },
        @{ n = 'android.jar'; p = $AndroidJar },
        @{ n = 'AndroidManifest.xml'; p = (Join-Path $CanaryDir 'AndroidManifest.xml') })) {
    if (-not (Test-Path $t.p)) { Fail "找不到 $($t.n)：$($t.p)" }
}
$env:JAVA_HOME = $JdkHome
$env:PATH = (Join-Path $JdkHome 'bin') + ';' + $env:PATH

Write-Ok "JDK         = $JdkHome"
Write-Ok "build-tools = $BuildTools"
Write-Ok "android.jar = $AndroidJar"
Write-Ok "ndk         = $NdkRoot"

if (-not $KeepWork -and (Test-Path $Work)) { Remove-Item $Work -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($d in @($Work, $GenDir, $ClassesDir, $DexDir, $AssetsWork, $NatOut)) { New-Dir $d }

# ================================================================ 02 签名密钥自举
Write-Step '签名密钥自举（keytool → PKCS12）'

$KeysDir = Join-Path $OutDir 'keys'
New-Dir $KeysDir
$Keystore = Join-Path $KeysDir 'litmus.p12'
$CertDer = Join-Path $KeysDir 'litmus-cert.der'
$KsPass = 'litmus-pw'   # PKCS12 要求口令 >= 6 位

if (-not (Test-Path $Keystore)) {
    Write-Ok '首次构建，生成 PKCS12 密钥（RSA2048 / 10000 天）'
    & $KeytoolExe -genkeypair -keystore $Keystore -storetype PKCS12 `
        -storepass $KsPass -keypass $KsPass -alias litmus `
        -keyalg RSA -keysize 2048 -validity 10000 `
        -dname "CN=Litmus, O=Litmus, C=CN" -noprompt 2>&1 | ForEach-Object { Write-Host "     $_" }
    if ($LASTEXITCODE -ne 0) { Fail "keytool 生成密钥失败 (exit $LASTEXITCODE)" }
}
# 每次构建都重新导出：keystore 被换过时旧 cert.der 会让烘进去的期望值全错
if (Test-Path $CertDer) { Remove-Item $CertDer -Force }
& $KeytoolExe -exportcert -keystore $Keystore -storepass $KsPass -alias litmus -file $CertDer 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "keytool 导出证书失败 (exit $LASTEXITCODE)" }

$CertSha256 = Get-Sha256Hex $CertDer
$KeyId = $CertSha256.Substring(0, 12)
Write-Ok "keystore    = $Keystore"
Write-Ok "certSha256  = $CertSha256"

# ================================================================ 03 assets（烘期望值）
Write-Step '生成 assets/litmus-build.properties（烘入证书期望值）'

$buildUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$hasNative = (-not $NoNative)
$flavor = if ($Debuggable) { 'debug' } else { 'release' }
$props = @(
    "# 构建期由 canary/build.ps1 生成，勿手工修改。"
    "litmus.version=$Version"
    "litmus.flavor=$flavor"
    "litmus.buildUtc=$buildUtc"
    "litmus.kitId=$KeyId"
    "litmus.hasNative=$($hasNative.ToString().ToLowerInvariant())"
    "litmus.expectedCertSha256=$CertSha256"
    "litmus.expectedLegacyCertSha256=$CertSha256"
    "litmus.expectedCertHistory=[`"$CertSha256`"]"
    "litmus.expectedSignerCount=1"
) -join "`n"

$srcAssets = Join-Path $CanaryDir 'assets'
if (Test-Path $srcAssets) { Copy-Item (Join-Path $srcAssets '*') $AssetsWork -Recurse -Force -ErrorAction SilentlyContinue }
Write-Utf8 (Join-Path $AssetsWork 'litmus-build.properties') ($props + "`n")
Write-Ok "assets 工作副本 = $AssetsWork"

# ================================================================ 04 资源编译 + link
Write-Step 'aapt2 compile + link'

$ResDir = Join-Path $CanaryDir 'res'
$ResZip = Join-Path $Work 'res.zip'
$BaseApk = Join-Path $Work 'base.apk'
if (Test-Path $ResZip) { Remove-Item $ResZip -Force }
if (Test-Path $BaseApk) { Remove-Item $BaseApk -Force }

& $Aapt2 compile --dir $ResDir -o $ResZip 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "aapt2 compile 失败 (exit $LASTEXITCODE)" }

$linkArgs = @(
    'link', '-o', $BaseApk,
    '--manifest', (Join-Path $CanaryDir 'AndroidManifest.xml'),
    '-I', $AndroidJar,
    '-A', $AssetsWork,
    '--java', $GenDir,
    '--min-sdk-version', "$MinSdk",
    '--target-sdk-version', "$TargetSdk",
    '--version-code', '1',
    '--version-name', $Version,
    '--auto-add-overlay',
    # targetSdk>=30 要求 resources.arsc 不压缩，否则 Android 11+ 装不上
    '-0', 'arsc'
)
if ($Debuggable) { $linkArgs += '--debug-mode' }
$linkArgs += $ResZip

& $Aapt2 @linkArgs 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "aapt2 link 失败 (exit $LASTEXITCODE)" }
Write-Ok ("base.apk = {0:N0} bytes" -f (Get-Item $BaseApk).Length)

# ================================================================ 05 javac
Write-Step 'javac（src + R.java → classes）'

$sources = @()
$sources += (Get-ChildItem (Join-Path $CanaryDir 'src') -Recurse -Filter *.java | ForEach-Object { $_.FullName })
if (Test-Path $GenDir) { $sources += (Get-ChildItem $GenDir -Recurse -Filter *.java | ForEach-Object { $_.FullName }) }
if ($sources.Count -eq 0) { Fail '没有 Java 源码' }

$argFile = Join-Path $Work 'sources.txt'
Write-Utf8 $argFile (($sources | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' }) -join "`n")
Write-Ok "$($sources.Count) 个 Java 文件"

& $JavacExe -encoding UTF-8 --release 11 -nowarn -Xlint:-options -cp $AndroidJar -d $ClassesDir "@$argFile"
if ($LASTEXITCODE -ne 0) { Fail "javac 失败 (exit $LASTEXITCODE)" }
$classFiles = @(Get-ChildItem $ClassesDir -Recurse -Filter *.class | ForEach-Object { $_.FullName })
Write-Ok "$($classFiles.Count) 个 class"

# ================================================================ 06 d8
Write-Step 'd8（classes → classes.dex）'

# 逐条传 .class 会撞 Windows 命令行长度上限（76 个 class 就炸），先打成一个 jar 再喂给 d8
$JarExe = Join-Path $JdkHome 'bin\jar.exe'
$ClassesJar = Join-Path $Work 'classes.jar'
if (Test-Path $ClassesJar) { Remove-Item $ClassesJar -Force }
& $JarExe cf $ClassesJar -C $ClassesDir . 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "jar 打包 classes 失败 (exit $LASTEXITCODE)" }

& $D8 --release --min-api $MinSdk --lib $AndroidJar --output $DexDir $ClassesJar 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "d8 失败 (exit $LASTEXITCODE)" }
$DexFile = Join-Path $DexDir 'classes.dex'
if (-not (Test-Path $DexFile)) { Fail "d8 没有产出 classes.dex：$DexDir" }
Write-Ok ("classes.dex = {0:N0} bytes" -f (Get-Item $DexFile).Length)

# ================================================================ 07 native（直接 clang++）
Write-Step ("native 探针（{0}）" -f $(if ($NoNative) { '已跳过' } else { $Abis }))

$soMap = @{}
if (-not $NoNative) {
    $clangxx = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe'
    $jniDir = Join-Path $CanaryDir 'jni'
    $cppFiles = @(Get-ChildItem $jniDir -Filter *.cpp | ForEach-Object { $_.FullName })
    if (-not (Test-Path $clangxx) -or $cppFiles.Count -eq 0) {
        Write-Warn2 "找不到 clang++（$clangxx）或 jni/*.cpp，降级为纯 Java"
        $hasNative = $false
    } else {
        foreach ($abi in ($Abis -split ',')) {
            $abi = $abi.Trim()
            $trip = switch ($abi) {
                'arm64-v8a' { 'aarch64-linux-android' }
                'x86_64' { 'x86_64-linux-android' }
                'armeabi-v7a' { 'armv7a-linux-androideabi' }
                default { $null }
            }
            if (-not $trip) { Write-Warn2 "不认识的 ABI: $abi，跳过"; continue }
            $abiOut = Join-Path $NatOut $abi
            New-Dir $abiOut
            $so = Join-Path $abiOut 'liblitmusprobe.so'
            if (Test-Path $so) { Remove-Item $so -Force }
            $cargs = @(
                "--target=$trip$MinSdk",
                # -Os + -s：体积优先。JNI 走 .dynsym，strip 掉 .symtab 不影响 dlsym
                '-std=c++17', '-Os', '-s', '-fPIC', '-shared', '-fno-exceptions', '-fno-rtti',
                # 必须静态链接 libc++：否则 .so 会 NEEDED libc++_shared.so，而 APK 里没有那个库，
                # dlopen 直接失败，报的却是含糊的 UnsatisfiedLinkError: no error!
                '-static-libstdc++',
                '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections',
                '-Wl,--gc-sections', '-Wl,--strip-all',
                '-Wall', '-Wextra', '-Wno-unused-parameter',
                '-DNDEBUG', '-o', $so
            ) + $cppFiles + @('-llog', '-ldl')
            & $clangxx @cargs 2>&1 | ForEach-Object { Write-Host "     $_" }
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $so)) {
                Write-Warn2 "$abi 编译失败，跳过该 ABI"
                continue
            }
            $soMap[$abi] = $so
            Write-Ok ("{0,-12} liblitmusprobe.so = {1:N0} bytes" -f $abi, (Get-Item $so).Length)
        }
        if ($soMap.Count -eq 0) {
            Write-Warn2 '所有 ABI 都没编出 native → hasNative=false（native 向量会出 UNKNOWN）'
            $hasNative = $false
        }
    }
}

# hasNative 最终值回写 assets（必须在 04 之前决定，所以这里重写一次 assets）
if ($hasNative) {
    # placeholder: props 里的值已经是对的
} else {
    Write-Utf8 (Join-Path $AssetsWork 'litmus-build.properties') `
        (($props -replace 'litmus.hasNative=true', 'litmus.hasNative=false') + "`n")
    # assets 变了必须重新 link，否则 APK 里还是旧值
    Write-Ok '重新 link（assets 中 hasNative 变更）'
    if (Test-Path $BaseApk) { Remove-Item $BaseApk -Force }
    & $Aapt2 @linkArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "aapt2 link 二次执行失败 (exit $LASTEXITCODE)" }
}

# ================================================================ 08 组包（新建 zip，逐条拷贝）
Write-Step '组包（base.apk 条目 + classes.dex + lib/*.so）'

Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

$Unsigned = Join-Path $Work 'unsigned.apk'
if (Test-Path $Unsigned) { Remove-Item $Unsigned -Force }

$srcZip = [System.IO.Compression.ZipFile]::OpenRead($BaseApk)
$dstStream = [System.IO.File]::Open($Unsigned, [System.IO.FileMode]::CreateNew)
$dstZip = New-Object System.IO.Compression.ZipArchive($dstStream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    # 1) 原样搬 base.apk 的条目（arsc 用 Stored，其余 Optimal）
    foreach ($e in $srcZip.Entries) {
        $level = if ($e.FullName -eq 'resources.arsc') {
            [System.IO.Compression.CompressionLevel]::NoCompression
        } else {
            [System.IO.Compression.CompressionLevel]::Optimal
        }
        $ne = $dstZip.CreateEntry($e.FullName, $level)
        if ($e.Length -gt 0) {
            $is = $e.Open()
            $os = $ne.Open()
            try { $is.CopyTo($os) } finally { $os.Dispose(); $is.Dispose() }
        }
    }
    # 2) classes.dex
    $de = $dstZip.CreateEntry('classes.dex', [System.IO.Compression.CompressionLevel]::Optimal)
    $ds = $de.Open(); $df = [System.IO.File]::OpenRead($DexFile)
    try { $df.CopyTo($ds) } finally { $df.Dispose(); $ds.Dispose() }
    # 3) lib/<abi>/liblitmusprobe.so —— 不压缩，便于 zipalign -p 做页对齐
    foreach ($abi in $soMap.Keys) {
        $ne = $dstZip.CreateEntry("lib/$abi/liblitmusprobe.so", [System.IO.Compression.CompressionLevel]::NoCompression)
        $os = $ne.Open(); $fsrc = [System.IO.File]::OpenRead($soMap[$abi])
        try { $fsrc.CopyTo($os) } finally { $fsrc.Dispose(); $os.Dispose() }
    }
} finally {
    $dstZip.Dispose(); $dstStream.Dispose(); $srcZip.Dispose()
}
Write-Ok ("unsigned.apk = {0:N0} bytes" -f (Get-Item $Unsigned).Length)

# ================================================================ 09 zipalign + 签名
Write-Step 'zipalign + apksigner'

$Aligned = Join-Path $Work 'aligned.apk'
if (Test-Path $Aligned) { Remove-Item $Aligned -Force }
& $ZipAlign -p -f 4 $Unsigned $Aligned 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "zipalign 失败 (exit $LASTEXITCODE)" }

$OutApk = Join-Path $OutDir "litmus-canary-$Version.apk"
if (Test-Path $OutApk) { Remove-Item $OutApk -Force }

& $ApkSigner sign `
    --ks $Keystore --ks-key-alias litmus `
    --ks-pass "pass:$KsPass" --key-pass "pass:$KsPass" `
    --min-sdk-version $MinSdk `
    --v1-signing-enabled false --v2-signing-enabled true `
    --v3-signing-enabled true --v4-signing-enabled false `
    --out $OutApk $Aligned 2>&1 | ForEach-Object { Write-Host "     $_" }
if ($LASTEXITCODE -ne 0) { Fail "apksigner sign 失败 (exit $LASTEXITCODE)" }

$verify = & $ApkSigner verify --print-certs --min-sdk-version $MinSdk $OutApk 2>&1
if ($LASTEXITCODE -ne 0) { Fail ("apksigner verify 失败：`n" + ($verify -join "`n")) }
$signerLine = ($verify | Where-Object { $_ -match 'Signer #1 certificate SHA-256 digest' } | Select-Object -First 1)
Write-Ok "$signerLine"

# ================================================================ 10 build-info
Write-Step '生成 build-info.json'

$apkSha256 = Get-Sha256Hex $OutApk
$zipFp = ''
$zipfpPy = Join-Path $RepoRoot 'tools\zipfp.py'
if (Test-Path $zipfpPy) {
    $zipFp = ((& python $zipfpPy $OutApk 2>&1 | Select-Object -Last 1) -as [string]).Trim()
} else {
    Write-Warn2 '找不到 tools/zipfp.py，zipFingerprint 留空'
}
$apkSize = (Get-Item $OutApk).Length

$info = [ordered]@{
    schema         = 'litmus.build/1'
    apk            = (Resolve-Path $OutApk).Path
    apkSha256      = $apkSha256
    certSha256     = $CertSha256
    zipFingerprint = $zipFp
    version        = $Version
    flavor         = $flavor
    builtAt        = $buildUtc
    minSdk         = $MinSdk
    targetSdk      = $TargetSdk
    abis           = @($soMap.Keys | Sort-Object)
    sizeBytes      = $apkSize
}
Write-Utf8 (Join-Path $OutDir 'build-info.json') (($info | ConvertTo-Json -Depth 4) + "`n")

Write-Ok ("APK       = {0}" -f $OutApk)
Write-Ok ("size      = {0:N0} bytes" -f $apkSize)
Write-Ok ("apkSha256 = {0}" -f $apkSha256)
Write-Ok ("zipFp     = {0}" -f $zipFp)
Write-Ok ("abis      = {0}" -f $(if ($soMap.Count) { ($soMap.Keys | Sort-Object) -join ',' } else { 'none' }))

# ================================================================ 11 设备动作
if (-not ($Install -or $Uninstall -or $Screenshot -or $Logcat)) {
    Write-Host ""
    Write-Host "构建完成。上设备：pwsh -File canary/build.ps1 -Install -Logcat -Serial emulator-5554" -ForegroundColor Green
    exit 0
}

Write-Step '设备操作（adb）'
if (-not (Test-Path $Adb)) { Fail "找不到 adb：$Adb" }

$adbArgs = @()
if ($Serial) {
    $adbArgs = @('-s', $Serial)
} else {
    $devices = @(& $Adb devices | Select-Object -Skip 1 | Where-Object { $_ -match '\sdevice$' })
    if ($devices.Count -ne 1) { Fail "在线设备 $($devices.Count) 台，请用 -Serial 指定" }
    $Serial = ($devices[0] -split '\s+')[0]
    $adbArgs = @('-s', $Serial)
}
Write-Ok "device = $Serial"

if ($Uninstall) {
    & $Adb @adbArgs uninstall io.litmus.canary 2>&1 | Out-Null
    Write-Ok '已卸载（清数据）'
}
if ($Install -or $Uninstall) {
    & $Adb @adbArgs logcat -c 2>&1 | Out-Null
    $r = & $Adb @adbArgs install -r -t $OutApk 2>&1
    if ($LASTEXITCODE -ne 0) { Fail ("adb install 失败：`n" + ($r -join "`n")) }
    Write-Ok (($r -join ' ').Trim())
    & $Adb @adbArgs shell am force-stop io.litmus.canary 2>&1 | Out-Null
    $startOut = & $Adb @adbArgs shell am start -W -n io.litmus.canary/.MainActivity 2>&1
    Write-Ok ($startOut -join ' ')
    Start-Sleep -Seconds 4
}
if ($Screenshot) {
    $png = Join-Path $OutDir 'ui-home.png'
    if (Test-Path $png) { Remove-Item $png -Force }
    # exec-out 是二进制流，PowerShell 的 > 会按文本落盘把 PNG 写坏，必须交给 cmd.exe
    & cmd /c "`"$Adb`" $($adbArgs -join ' ') exec-out screencap -p > `"$png`""
    if (Test-Path $png) { Write-Ok ("截图 = {0} ({1:N0} bytes)" -f $png, (Get-Item $png).Length) }
    else { Write-Warn2 '截图失败' }
}
if ($Logcat) {
    $lines = & $Adb @adbArgs logcat -d -s LitmusReport 2>&1 | Select-String -Pattern 'LITMUS_REPORT' | Select-Object -Last 3
    foreach ($l in $lines) {
        $s = $l.ToString()
        Write-Ok $(if ($s.Length -gt 900) { $s.Substring(0, 900) + ' …' } else { $s })
    }
}

Write-Host ""
Write-Host "完成。" -ForegroundColor Green
