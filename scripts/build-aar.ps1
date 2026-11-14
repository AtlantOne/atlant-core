param([string]$OutputName='atlant.aar', [switch]$AllAbis)

# Native library only: deliberately does not invoke Gradle or assemble an APK.
$ErrorActionPreference='Stop'
if ([IO.Path]::GetFileName($OutputName) -ne $OutputName -or
    [IO.Path]::GetExtension($OutputName) -ne '.aar') {
    throw 'OutputName must be a filename ending in .aar, without a directory'
}
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$savedJava,$savedAndroid,$savedPath=$env:JAVA_HOME,$env:ANDROID_HOME,$env:PATH
$savedGoOs,$savedGoArch,$savedCgo=$env:GOOS,$env:GOARCH,$env:CGO_ENABLED
$savedGoToolchain=$env:GOTOOLCHAIN
$mappedDrive=''
try {
    $env:GOOS=$null;$env:GOARCH=$null;$env:CGO_ENABLED=$null
    if (-not $env:JAVA_HOME) { $env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr' }
    if (-not $env:ANDROID_HOME) { $env:ANDROID_HOME=Join-Path $env:LOCALAPPDATA 'Android/Sdk' }
    $env:PATH=(Join-Path $env:JAVA_HOME 'bin')+';'+$env:PATH
    $mobileTool=Join-Path $env:USERPROFILE 'go/bin/gomobile.exe'
    if (-not (Test-Path -LiteralPath $mobileTool)) { throw 'Install gomobile before building the library' }
    $outputDir=Join-Path $projectRoot 'artifacts/android'
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    $output=Join-Path $outputDir $OutputName
    # A cancelled bind must never truncate the last usable library.
    $stagedOutput=Join-Path $outputDir ('.'+[IO.Path]::GetFileNameWithoutExtension($OutputName)+'.'+[guid]::NewGuid().ToString('N')+'.aar')
    $stagedSources=Join-Path $outputDir ([IO.Path]::GetFileNameWithoutExtension($stagedOutput)+'-sources.jar')
    # gomobile records absolute local module replacements in Go build info.
    # A neutral drive alias keeps the Windows account name out of the AAR.
    foreach($letter in @('R','Q','P','O')) {
        if(-not (Test-Path ($letter+':/'))) {$mappedDrive=$letter+':';break}
    }
    if(-not $mappedDrive){throw 'No unused drive alias available for a private build'}
    & subst $mappedDrive $projectRoot
    if($LASTEXITCODE){throw 'Cannot create neutral Android build path'}
    Push-Location ($mappedDrive+'/client/android')
    try {
        # gomobile creates a temporary module with a shorter go directive.
        # Reuse this module's resolved toolchain instead of selecting a newer
        # release again when tidy discovers our local shared dependency.
        $buildGoRoot=(& go env GOROOT)
        if ($LASTEXITCODE -ne 0 -or -not $buildGoRoot) { throw 'Cannot resolve the Android module Go toolchain' }
        $env:PATH=(Join-Path $buildGoRoot.Trim() 'bin')+';'+$env:PATH
        $env:GOTOOLCHAIN='local'
        $targets = if ($AllAbis) { 'android/arm64,android/arm,android/386,android/amd64' } else { 'android/arm64,android/arm' }
        & $mobileTool bind "-target=$targets" -androidapi 24 -trimpath '-ldflags=-s -w' -o $stagedOutput .
        if ($LASTEXITCODE -ne 0) { throw 'Android native library build failed' }
    } finally { Pop-Location }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($stagedOutput)
    try {
        $entries = @('classes.jar','jni/arm64-v8a/libgojni.so','jni/armeabi-v7a/libgojni.so')
        if ($AllAbis) { $entries += @('jni/x86/libgojni.so','jni/x86_64/libgojni.so') }
        foreach($entry in $entries) {
            $member=$archive.GetEntry($entry)
            if($null -eq $member -or $member.Length -eq 0){throw "Incomplete AAR: $entry missing"}
            $stream=$member.Open()
            try {$stream.CopyTo([IO.Stream]::Null)} finally {$stream.Dispose()}
        }
    } finally {$archive.Dispose()}
    if(Test-Path -LiteralPath $output){[IO.File]::Replace($stagedOutput,$output,[System.Management.Automation.Language.NullString]::Value)}
    else {[IO.File]::Move($stagedOutput,$output)}
    $outputSources=Join-Path $outputDir ([IO.Path]::GetFileNameWithoutExtension($output)+'-sources.jar')
    if(Test-Path -LiteralPath $stagedSources) {
        if(Test-Path -LiteralPath $outputSources){[IO.File]::Replace($stagedSources,$outputSources,[System.Management.Automation.Language.NullString]::Value)}
        else {[IO.File]::Move($stagedSources,$outputSources)}
    }
    Get-FileHash -LiteralPath $output -Algorithm SHA256
} finally {
    if($mappedDrive){& subst $mappedDrive /D}
    foreach($stage in @($stagedOutput,$stagedSources)) {
        if($stage -and (Test-Path -LiteralPath $stage -PathType Leaf)) {Remove-Item -LiteralPath $stage -ErrorAction SilentlyContinue}
    }
    $env:JAVA_HOME=$savedJava;$env:ANDROID_HOME=$savedAndroid;$env:PATH=$savedPath
    $env:GOOS=$savedGoOs;$env:GOARCH=$savedGoArch;$env:CGO_ENABLED=$savedCgo
    $env:GOTOOLCHAIN=$savedGoToolchain
}
