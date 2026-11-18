# 打包便携版：dist\解压开镜-<版本>-win64.zip
# 用法：pwsh tools\build-release.ps1 -Version 0.1.0
param([string]$Version = "0.1.0")

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo build 失败" }

    $name = "解压开镜-$Version"
    $dist = Join-Path $root "dist"
    $dir = Join-Path $dist $name
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    Copy-Item -LiteralPath "target\release\jieya-app.exe" -Destination $dir
    Copy-Item -LiteralPath "target\release\jieya.exe" -Destination $dir
    Copy-Item -LiteralPath "README.md" -Destination $dir
    Copy-Item -LiteralPath "docs" -Destination (Join-Path $dir "docs") -Recurse

    $note = @"
解压开镜 $Version（Rust + Tauri 便携版）

1. 双击 jieya-app.exe 启动图形界面。
2. 依赖系统已安装 7-Zip（7z.exe）。若不在默认位置，在「设置」里填 7z.exe 路径，
   或设置环境变量 SEVENZIP_PATH。
3. jieya.exe 是命令行版，用法：jieya extract <路径> --sevenzip <7z.exe>。
4. 密码库与任务库在 %LOCALAPPDATA%\解压开镜\data\jieya.db，可直接沿用 Python 版老库。
5. 资源管理器右键菜单：设置里点「添加右键菜单」（仅写 HKCU，不需要管理员）。
"@
    Set-Content -LiteralPath (Join-Path $dir "使用说明.txt") -Value $note -Encoding UTF8

    $zip = Join-Path $dist "$name-win64.zip"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    Compress-Archive -Path (Join-Path $dir "*") -DestinationPath $zip
    Get-ChildItem -LiteralPath $zip | Select-Object FullName, Length
} finally {
    Pop-Location
}
