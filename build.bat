@echo off
REM Build script for minimal .NET Framework 4.7 executable

set MSBUILD=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe

echo Building ToolLauncher.exe...
%MSBUILD% ToolLauncher.csproj /p:Configuration=Release /nologo /v:minimal

if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    for %%A in (ToolLauncher.exe) do echo File size: %%~zA bytes

    REM Clean up extra files created by MSBuild
    del /q *.nlp 2>nul
    del /q *.pdb 2>nul
    del /q mscorlib.dll 2>nul
) else (
    echo Build failed!
)
