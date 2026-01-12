# ToolLauncher

A lightweight Windows application for downloading and running tools from a central web server.

<p align="center">
<img width="480" height="377" alt="Screenshot1" src="https://github.com/user-attachments/assets/f1fd9a86-a6bb-44dd-8619-6ae211001690" />
</p>

## Features

- **Download and run** - Downloads the selected tool from your web server and runs it automatically
- **Lightweight** - Single executable (~23KB)
- **Admin elevation** - Right-click any tool for a "Run as Administrator" option, or add `[admin]` to the tool name for automatic elevation
- **Program icons** - The web server script automatically extracts icons from .exe files and displays them in the tool list
- **Download progress** - Shows download progress so you know large tools are actually downloading
- **App packages** - Zip multiple files together into a .scapp file - extracts automatically (Same technique as the ScreenConnect toolbox)
- **Key authentication** - Configure a key so tools are not publicly downloadable without the program
- **Wide compatibility** - Uses .NET Framework 4.7, available by default since  Windows 10 v1703 and often available on older Windows versions

## Setup

### Server Setup

Requirements: PHP 8.2 or later, GD extension (for icon extraction)

1. Upload `index.php` to your web server
2. Create a `data` folder in the same directory as `index.php`
   - Recommended: Block direct access to `data` using the preferred method on your web server
   - Update the path in index.php if not using `data`
3. Upload your tools (executables, scripts, etc.) in the `data` folder and subfolders
4. Edit `index.php` and set your own `$validKey` value
5. Optionally set `$enableDebug = true` for troubleshooting

### Client Setup / Build

Requirements: Windows with .NET 4.7 Framework or SDK

1. Rename AppConfig.example.cs to AppConfig.cs and configure it's values (ApiUrl, ApiKey, Title)
2. Build the application using `build.bat`
3. Run `ToolLauncher.exe`

## Supported File Types

| Extension | Action |
|-----------|--------|
| .exe | Run directly |
| .msi | Installs with msiexec (not silent) |
| .ps1 | Run with PowerShell (bypass execution policy) |
| .bat, .cmd | Run with cmd.exe |
| .scapp, .app.zip | Extract zip and run the first `.bat` found (e.g. `a.bat`) |
| Other | Open with default program |

## To Do

### Security

- Enforce HTTPS in tool downloads if server URL is HTTPS
- Sanitize or validate filenames from JSON data.

### Other

- Cleanup `LoadData`, `imageList.Images`, `extensionIconMap`
- Cleanup temporary files from tools
- Control timeouts in app and server script
- Review blocking UI calls if timeouts aren't enough
