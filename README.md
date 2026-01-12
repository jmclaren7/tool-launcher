# ToolLauncher

A lightweight Windows application for downloading and running tools from a central web server.

## Features

- **Download and run** - Downloads the selected tool from your web server and runs it automatically
- **Lightweight** - Single executable (~23KB)
- **Admin elevation** - Right-click any tool for a "Run as Administrator" option, or add `[admin]` to the tool name for automatic elevation
- **Program icons** - The web server script automatically extracts icons from .exe files and displays them in the tool list
- **Download progress** - Shows download progress so you know large tools are actually downloading
- **App packages** - Zip multiple files together into a .scapp file - extracts automatically (Same technique as the ScreenConnect toolbox)
- **Key authentication** - Configure a key so tools are not publicly downloadable without the program
- **Wide compatibility** - Uses .NET Framework 4.7, available on Windows 8.1 and later by default

## Requirements

### Client
- Windows with .NET Framework 4.7

### Server
- PHP 8.2 or later
- GD extension (for icon extraction)

## Setup

### Server Setup

1. Upload `index.php` to your web server
2. Create a `data` folder in the same directory and upload your tools to it
   - Recommended: Block direct download access to files using the preferred method on your web server. Most web servers will not allow access to "dot" files, you could change the folder name to ".data"
   - Update the path in index.php if it differs
3. Place your tools (executables, scripts, etc.) in the `data` folder
4. Edit `index.php` and set your own `$validKey` value
5. Optionally set `$enableDebug = true` for troubleshooting

### Client Setup

1. Rename AppConfig.example.cs to AppConfig.cs and configure it's values (ApiUrl, ApiKey, Title)
2. Build the application using `build.bat`
3. Run `ToolLauncher.exe`
   - Optional: Use your server URL as a parameter

## Supported File Types

| Extension | Action |
|-----------|--------|
| .exe | Run directly |
| .msi | Installs with msiexec (not silent) |
| .ps1 | Run with PowerShell (bypass execution policy) |
| .bat, .cmd | Run with cmd.exe |
| .scapp | Extract and run `_a.bat` or `a.bat` |
| Other | Open with default program |

## Building

Run `build.bat` to compile the application. Requires .NET Framework 4.7 SDK or the build tools included with Windows.

```batch
build.bat
```

## TODO List

### Security

- Enforce HTTPS in tool downloads if server URL is HTTPS
- Sanitize or validate filenames from JSON data.

### Other

- Cleanup `LoadData`, `imageList.Images`, `extensionIconMap`
- Cleanup temporary files from tools
- Control timeouts in app and server script
- Review blocking UI calls if timeouts aren't enough
