using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[DataContract]
public class AppItem
{
    [DataMember(Name = "name")]
    public string Name { get; set; }
    
    [DataMember(Name = "size")]
    public string Size { get; set; }
    
    [DataMember(Name = "file")]
    public string File { get; set; }

    [DataMember(Name = "icon")]
    public string Icon { get; set; }

    [DataMember(Name = "children")]
    public List<AppItem> Children { get; set; }
}

[DataContract]
public class AppList
{
    [DataMember(Name = "items")]
    public List<AppItem> Items { get; set; }
}

public class MainForm : Form
{
    // Icon indices
    private const int IconFolder = 0;
    private Dictionary<string, int> extensionIconMap;

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes,
        ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string szTypeName;
    }

    private const uint SHGFI_ICON = 0x100;
    private const uint SHGFI_SMALLICON = 0x1;
    private const uint SHGFI_USEFILEATTRIBUTES = 0x10;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;

    [DllImport("shell32.dll", CharSet = CharSet.Auto)]
    private static extern uint ExtractIconEx(string lpszFile, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

    private TreeView treeView;
    private Label statusLabel;
    private Button refreshButton;
    private TextBox urlTextBox;
    private ContextMenuStrip contextMenu;
    private ImageList imageList;
    private string jsonUrl;

    public MainForm(string url)
    {
        jsonUrl = url;
        InitializeComponents();
        LoadData();
    }

    private void InitializeComponents()
    {
        this.Text = AppConfig.Title;
        this.Size = new Size(500, 500);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.MinimumSize = new Size(400, 300);
        this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        var urlLabel = new Label
        {
            Text = "Tools URL:",
            Location = new Point(10, 12),
            AutoSize = true
        };

        urlTextBox = new TextBox
        {
            Text = jsonUrl,
            Location = new Point(80, 10),
            Width = 320,
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
        };

        refreshButton = new Button
        {
            Text = "Load",
            Location = new Point(410, 8),
            Width = 60,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        refreshButton.Click += RefreshButton_Click;

        // Create context menu
        contextMenu = new ContextMenuStrip();
        var runItem = new ToolStripMenuItem("Run");
        runItem.Click += ContextMenu_Run_Click;
        var runAsAdminItem = new ToolStripMenuItem("Run as Administrator");
        runAsAdminItem.Click += ContextMenu_RunAsAdmin_Click;
        contextMenu.Items.Add(runItem);
        contextMenu.Items.Add(runAsAdminItem);

        // Create image list with system icons
        imageList = new ImageList { ColorDepth = ColorDepth.Depth32Bit, ImageSize = new Size(16, 16) };
        extensionIconMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        imageList.Images.Add(GetSystemIcon(null, true)); // 0: Folder

        // Add icons for common file types and build extension map
        string[] commonFileTypes = { ".ps1", ".bat", ".cmd", ".msc", ".txt", ".pdf", ".zip", ".rar", ".msi", ".7z", ".reg", ".exe" };
        for (int i = 0; i < commonFileTypes.Length; i++)
        {
            imageList.Images.Add(GetSystemIcon(commonFileTypes[i], false));
            extensionIconMap[commonFileTypes[i]] = i + 1; // +1 because folder is index 0
        }

        // Add .scapp icon from imageres.dll
        var scappIcon = GetIconFromDll("imageres.dll", 95);
        imageList.Images.Add(scappIcon ?? GetSystemIcon(".zip", false));
        extensionIconMap[".scapp"] = imageList.Images.Count - 1;

        treeView = new TreeView
        {
            Location = new Point(10, 40),
            Size = new Size(460, 380),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            TreeViewNodeSorter = new NodeSorter(),
            ImageList = imageList
        };
        treeView.Font = new Font(treeView.Font.FontFamily, treeView.Font.Size + AppConfig.FontSizeIncrease);
        treeView.NodeMouseClick += TreeView_NodeMouseClick;
        treeView.NodeMouseDoubleClick += TreeView_NodeMouseDoubleClick;

        statusLabel = new Label
        {
            Text = "Ready",
            Location = new Point(10, 430),
            Size = new Size(460, 20),
            AutoSize = false,
            AutoEllipsis = true,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };

        this.Controls.Add(urlLabel);
        this.Controls.Add(urlTextBox);
        this.Controls.Add(refreshButton);
        this.Controls.Add(treeView);
        this.Controls.Add(statusLabel);
    }

    private void RefreshButton_Click(object sender, EventArgs e)
    {
        jsonUrl = urlTextBox.Text;
        LoadData();
    }

    private void LoadData()
    {
        treeView.Nodes.Clear();
        statusLabel.Text = "Loading...";
        Application.DoEvents();

        try
        {
            string json;
            
            if (jsonUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                jsonUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                string separator = jsonUrl.Contains("?") ? "&" : "?";
                string urlWithKey = jsonUrl + separator + "key=" + Uri.EscapeDataString(AppConfig.ApiKey);
                using (var client = new WebClient())
                {
                    json = client.DownloadString(urlWithKey);
                }
            }
            else
            {
                json = File.ReadAllText(jsonUrl);
            }

            var serializer = new DataContractJsonSerializer(typeof(AppList));
            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                var appList = (AppList)serializer.ReadObject(stream);
                PopulateTree(appList);
            }

            statusLabel.Text = "Loaded successfully. Double-click or right-click an item to download and run.";
        }
        catch (Exception ex)
        {
            statusLabel.Text = "Error: " + ex.Message;
            MessageBox.Show("Failed to load data: " + ex.Message, "Error", 
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void PopulateTree(AppList appList)
    {
        if (appList == null || appList.Items == null) return;

        foreach (var item in appList.Items)
        {
            var node = CreateTreeNode(item);
            treeView.Nodes.Add(node);
        }

        treeView.CollapseAll();
    }

    private TreeNode CreateTreeNode(AppItem item)
    {
        TreeNode node;
        int iconIndex;

        // Check if this is a file (has File path) or folder (has children or no File)
        bool isFile = !string.IsNullOrEmpty(item.File);

        if (isFile)
        {
            // File node - show name with size
            string displayText = string.IsNullOrEmpty(item.Size)
                ? item.Name
                : string.Format("{0} ({1})", item.Name, item.Size);
            node = new TreeNode(displayText);

            // Check for custom icon from server (base64 PNG)
            if (!string.IsNullOrEmpty(item.Icon))
            {
                try
                {
                    byte[] iconBytes = Convert.FromBase64String(item.Icon);
                    using (var ms = new MemoryStream(iconBytes))
                    {
                        var img = Image.FromStream(ms);
                        imageList.Images.Add(img);
                        iconIndex = imageList.Images.Count - 1;
                    }
                }
                catch
                {
                    // Fall back to default icon on decode failure
                    iconIndex = extensionIconMap[".exe"];
                }
            }
            else
            {
                // Determine icon based on file extension using the map
                string ext = Path.GetExtension(item.File);
                if (!extensionIconMap.TryGetValue(ext, out iconIndex))
                {
                    iconIndex = extensionIconMap[".exe"]; // Default to exe icon
                }
            }
        }
        else
        {
            // Folder node - just show name
            node = new TreeNode(item.Name);
            iconIndex = IconFolder;
        }

        node.Tag = item;
        node.ImageIndex = iconIndex;
        node.SelectedImageIndex = iconIndex;

        // Recursively add children
        if (item.Children != null)
        {
            foreach (var child in item.Children)
            {
                node.Nodes.Add(CreateTreeNode(child));
            }
        }

        return node;
    }

    private Icon GetSystemIcon(string extension, bool isFolder)
    {
        SHFILEINFO shfi = new SHFILEINFO();
        uint flags = SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES;
        uint attributes = isFolder ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
        string path = isFolder ? "folder" : "file" + extension;

        SHGetFileInfo(path, attributes, ref shfi, (uint)Marshal.SizeOf(shfi), flags);

        if (shfi.hIcon != IntPtr.Zero)
        {
            Icon icon = Icon.FromHandle(shfi.hIcon);
            Icon clonedIcon = (Icon)icon.Clone();
            DestroyIcon(shfi.hIcon);
            return clonedIcon;
        }

        return SystemIcons.Application;
    }

    private Icon GetIconFromDll(string dllName, int iconIndex)
    {
        string dllPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), dllName);
        IntPtr[] smallIcons = new IntPtr[1];

        uint count = ExtractIconEx(dllPath, iconIndex, null, smallIcons, 1);
        if (count > 0 && smallIcons[0] != IntPtr.Zero)
        {
            Icon icon = Icon.FromHandle(smallIcons[0]);
            Icon clonedIcon = (Icon)icon.Clone();
            DestroyIcon(smallIcons[0]);
            return clonedIcon;
        }

        return null;
    }

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private void TreeView_NodeMouseClick(object sender, TreeNodeMouseClickEventArgs e)
    {
        if (e.Button == MouseButtons.Right)
        {
            treeView.SelectedNode = e.Node;
            var item = e.Node.Tag as AppItem;
            if (item != null && !string.IsNullOrEmpty(item.File))
            {
                contextMenu.Show(treeView, e.Location);
            }
        }
    }

    private void TreeView_NodeMouseDoubleClick(object sender, TreeNodeMouseClickEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;

        // Only run if the double-clicked node is the selected node
        // This prevents running a file when double-clicking a folder to expand it
        // (the folder expands on first click, second click lands on a different node)
        if (e.Node != treeView.SelectedNode) return;

        var item = e.Node.Tag as AppItem;
        if (item != null && !string.IsNullOrEmpty(item.File))
        {
            DownloadAndRun(item, false);
        }
    }

    private void ContextMenu_Run_Click(object sender, EventArgs e)
    {
        if (treeView.SelectedNode == null) return;
        var item = treeView.SelectedNode.Tag as AppItem;
        if (item == null || string.IsNullOrEmpty(item.File)) return;
        DownloadAndRun(item, false);
    }

    private void ContextMenu_RunAsAdmin_Click(object sender, EventArgs e)
    {
        if (treeView.SelectedNode == null) return;
        var item = treeView.SelectedNode.Tag as AppItem;
        if (item == null || string.IsNullOrEmpty(item.File)) return;
        DownloadAndRun(item, true);
    }

    private void DownloadAndRun(AppItem item, bool runAsAdmin = false)
    {
        // Auto-elevate if name contains [admin]
        if (item.Name.IndexOf("[admin]", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            runAsAdmin = true;
        }

        statusLabel.Text = "Downloading " + item.Name + "...";
        Application.DoEvents();

        try
        {
            // Extract file extension from the file path
            string extension = GetFileExtension(item.File);

            string tempPath = Path.Combine(Path.GetTempPath(), item.Name + extension);

            // Build download URL through index.php
            string separator = jsonUrl.Contains("?") ? "&" : "?";
            string downloadUrl = jsonUrl + separator + "key=" + Uri.EscapeDataString(AppConfig.ApiKey)
                               + "&file=" + Uri.EscapeDataString(item.File);
            Uri uri = new Uri(downloadUrl);

            // Parse expected file size from JSON for progress calculation
            long expectedSize = ParseSizeString(item.Size);

            using (var client = new WebClient())
            {
                bool completed = false;
                Exception downloadError = null;

                client.DownloadProgressChanged += (s, e) =>
                {
                    int percent;
                    if (expectedSize > 0)
                    {
                        percent = (int)((e.BytesReceived * 100) / expectedSize);
                        if (percent > 100) percent = 100;
                    }
                    else
                    {
                        percent = e.ProgressPercentage;
                    }
                    statusLabel.Text = string.Format("Downloading {0}... {1}%", item.Name, percent);
                };

                client.DownloadFileCompleted += (s, e) =>
                {
                    if (e.Error != null) downloadError = e.Error;
                    completed = true;
                };

                client.DownloadFileAsync(uri, tempPath);

                while (!completed)
                {
                    Application.DoEvents();
                    Thread.Sleep(10);
                }

                if (downloadError != null) throw downloadError;
            }

            statusLabel.Text = "Running " + item.Name + (runAsAdmin ? " as Administrator" : "") + "...";

            ProcessStartInfo psi;

            switch (extension)
            {
                case ".exe":
                    psi = new ProcessStartInfo(tempPath);
                    break;

                case ".msi":
                    psi = new ProcessStartInfo("msiexec.exe", "/i \"" + tempPath + "\"");
                    break;

                case ".ps1":
                    psi = new ProcessStartInfo("powershell.exe", "-ExecutionPolicy Bypass -File \"" + tempPath + "\"");
                    break;

                case ".bat":
                case ".cmd":
                    psi = new ProcessStartInfo("cmd.exe", "/c \"" + tempPath + "\"");
                    break;

                case ".app.zip":
                case ".scapp":
                    // Extract zip to temp folder and run first matching batch file
                    string extractPath = Path.Combine(Path.GetTempPath(), "scapp_" + Path.GetFileNameWithoutExtension(item.Name));
                    if (Directory.Exists(extractPath))
                    {
                        Directory.Delete(extractPath, true);
                    }
                    ZipFile.ExtractToDirectory(tempPath, extractPath);

                    // Find all batch files and sort them using standard Windows sorting
                    string[] batFiles = Directory.GetFiles(extractPath, "*.bat");
                    
                    if (batFiles.Length == 0)
                    {
                         throw new FileNotFoundException("No .bat file found in scapp package.");
                    }

                    Array.Sort(batFiles, new WindowsExplorerComparer());
                    string batPath = batFiles[0];

                    psi = new ProcessStartInfo("cmd.exe", "/c \"" + batPath + "\"")
                    {
                        WorkingDirectory = extractPath
                    };
                    break;

                default:
                    // Use shell execute for unknown types (opens with default program)
                    psi = new ProcessStartInfo(tempPath)
                    {
                        UseShellExecute = true
                    };
                    break;
            }

            if (runAsAdmin)
            {
                psi.UseShellExecute = true;
                psi.Verb = "runas";
            }

            Process.Start(psi);
            statusLabel.Text = "Launched " + item.Name;
        }
        catch (Exception ex)
        {
            statusLabel.Text = "Error: " + ex.Message;
            MessageBox.Show("Failed to download or run: " + ex.Message, "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private string GetFileExtension(string fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return string.Empty;

        // Check for double extensions
        string[] doubleExtensions = { ".tar.gz", ".tar.bz2", ".tar.xz", ".app.zip" };
        foreach (var ext in doubleExtensions)
        {
            if (fileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return ext.ToLowerInvariant();
            }
        }

        string extension = Path.GetExtension(fileName);
        return string.IsNullOrEmpty(extension) ? string.Empty : extension.ToLowerInvariant();
    }

    private long ParseSizeString(string sizeStr)
    {
        if (string.IsNullOrEmpty(sizeStr)) return 0;

        sizeStr = sizeStr.Trim().ToUpperInvariant();

        // Try to extract number and unit
        double value = 0;
        string unit = "";

        int i = 0;
        while (i < sizeStr.Length && (char.IsDigit(sizeStr[i]) || sizeStr[i] == '.'))
        {
            i++;
        }

        if (i == 0) return 0;

        if (!double.TryParse(sizeStr.Substring(0, i), out value)) return 0;

        unit = sizeStr.Substring(i).Trim();

        if (unit.StartsWith("GB"))
            return (long)(value * 1073741824);
        else if (unit.StartsWith("MB"))
            return (long)(value * 1048576);
        else if (unit.StartsWith("KB"))
            return (long)(value * 1024);
        else
            return (long)value;
    }
}

public class WindowsExplorerComparer : IComparer<string>, IComparer
{
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int StrCmpLogicalW(string x, string y);

    public int Compare(string x, string y)
    {
        return StrCmpLogicalW(x, y);
    }

    public int Compare(object x, object y)
    {
        return Compare(x as string, y as string);
    }
}

public class NodeSorter : IComparer
{
    public int Compare(object x, object y)
    {
        TreeNode tx = x as TreeNode;
        TreeNode ty = y as TreeNode;
        if (tx == null || ty == null) return 0;
        return string.Compare(tx.Text, ty.Text, StringComparison.OrdinalIgnoreCase);
    }
}

class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        // Enable TLS 1.2 for HTTPS connections (required for modern servers)
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
        
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        string url = args.Length > 0 ? args[0] : AppConfig.ApiUrl;
        Application.Run(new MainForm(url));
    }
}
