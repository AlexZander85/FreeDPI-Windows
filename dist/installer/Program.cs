using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

const string ServiceName = "FreeDPI";
const string TargetDir = "C:\\Program Files\\FreeDPI";
const string ExeName = "freedpi-service.exe";
const string SysName = "WinDivert64.sys";
const string UiName = "ByeByeDPI.exe";

// ---- Elevation check ----
if (!IsAdministrator())
{
    var exePath = Environment.ProcessPath!;
    var psi = new ProcessStartInfo
    {
        FileName = exePath,
        UseShellExecute = true,
        Verb = "runas",
    };
    try
    {
        Process.Start(psi)?.WaitForExit();
    }
    catch
    {
        Console.Error.WriteLine("ERROR: Administrator privileges required.");
        WaitAndExit(1);
    }
    return;
}

Console.WriteLine("============================================");
Console.WriteLine(" FreeDPI — Windows DPI Bypass Service Setup");
Console.WriteLine("============================================");
Console.WriteLine();

// ---- Step 1: Create directory ----
Console.Write("[1/5] Creating installation directory... ");
Directory.CreateDirectory(TargetDir);
Console.WriteLine("OK");

// ---- Step 2: Extract files ----
Console.Write("[2/5] Extracting files... ");
var asm = Assembly.GetExecutingAssembly();
ExtractResource(asm, ExeName, Path.Combine(TargetDir, ExeName));
ExtractResource(asm, SysName, Path.Combine(TargetDir, SysName));
ExtractResource(asm, UiName, Path.Combine(TargetDir, UiName));
Console.WriteLine("OK");

// ---- Step 3: Register service ----
Console.Write("[3/5] Registering FreeDPI service... ");
var result = RunProcess(Path.Combine(TargetDir, ExeName), "--install");
if (result.ExitCode != 0)
{
    Console.Error.WriteLine($"FAILED (exit code {result.ExitCode})");
    Console.Error.WriteLine(result.Stderr);
    WaitAndExit(1);
}
Console.WriteLine("OK");

// ---- Step 4: Start service ----
Console.Write("[4/5] Starting service... ");
result = RunProcess("sc", $"start {ServiceName}");
if (result.ExitCode == 0)
{
    Console.WriteLine("OK");
}
else if (result.ExitCode == 1056) // SERVICE_ALREADY_RUNNING
{
    Console.WriteLine("Already running.");
}
else
{
    Console.WriteLine($"WARNING: Could not start service (exit code {result.ExitCode}).");
    Console.WriteLine("Try: net start FreeDPI");
}

// ---- Step 5: Create shortcuts ----
Console.Write("[5/5] Creating shortcuts... ");
try
{
    var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    var startMenu = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
        "Programs", "FreeDPI");

    Directory.CreateDirectory(startMenu);

    // Desktop shortcut
    CreateShortcut(
        Path.Combine(desktop, "FreeDPI.lnk"),
        Path.Combine(TargetDir, UiName),
        TargetDir);

    // Start Menu shortcut
    CreateShortcut(
        Path.Combine(startMenu, "FreeDPI.lnk"),
        Path.Combine(TargetDir, UiName),
        TargetDir);

    // Start Menu — Service Manager shortcut
    CreateShortcut(
        Path.Combine(startMenu, "Stop FreeDPI Service.lnk"),
        "net",
        null,
        "stop FreeDPI");

    Console.WriteLine("OK");
}
catch (Exception ex)
{
    Console.WriteLine($"WARNING: Could not create shortcuts ({ex.Message})");
}

Console.WriteLine();
Console.WriteLine("============================================");
Console.WriteLine(" SUCCESS: FreeDPI is installed!");
Console.WriteLine("============================================");
Console.WriteLine();
Console.WriteLine("  Service:  FreeDPI");
Console.WriteLine("  API:      http://127.0.0.1:11337");
Console.WriteLine("  Config:   " + Path.Combine(TargetDir, "config.toml"));
Console.WriteLine("  UI:       " + Path.Combine(TargetDir, UiName));
Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// ─── Helper methods ─────────────────────────────────────────────────────

static bool IsAdministrator()
{
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    var principal = new System.Security.Principal.WindowsPrincipal(identity);
    return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}

static void ExtractResource(Assembly asm, string resourceName, string outputPath)
{
    var fullName = asm.GetManifestResourceNames()
        .FirstOrDefault(n => n.EndsWith(resourceName))
        ?? throw new FileNotFoundException($"Embedded resource '{resourceName}' not found.");

    using var stream = asm.GetManifestResourceStream(fullName)
        ?? throw new FileNotFoundException($"Cannot open resource stream for '{resourceName}'.");

    using var fileStream = File.Create(outputPath);
    stream.CopyTo(fileStream);
}

static (int ExitCode, string Stdout, string Stderr) RunProcess(string file, string args)
{
    var psi = new ProcessStartInfo
    {
        FileName = file,
        Arguments = args,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
    };
    var proc = Process.Start(psi) ?? throw new InvalidOperationException($"Cannot start '{file}'.");
    proc.WaitForExit(60000);
    var stdout = proc.StandardOutput.ReadToEnd();
    var stderr = proc.StandardError.ReadToEnd();
    return (proc.ExitCode, stdout, stderr);
}

static void CreateShortcut(string shortcutPath, string targetPath, string? workingDir, string? arguments = null)
{
    var shellType = Type.GetTypeFromCLSID(new Guid("72C24DD5-D70A-438B-8A42-98424B88AFB8"));
    if (shellType == null) throw new InvalidOperationException("Cannot create WScript.Shell COM object.");

    dynamic? shell = Activator.CreateInstance(shellType);
    if (shell == null) throw new InvalidOperationException("Cannot create WScript.Shell COM object.");

    try
    {
        var shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = targetPath;
        shortcut.WorkingDirectory = workingDir ?? "";
        if (arguments != null) shortcut.Arguments = arguments;
        shortcut.Save();
    }
    finally
    {
        Marshal.ReleaseComObject(shell);
    }
}

static void WaitAndExit(int code)
{
    Console.WriteLine("Press any key to exit...");
    Console.ReadKey();
    Environment.Exit(code);
}
