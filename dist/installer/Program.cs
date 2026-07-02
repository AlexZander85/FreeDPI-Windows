using System.Diagnostics;
using System.Reflection;

const string ServiceName = "FreeDPI";
const string TargetDir = "C:\\Program Files\\FreeDPI";
const string ExeName = "freedpi-service.exe";
const string SysName = "WinDivert64.sys";

// ---- Elevation check ----
if (!IsAdministrator())
{
    // Self-elevate
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
Console.Write("[1/4] Creating installation directory... ");
Directory.CreateDirectory(TargetDir);
Console.WriteLine("OK");

// ---- Step 2: Extract embedded resources ----
Console.Write("[2/4] Extracting files... ");
var asm = Assembly.GetExecutingAssembly();
ExtractResource(asm, ExeName, Path.Combine(TargetDir, ExeName));
ExtractResource(asm, SysName, Path.Combine(TargetDir, SysName));
Console.WriteLine("OK");

// ---- Step 3: Register service ----
Console.Write("[3/4] Registering FreeDPI service... ");
var result = RunProcess(Path.Combine(TargetDir, ExeName), "--install");
if (result.ExitCode != 0)
{
    Console.Error.WriteLine($"FAILED (exit code {result.ExitCode})");
    Console.Error.WriteLine(result.Stderr);
    WaitAndExit(1);
}
Console.WriteLine("OK");

// ---- Step 4: Start service ----
Console.Write("[4/4] Starting service... ");
result = RunProcess("sc", $"start {ServiceName}");
if (result.ExitCode == 0)
{
    Console.WriteLine("OK");
    Console.WriteLine();
    Console.WriteLine("SUCCESS: FreeDPI is now running.");
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

Console.WriteLine();
Console.WriteLine("  Service:  FreeDPI");
Console.WriteLine("  API:      http://127.0.0.1:8080");
Console.WriteLine("  Config:   " + Path.Combine(TargetDir, "config.toml"));
Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// ---- Helper methods ----
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
    proc.WaitForExit(60000); // 60s timeout
    var stdout = proc.StandardOutput.ReadToEnd();
    var stderr = proc.StandardError.ReadToEnd();
    return (proc.ExitCode, stdout, stderr);
}

static void WaitAndExit(int code)
{
    Console.WriteLine("Press any key to exit...");
    Console.ReadKey();
    Environment.Exit(code);
}
