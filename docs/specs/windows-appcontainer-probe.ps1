<#
.SYNOPSIS
  Measures what an AppContainer with NO capabilities can actually do on this
  machine, unelevated.

.DESCRIPTION
  docs/specs/windows-sandbox-design.md proposes running the agent in an
  AppContainer with no network capability, reaching approved hosts only through
  a broker over a named pipe. Four things in that design are reasoned, not
  measured. This probe measures them.

  Question 4 is the one that changes the design:

    Can a process inside an AppContainer bind and listen on loopback?

  If it CAN, the Linux/macOS model transfers: a shim listens on loopback inside
  the sandbox, speaks HTTP-proxy protocol, and unmodified `pip` works. If it
  CANNOT, Windows must be capability-mediated — code has to *ask* the broker
  rather than *connect* — package installation moves into the broker's trust
  domain, and a notebook cell can never fetch a URL directly.

  Nothing here installs anything, needs a compiler, or touches the network
  except to attempt one outbound connection that is EXPECTED to fail.

.PARAMETER Name
  AppContainer profile name. Reused if it already exists; deleted on exit
  unless -Keep is passed.

.PARAMETER Keep
  Leave the profile behind for inspection.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\windows-appcontainer-probe.ps1
#>
[CmdletBinding()]
param(
  [string] $Name = "openscience-probe",
  [switch] $Keep
)

$ErrorActionPreference = "Stop"

function Say([string] $text, [string] $colour = "Gray") { Write-Host $text -ForegroundColor $colour }
function Result([string] $label, [bool] $value, [string] $expected) {
  $mark = if ($value) { "YES" } else { "NO " }
  $colour = if ($expected -eq "either") { "Cyan" } elseif (($expected -eq "yes") -eq $value) { "Green" } else { "Red" }
  Say ("  {0,-52} {1}" -f $label, $mark) $colour
}

# ── Elevation ────────────────────────────────────────────────────────────────
# The entire premise of the design is that OpenScience never asks for admin.
# A probe run elevated would answer a question nobody asked.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

Say ""
Say "OpenScience — Windows AppContainer probe" "White"
Say ("  user            : {0}" -f $identity.Name)
Say ("  elevated        : {0}" -f $elevated) $(if ($elevated) { "Yellow" } else { "Green" })
Say ("  windows         : {0}" -f [Environment]::OSVersion.Version)
Say ("  powershell      : {0}" -f $PSVersionTable.PSVersion)
if ($elevated) {
  Say ""
  Say "  WARNING: running elevated. The design's whole claim is that none of" "Yellow"
  Say "  this needs admin, so re-run in a NORMAL terminal for a valid answer." "Yellow"
}
Say ""

# ── Win32 interop ────────────────────────────────────────────────────────────
# Inline C# rather than raw PowerShell marshalling: UpdateProcThreadAttribute
# with a SECURITY_CAPABILITIES blob is where a hand-marshalled version goes
# subtly wrong and reports a false negative.
if (-not ("OpenScience.AppContainer" -as [type])) {
  Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenScience {
  [StructLayout(LayoutKind.Sequential)]
  public struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

  [StructLayout(LayoutKind.Sequential)]
  public struct SecurityCapabilities {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
    public uint Reserved;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct StartupInfoEx {
    public int cb; public IntPtr lpReserved, lpDesktop, lpTitle;
    public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    public short wShowWindow, cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError, lpAttributeList;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct ProcessInformation { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

  public static class AppContainer {
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_NO_WINDOW            = 0x08000000;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = (IntPtr)0x00020009;

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int CreateAppContainerProfile(string name, string display, string description,
      IntPtr capabilities, uint capabilityCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeleteAppContainerProfile(string name);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSidToSid(string str, out IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LocalFree(IntPtr p);

    [DllImport("userenv.dll")]
    static extern void FreeSid(IntPtr sid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute,
      IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcess(string application, StringBuilder commandLine,
      IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
      IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation info);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr handle, out uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr handle, uint code);

    static string SidToString(IntPtr sid) {
      IntPtr str;
      if (!ConvertSidToStringSid(sid, out str)) throw new Win32Exception(Marshal.GetLastWin32Error());
      try { return Marshal.PtrToStringUni(str); } finally { LocalFree(str); }
    }

    /// Creates the profile, or derives the SID if it already exists.
    /// Returns "S-1-15-2-..." and whether the profile was newly created.
    public static string EnsureProfile(string name, out bool created, out int hresult) {
      IntPtr sid;
      hresult = CreateAppContainerProfile(name, name, "OpenScience sandbox probe", IntPtr.Zero, 0, out sid);
      created = (hresult == 0);
      if (hresult == 0) { try { return SidToString(sid); } finally { FreeSid(sid); } }
      // 0x800700B7 == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
      if ((uint)hresult == 0x800700B7) {
        int derived = DeriveAppContainerSidFromAppContainerName(name, out sid);
        if (derived != 0) throw new Win32Exception(derived, "DeriveAppContainerSidFromAppContainerName failed");
        try { return SidToString(sid); } finally { FreeSid(sid); }
      }
      throw new Win32Exception(hresult, "CreateAppContainerProfile failed (HRESULT 0x" + hresult.ToString("X8") + ")");
    }

    public static void Delete(string name) { DeleteAppContainerProfile(name); }

    /// Launches commandLine inside the AppContainer identified by sidString,
    /// with NO capabilities granted, and returns its exit code.
    public static int Launch(string sidString, string commandLine, int timeoutMs) {
      IntPtr sid;
      if (!ConvertStringSidToSid(sidString, out sid)) throw new Win32Exception(Marshal.GetLastWin32Error());

      IntPtr attributes = IntPtr.Zero;
      IntPtr capabilitiesBlob = IntPtr.Zero;
      try {
        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        attributes = Marshal.AllocHGlobal(size);
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
          throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");

        // CapabilityCount 0 is the whole point: no internetClient, no
        // privateNetworkClientServer, nothing.
        SecurityCapabilities caps = new SecurityCapabilities();
        caps.AppContainerSid = sid;
        caps.Capabilities = IntPtr.Zero;
        caps.CapabilityCount = 0;
        caps.Reserved = 0;

        capabilitiesBlob = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityCapabilities)));
        Marshal.StructureToPtr(caps, capabilitiesBlob, false);

        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
              capabilitiesBlob, (IntPtr)Marshal.SizeOf(typeof(SecurityCapabilities)), IntPtr.Zero, IntPtr.Zero))
          throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute failed");

        StartupInfoEx si = new StartupInfoEx();
        si.cb = Marshal.SizeOf(typeof(StartupInfoEx));
        si.lpAttributeList = attributes;

        ProcessInformation pi;
        StringBuilder cmd = new StringBuilder(commandLine);
        if (!CreateProcess(null, cmd, IntPtr.Zero, IntPtr.Zero, false,
              EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
          throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess into AppContainer failed");

        try {
          if (WaitForSingleObject(pi.hProcess, (uint)timeoutMs) != 0) {
            TerminateProcess(pi.hProcess, 9999);
            return -1; // timed out
          }
          uint code;
          if (!GetExitCodeProcess(pi.hProcess, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
          return unchecked((int)code);
        } finally { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
      } finally {
        if (attributes != IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
        if (capabilitiesBlob != IntPtr.Zero) Marshal.FreeHGlobal(capabilitiesBlob);
        if (sid != IntPtr.Zero) LocalFree(sid);
      }
    }
  }
}
"@
}

# ── 1. Create the profile, unelevated ────────────────────────────────────────
Say "1. CreateAppContainerProfile as a standard user" "White"
$created = $false
$hr = 0
try {
  $sid = [OpenScience.AppContainer]::EnsureProfile($Name, [ref]$created, [ref]$hr)
} catch {
  Say ("  FAILED: {0}" -f $_.Exception.Message) "Red"
  Say ""
  Say "  Question 1 answered: NO — the design's foundation does not hold." "Red"
  Say "  Everything downstream of it is moot; send this output back." "Red"
  exit 1
}
Result "profile created or already present" $true "yes"
Say ("  SID             : {0}" -f $sid) "Gray"
Say ("  newly created   : {0}" -f $created) "Gray"
Say ""

# ── Scratch dir the container can write, and the child script ────────────────
# An AppContainer gets no access to the user profile by default, so the child
# needs somewhere to write. Granting one temp directory to the package SID is
# an ordinary user-mode ACL edit — itself part of what the design assumes.
$work = Join-Path ([IO.Path]::GetTempPath()) ("openscience-probe-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
& icacls.exe $work /grant ("*" + $sid + ":(OI)(CI)(F)") /Q | Out-Null
$aclOk = ($LASTEXITCODE -eq 0)
Result "temp dir ACL'd to the package SID (icacls)" $aclOk "yes"

$marker = Join-Path $work "started.txt"
$report = Join-Path $work "report.json"

# A host-side loopback listener the child will try to reach. This is the
# question that decides whether a host proxy is reachable from inside at all.
$hostListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$hostListener.Start()
$hostPort = ([Net.IPEndPoint]$hostListener.Server.LocalEndPoint).Port
Say ("  host loopback listener on 127.0.0.1:{0}" -f $hostPort) "Gray"
Say ""

# Written as a file rather than -Command: quoting an inline script through
# CreateProcess into an AppContainer is a needless way to lose an afternoon.
$childPath = Join-Path $work "child.ps1"
@"
`$ErrorActionPreference = 'SilentlyContinue'
`$work = '$work'
`$hostPort = $hostPort
Set-Content -LiteralPath (Join-Path `$work 'started.txt') -Value 'started'

`$bits = 1   # 1 = the child ran at all
`$detail = @{}

# 2 = can BIND and LISTEN on loopback inside the container.
`$listener = `$null
try {
  `$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
  `$listener.Start()
  `$port = ([Net.IPEndPoint]`$listener.Server.LocalEndPoint).Port
  `$bits = `$bits -bor 2
  `$detail.listenPort = `$port
} catch { `$detail.listenError = `$_.Exception.Message }

# 4 = can CONNECT to its own listener (a loopback round trip inside one container).
if (`$listener) {
  try {
    `$c = [Net.Sockets.TcpClient]::new()
    `$iar = `$c.BeginConnect([Net.IPAddress]::Loopback, `$detail.listenPort, `$null, `$null)
    if (`$iar.AsyncWaitHandle.WaitOne(3000) -and `$c.Connected) { `$bits = `$bits -bor 4 }
    `$c.Close()
  } catch { `$detail.selfConnectError = `$_.Exception.Message }
}

# 8 = can reach the OUTSIDE world. Expected NO: no capabilities were granted.
try {
  `$c = [Net.Sockets.TcpClient]::new()
  `$iar = `$c.BeginConnect('1.1.1.1', 443, `$null, `$null)
  if (`$iar.AsyncWaitHandle.WaitOne(4000) -and `$c.Connected) { `$bits = `$bits -bor 8 }
  `$c.Close()
} catch { `$detail.outboundError = `$_.Exception.Message }

# 16 = can reach a listener on the HOST's loopback. This decides whether a
# host-side proxy is reachable without a loopback exemption.
try {
  `$c = [Net.Sockets.TcpClient]::new()
  `$iar = `$c.BeginConnect([Net.IPAddress]::Loopback, `$hostPort, `$null, `$null)
  if (`$iar.AsyncWaitHandle.WaitOne(3000) -and `$c.Connected) { `$bits = `$bits -bor 16 }
  `$c.Close()
} catch { `$detail.hostLoopbackError = `$_.Exception.Message }

# 32 = DNS resolves inside the container.
try {
  [Net.Dns]::GetHostAddresses('pypi.org') | Out-Null
  `$bits = `$bits -bor 32
} catch { `$detail.dnsError = `$_.Exception.Message }

if (`$listener) { `$listener.Stop() }
`$detail.bits = `$bits
`$detail | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path `$work 'report.json')
exit `$bits
"@ | Set-Content -LiteralPath $childPath -Encoding UTF8

# ── 2. Launch into the container with zero capabilities ──────────────────────
Say "2. Launch a child into the AppContainer with NO capabilities" "White"
$ps = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$cmdline = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}"' -f $ps, $childPath

$code = $null
try {
  $code = [OpenScience.AppContainer]::Launch($sid, $cmdline, 45000)
} catch {
  Say ("  FAILED to launch: {0}" -f $_.Exception.Message) "Red"
  Say ""
  Say "  This alone is a finding: if a stock powershell.exe cannot start in an" "Yellow"
  Say "  empty AppContainer, the design needs a purpose-built child binary." "Yellow"
}

$ran = Test-Path -LiteralPath $marker
Result "child process actually started" $ran "yes"
if ($code -eq -1) { Say "  (child timed out after 45s)" "Yellow" }
Say ""

$hostListener.Stop()

# ── 3. Results ───────────────────────────────────────────────────────────────
if ($ran -and $code -ne $null -and $code -ge 0) {
  Say "3. What the container could do" "White"
  Result "bind + listen on loopback INSIDE the container" (($code -band 2) -ne 0) "either"
  Result "connect to its own loopback listener"           (($code -band 4) -ne 0) "either"
  Result "connect outbound to 1.1.1.1:443"                (($code -band 8) -ne 0) "no"
  Result "connect to a listener on the HOST loopback"     (($code -band 16) -ne 0) "no"
  Result "resolve DNS (pypi.org)"                         (($code -band 32) -ne 0) "no"
  Say ""

  $canListen = (($code -band 2) -ne 0) -and (($code -band 4) -ne 0)
  Say "VERDICT" "White"
  if ($canListen) {
    Say "  An AppContainer CAN host a loopback listener." "Green"
    Say "  The Linux/macOS shim model transfers: a shim inside the sandbox can" "Green"
    Say "  speak HTTP-proxy protocol and unmodified pip works. Windows can be" "Green"
    Say "  socket-transparent like the other two platforms." "Green"
  } else {
    Say "  An AppContainer CANNOT host a loopback listener." "Yellow"
    Say "  Windows must be capability-mediated: code has to ASK a broker rather" "Yellow"
    Say "  than connect. Package installation moves into the broker's trust" "Yellow"
    Say "  domain, and a notebook cell cannot fetch a URL directly." "Yellow"
  }
  if ((($code -band 8) -ne 0) -or (($code -band 16) -ne 0)) {
    Say ""
    Say "  UNEXPECTED: the container reached the network with no capabilities" "Red"
    Say "  granted. That undermines the isolation the whole design rests on —" "Red"
    Say "  this is the most important line in the output." "Red"
  }
  Say ""
  if (Test-Path -LiteralPath $report) {
    Say "Raw detail (paste this back):" "White"
    Get-Content -LiteralPath $report -Raw | Write-Host
  }
} else {
  Say "3. No usable result — the child did not report." "Red"
  Say ("  exit code: {0}" -f $code) "Red"
}

# ── Cleanup ──────────────────────────────────────────────────────────────────
Say ""
if (-not $Keep) {
  [OpenScience.AppContainer]::Delete($Name)
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  Say "Cleaned up the profile and temp directory." "Gray"
} else {
  Say ("Kept profile '{0}' and {1}" -f $Name, $work) "Gray"
}
Say ""
