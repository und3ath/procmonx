# hunt.ps1 - sweep a capture through every lens in conf\hunt, then verify each
# hit's *exploitability* from a low-privilege attacker's point of view: does the
# missing/target object sit in a directory (or registry key) a non-admin can
# write? Emits a per-technique summary + FINDINGS.md.
#
#   1) capture (auto-elevates):  .\build\src\cli\pmx.exe live --count 20000 --save cap.pmxlog
#   2) analyze:                  .\hunt.ps1 cap.pmxlog
#
# The attacker view does NOT depend on who runs the analysis: write access is
# evaluated for a synthetic generic standard user (AuthzAccessCheck), not your
# token. Run it ELEVATED so Get-Acl can read every object's security descriptor
# (unreadable descriptors are reported as "not writable").
[CmdletBinding()]
param(
  [Parameter(Mandatory, Position=0)] [string] $Log,
  [string] $OutDir = "hunt-out",
  # Whose write access defines "exploitable". 'standard' = a generic low-priv
  # user (Everyone / Authenticated Users / Users / Interactive) - the true
  # attacker view, independent of who runs this. 'self' also counts your own
  # SID (surfaces self-access; noisier). Run the analysis ELEVATED regardless,
  # so Get-Acl can read every object's security descriptor.
  [ValidateSet('standard','self')] [string] $Principal = 'standard',
  [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'
$pmx = Join-Path $PSScriptRoot 'build\src\cli\pmx.exe'

# --- \Device\HarddiskVolumeN -> drive-letter map (QueryDosDevice) -------------
Add-Type -Namespace Native -Name Dos -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern uint QueryDosDevice(string dev, System.Text.StringBuilder buf, uint n);
'@ -ErrorAction SilentlyContinue

function Get-DeviceMap {
  $map = @{}
  foreach ($d in [char[]](65..90)) {
    $dos = "$d`:"
    $sb  = New-Object System.Text.StringBuilder 1024
    if ([Native.Dos]::QueryDosDevice($dos, $sb, 1024) -ne 0) {
      $map[$sb.ToString()] = $dos    # "\Device\HarddiskVolume5" -> "C:"
    }
  }
  $map
}
$DeviceMap = Get-DeviceMap

# Translate a captured NT path to a Win32 path, or $null if not a disk path.
function ConvertTo-Win32Path([string] $p) {
  if (-not $p) { return $null }
  if ($p -like 'HK*' -or $p -like '\REGISTRY\*') { return $p }          # registry, handled elsewhere
  if ($p -like '\Device\NamedPipe*') { return $null }                    # not a filesystem object
  if ($p -match '^(\\Device\\HarddiskVolume\d+)(\\.*)?$') {
    $dev = $Matches[1]; $rest = $Matches[2]
    if ($DeviceMap.ContainsKey($dev)) { return ($DeviceMap[$dev] + $rest) }
    return $null
  }
  if ($p -match '^[A-Za-z]:\\') { return $p }                            # already a drive path
  return $null
}

# --- low-privilege principals we care about -----------------------------------
# Generic standard-user principals: Everyone, Authenticated Users, Users,
# Interactive, Guests. A write grant to any of these = a real low-priv attacker
# can write, no matter whose token runs this analysis.
$LowPrivSids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($s in 'S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4','S-1-5-32-546') { [void]$LowPrivSids.Add($s) }
if ($Principal -eq 'self') {
  try { [void]$LowPrivSids.Add([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } catch {}
}

# Action bits ONLY - deliberately excludes READ_CONTROL(0x20000) and
# SYNCHRONIZE(0x100000), which FullControl/Modify/ReadAndExecute all share and
# which would otherwise make every read-grant look writable.
#   file: WriteData/CreateFiles 0x2, AppendData/CreateDirs 0x4, WriteEA 0x10,
#         DeleteChild 0x40, WriteAttrs 0x100, Delete 0x10000, WriteDAC 0x40000,
#         WriteOwner 0x80000
$FileWriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000
#   reg: SetValue 0x2, CreateSubKey 0x4, CreateLink 0x20, Delete 0x10000,
#        WriteDAC 0x40000, WriteOwner 0x80000
$RegWriteMask  = 0x2 -bor 0x4 -bor 0x20 -bor 0x10000 -bor 0x40000 -bor 0x80000

# Pull "_desc" from a lens file without a strict JSON parse (the confs use
# Windows paths with single backslashes, which ConvertFrom-Json rejects but our
# C++ filter parser accepts).
function Get-LensDesc([string] $file) {
  $raw = Get-Content -Raw -LiteralPath $file
  $m = [regex]::Match($raw, '"_desc"\s*:\s*"((?:\\.|[^"\\])*)"')
  if ($m.Success) { return $m.Groups[1].Value }
  return ''
}

function Resolve-Sid($idRef) {
  try { return $idRef.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}

# Existence probe that never throws (some protected objects deny even Test-Path).
function TP([string] $p) {
  try { return [bool](Test-Path -LiteralPath $p -ErrorAction Stop) } catch { return $false }
}

# --- effective-access backend: AuthzAccessCheck against a synthetic token ------
# Builds a client context holding a generic standard user's SIDs (Everyone,
# Authenticated Users, Users, Interactive; +your SID under -Principal self) with
# NO admin membership, then access-checks each object's real security descriptor
# with MAXIMUM_ALLOWED. Unlike an ACE scan this honours Deny ACEs, inheritance
# and ACE order exactly - the true "could a low-priv user write this" answer.
Add-Type -ErrorAction SilentlyContinue -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class EffAccess {
  const int AUTHZ_RM_FLAG_NO_AUDIT = 0x1;
  const int AUTHZ_SKIP_TOKEN_GROUPS = 0x2;
  const uint MAXIMUM_ALLOWED = 0x02000000;
  const uint SE_GROUP_ENABLED = 0x4;
  [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Lo; public int Hi; }
  [StructLayout(LayoutKind.Sequential)] struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct AUTHZ_ACCESS_REQUEST {
    public uint DesiredAccess; public IntPtr PrincipalSelfSid;
    public IntPtr ObjectTypeList; public uint ObjectTypeListLength; public IntPtr OptionalArguments; }
  [StructLayout(LayoutKind.Sequential)] struct AUTHZ_ACCESS_REPLY {
    public uint ResultListLength; public IntPtr GrantedAccessMask; public IntPtr SaclEvaluationResults; public IntPtr Error; }
  [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzInitializeResourceManager(int f, IntPtr a, IntPtr b, IntPtr c, string n, out IntPtr rm);
  [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzInitializeContextFromSid(int f, byte[] sid, IntPtr rm, IntPtr exp, LUID id, IntPtr dyn, out IntPtr ctx);
  [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzAddSidsToContext(IntPtr ctx, SID_AND_ATTRIBUTES[] sids, uint n, IntPtr rsid, uint rn, out IntPtr nctx);
  [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzAccessCheck(int f, IntPtr ctx, ref AUTHZ_ACCESS_REQUEST req, IntPtr ae, byte[] sd, IntPtr[] osd, uint on, ref AUTHZ_ACCESS_REPLY rep, out IntPtr res);
  [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr ctx);
  [DllImport("authz.dll")] static extern bool AuthzFreeHandle(IntPtr h);
  static IntPtr _rm = IntPtr.Zero, _ctx = IntPtr.Zero;
  static byte[] Sid(WellKnownSidType t){ var s=new SecurityIdentifier(t,null); var b=new byte[s.BinaryLength]; s.GetBinaryForm(b,0); return b; }
  static byte[] Sid(string v){ var s=new SecurityIdentifier(v); var b=new byte[s.BinaryLength]; s.GetBinaryForm(b,0); return b; }
  public static string Init(string[] extra){
    try {
      if(!AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "pmxhunt", out _rm)) return "rm:"+Marshal.GetLastWin32Error();
      IntPtr baseCtx; LUID luid=new LUID();
      if(!AuthzInitializeContextFromSid(AUTHZ_SKIP_TOKEN_GROUPS, Sid(WellKnownSidType.BuiltinUsersSid), _rm, IntPtr.Zero, luid, IntPtr.Zero, out baseCtx)) return "ctx:"+Marshal.GetLastWin32Error();
      var groups = new System.Collections.Generic.List<byte[]>();
      foreach(var t in new[]{ WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid, WellKnownSidType.InteractiveSid }) groups.Add(Sid(t));
      if(extra!=null) foreach(var e in extra){ try { groups.Add(Sid(e)); } catch {} }
      var saa = new SID_AND_ATTRIBUTES[groups.Count];
      for(int i=0;i<groups.Count;i++){ IntPtr p=Marshal.AllocHGlobal(groups[i].Length); Marshal.Copy(groups[i],0,p,groups[i].Length); saa[i].Sid=p; saa[i].Attributes=SE_GROUP_ENABLED; }
      if(!AuthzAddSidsToContext(baseCtx, saa, (uint)saa.Length, IntPtr.Zero, 0, out _ctx)) return "add:"+Marshal.GetLastWin32Error();
      AuthzFreeContext(baseCtx);
      return "ok";
    } catch(Exception ex){ return "ex:"+ex.Message; }
  }
  // Maximum access a standard user is granted on this self-relative SD (0 on failure).
  public static uint GrantedMask(byte[] sd){
    if(_ctx==IntPtr.Zero || sd==null || sd.Length==0) return 0;
    var req=new AUTHZ_ACCESS_REQUEST(); req.DesiredAccess=MAXIMUM_ALLOWED;
    var rep=new AUTHZ_ACCESS_REPLY(); rep.ResultListLength=1;
    IntPtr g=Marshal.AllocHGlobal(4), e=Marshal.AllocHGlobal(4), s=Marshal.AllocHGlobal(4), res=IntPtr.Zero;
    Marshal.WriteInt32(g,0); Marshal.WriteInt32(e,0); Marshal.WriteInt32(s,0);
    rep.GrantedAccessMask=g; rep.Error=e; rep.SaclEvaluationResults=s;
    uint mask=0;
    if(AuthzAccessCheck(0, _ctx, ref req, IntPtr.Zero, sd, null, 0, ref rep, out res)){ mask=(uint)Marshal.ReadInt32(g); if(res!=IntPtr.Zero) AuthzFreeHandle(res); }
    Marshal.FreeHGlobal(g); Marshal.FreeHGlobal(e); Marshal.FreeHGlobal(s);
    return mask;
  }
}
'@
$AuthzExtra = if ($Principal -eq 'self') { @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) } else { @() }
$UseAuthz = $false
try { if (('EffAccess' -as [type]) -and ([EffAccess]::Init($AuthzExtra) -eq 'ok')) { $UseAuthz = $true } } catch {}

function Format-Rights([int] $mask, [bool] $isRegistry) {
  try { if ($isRegistry) { return ([Security.AccessControl.RegistryRights]$mask -replace ' ', '') }
        else { return ([Security.AccessControl.FileSystemRights]$mask -replace ' ', '') } }
  catch { return ('0x{0:X}' -f $mask) }
}

# Can a generic standard user write this existing object? Prefers a real
# effective-access check (AuthZ); falls back to an Allow-ACE scan if AuthZ is
# unavailable.
function Test-AclWritable($aclPath, $isRegistry) {
  $mask = if ($isRegistry) { $RegWriteMask } else { $FileWriteMask }
  if ($UseAuthz) {
    try { $sd = (Get-Acl -LiteralPath $aclPath -ErrorAction Stop).GetSecurityDescriptorBinaryForm() }
    catch { return @{ ok=$false; who=@(); err=$_.Exception.Message } }
    $granted = [int][EffAccess]::GrantedMask($sd)
    $eff = $granted -band $mask
    if ($eff -ne 0) { return @{ ok=$true; who=@("standard user -> $(Format-Rights $eff $isRegistry)") } }
    return @{ ok=$false; who=@() }
  }
  # fallback: scan Allow ACEs for the generic low-priv SID set (ignores Deny)
  try { $acl = Get-Acl -LiteralPath $aclPath -ErrorAction Stop } catch { return @{ ok=$false; who=@(); err=$_.Exception.Message } }
  $who = @()
  foreach ($r in $acl.Access) {
    if ($r.AccessControlType -ne 'Allow') { continue }
    $sid = Resolve-Sid $r.IdentityReference
    if (-not $sid -or -not $LowPrivSids.Contains($sid)) { continue }
    $rights = if ($isRegistry) { $r.RegistryRights } else { $r.FileSystemRights }
    if (([int]$rights -band [int]$mask) -ne 0) {
      $who += ('{0} [{1}]' -f $r.IdentityReference, ($rights -replace ' ', ''))
    }
  }
  @{ ok = ($who.Count -gt 0); who = ($who | Select-Object -Unique) }
}

# Parent dir of a filesystem path (no wildcard/param-set pitfalls).
function Get-ParentPath([string] $p) { return [System.IO.Path]::GetDirectoryName($p) }

# Nearest existing filesystem ancestor of a (possibly missing) path.
function Get-NearestExisting([string] $p) {
  while ($p -and -not (TP $p)) {
    $parent = Get-ParentPath $p
    if (-not $parent -or $parent -eq $p) { return $null }
    $p = $parent
  }
  if ($p -and (TP $p)) { return $p }
  return $null
}

# Verdict for a file object under a given technique category.
function Test-FileExploitable([string] $win32, [string] $category) {
  $r = [ordered]@{ verdict='NO'; detail=''; who=@() }
  if (-not $win32) { $r.verdict='SKIP'; $r.detail='non-disk path'; return $r }

  switch ($category) {
    'plant' {   # dll-hijack / missing-file: can we create the missing leaf?
      $parent = Get-ParentPath $win32
      if ($parent -and (TP $parent)) {
        $t = Test-AclWritable $parent $false
        if ($t.ok) {
          $empty = -not (Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
          $r.verdict='EXPLOITABLE'; $r.who=$t.who
          $r.detail=("parent writable{0}: {1}" -f ($(if($empty){' (empty dir)'}else{''}), $parent)
          )
        } else { $r.detail="parent not writable: $parent" }
      } else {
        $anc = Get-NearestExisting $win32
        if ($anc) { $t = Test-AclWritable $anc $false
          if ($t.ok) { $r.verdict='MAYBE'; $r.who=$t.who; $r.detail="ancestor writable, missing dirs createable: $anc" }
          else { $r.detail="ancestor not writable: $anc" }
        } else { $r.detail='no existing ancestor' }
      }
    }
    'write' {   # writable-write: mutate the target (or create it in its dir)
      if (TP $win32) {
        $t = Test-AclWritable $win32 $false
        if ($t.ok) { $r.verdict='EXPLOITABLE'; $r.who=$t.who; $r.detail="target writable: $win32" }
        else { $r.detail="target not writable: $win32" }
      } else {
        $parent = Get-ParentPath $win32
        $anc = Get-NearestExisting $parent
        if ($anc) { $t = Test-AclWritable $anc $false
          if ($t.ok) { $r.verdict=$(if($anc -eq $parent){'EXPLOITABLE'}else{'MAYBE'}); $r.who=$t.who; $r.detail="dir writable: $anc" }
          else { $r.detail="dir not writable: $anc" }
        } else { $r.detail='no existing ancestor' }
      }
    }
    'remove' {  # delete/rename: control of parent lets you swap/remove the child
      $parent = Get-ParentPath $win32
      $anc = Get-NearestExisting $parent
      if ($anc) { $t = Test-AclWritable $anc $false
        if ($t.ok) { $r.verdict='EXPLOITABLE'; $r.who=$t.who; $r.detail="parent writable (rename/delete child): $anc" }
        else { $r.detail="parent not writable: $anc" }
      } else { $r.detail='no existing ancestor' }
    }
    'toctou' {  # temp create: symlink/junction + oplock redirection surface
      $parent = Get-ParentPath $win32
      $anc = Get-NearestExisting $parent
      if ($anc) { $t = Test-AclWritable $anc $false
        if ($t.ok) { $r.verdict='EXPLOITABLE'; $r.who=$t.who; $r.detail="temp dir writable -> symlink/oplock TOCTOU: $anc" }
        else { $r.detail="dir not writable: $anc" }
      } else { $r.detail='no existing ancestor' }
    }
    default { $r.verdict='MANUAL'; $r.detail='no automated check' }
  }
  return $r
}

# Registry: normalize NT/HK path -> provider path, then ACL-check the key.
function ConvertTo-RegProviderPath([string] $p) {
  if (-not $p) { return $null }
  $p = $p -replace '^\\REGISTRY\\MACHINE', 'HKEY_LOCAL_MACHINE' `
          -replace '^\\REGISTRY\\USER',    'HKEY_USERS' `
          -replace '^HKLM',  'HKEY_LOCAL_MACHINE' `
          -replace '^HKCU',  'HKEY_CURRENT_USER' `
          -replace '^HKCR',  'HKEY_CLASSES_ROOT' `
          -replace '^HKU',   'HKEY_USERS'
  if ($p -notmatch '^HKEY_') { return $null }
  return "Registry::$p"
}
# $isValueOp: the captured path ends in a VALUE name (RegSetValue/RegDeleteValue/
# RegQueryValue), so the key to check is its parent - a writable parent key is a
# direct hit, not a "missing key" MAYBE.
function Test-RegExploitable([string] $regPath, [bool] $isValueOp = $false) {
  $r = [ordered]@{ verdict='NO'; detail=''; who=@() }
  $prov = ConvertTo-RegProviderPath $regPath
  if (-not $prov) { $r.verdict='SKIP'; $r.detail='unmappable key'; return $r }
  if ($isValueOp) {
    $i = $prov.LastIndexOf('\')
    if ($i -gt 0) { $prov = $prov.Substring(0, $i) }
  }
  $key = $prov
  while ($key -and -not (TP $key)) {
    $parent = Split-Path $key -Parent
    if (-not $parent -or $parent -eq $key) { break }
    $key = $parent
  }
  if (-not (TP $key)) { $r.detail='key not present'; return $r }
  $t = Test-AclWritable $key $true
  if ($t.ok) { $r.verdict=$(if($key -eq $prov){'EXPLOITABLE'}else{'MAYBE'}); $r.who=$t.who; $r.detail="key writable: $($key -replace '^Registry::','')" }
  else { $r.detail="key not writable: $($key -replace '^Registry::','')" }
  return $r
}

# Map lens basename -> (kind, category)
function Get-LensClass([string] $name) {
  switch -Regex ($name) {
    'dll-hijack|missing-file' { return @{ kind='file'; cat='plant'  } }
    'writable-write'          { return @{ kind='file'; cat='write'  } }
    'arbitrary-delete|arbitrary-rename' { return @{ kind='file'; cat='remove' } }
    'toctou'                  { return @{ kind='file'; cat='toctou' } }
    'named-pipe'              { return @{ kind='pipe'; cat='manual' } }
    'reg-'                    { return @{ kind='reg';  cat='reg'    } }
    default                   { return @{ kind='file'; cat='write'  } }
  }
}

if ($SelfTest) {
  Write-Host ("SelfTest: backend={0}  principal={1}" -f $(if($UseAuthz){'AuthzAccessCheck'}else{'ACE-scan fallback'}), $Principal) -ForegroundColor Cyan
  $DeviceMap.GetEnumerator() | Sort-Object Value | ForEach-Object { "  {0} -> {1}" -f $_.Value, $_.Key }
  foreach ($p in "$env:SystemRoot\System32\doesnotexist.dll", "$env:PUBLIC\test.dll", "$env:TEMP\x.tmp", "$env:ProgramData\test.dll") {
    $v = Test-FileExploitable $p 'plant'
    "  plant {0,-45} => {1} {2}" -f $p, $v.verdict, $v.detail
  }
  ('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_CURRENT_USER\SOFTWARE') | ForEach-Object {
    $t = Test-AclWritable $_ $true; "  reg {0,-40} writable={1} {2}" -f $_, $t.ok, ($t.who -join ';')
  }
  return
}

if (-not (Test-Path $pmx)) { throw "build first (cmake --build build): $pmx" }
if (-not (Test-Path $Log)) { throw "no capture: $Log" }
New-Item -ItemType Directory -Force $OutDir | Out-Null

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Hunt findings - $(Get-Date -Format s)")
$md.Add("")
$md.Add("Capture: ``$Log``  |  principal: ``$Principal``  |  backend: ``$(if($UseAuthz){'AuthzAccessCheck'}else{'ACE-scan'})``  |  analysis token: ``$([Security.Principal.WindowsIdentity]::GetCurrent().Name)``")
$md.Add("")

Write-Host ("{0,-22} {1,6} {2,6} {3,7} {4,6}" -f 'technique','hits','uniq','exploit','maybe')
Write-Host ('-' * 55)

$grand = 0
foreach ($conf in (Get-ChildItem (Join-Path $PSScriptRoot 'conf\hunt\*.json') | Sort-Object Name)) {
  $name = $conf.BaseName
  $csv  = Join-Path $OutDir "$name.csv"
  # Remove any CSV from a previous run first: if pmx fails (bad lens, unreadable
  # log) we must not silently re-analyse stale rows.
  Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
  & $pmx open $Log --filter-file $conf.FullName --csv $csv --quiet | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning ("{0}: pmx open failed (exit {1}) - lens skipped" -f $name, $LASTEXITCODE)
    $md.Add("## $name  -  ERROR: pmx open exited $LASTEXITCODE (lens skipped)")
    $md.Add("")
    continue
  }
  $rows = @(if (Test-Path $csv) { Import-Csv $csv })
  $cls  = Get-LensClass $name

  # dedup by path; keep a sample operation/process
  $uniq = $rows | Group-Object Path | ForEach-Object {
    $s = $_.Group[0]
    [pscustomobject]@{ Path=$_.Name; Op=$s.Operation; Proc=$s.'Process Name'; User=$s.User; Integrity=$s.Integrity; Count=$_.Count }
  }

  $findings = foreach ($u in $uniq) {
    if ($cls.kind -eq 'reg') { $v = Test-RegExploitable $u.Path ($u.Op -match 'Value$') }
    elseif ($cls.kind -eq 'pipe') { $v = [ordered]@{ verdict='MANUAL'; detail='named pipe - check pipe ACL at runtime'; who=@() } }
    else { $w = ConvertTo-Win32Path $u.Path; $v = Test-FileExploitable $w $cls.cat }
    [pscustomobject]@{ Path=$u.Path; Op=$u.Op; Proc=$u.Proc; Integrity=$u.Integrity; Count=$u.Count; Verdict=$v.verdict; Detail=$v.detail; Who=($v.who -join '; ') }
  }

  $exp = @($findings | Where-Object Verdict -eq 'EXPLOITABLE')
  $may = @($findings | Where-Object Verdict -eq 'MAYBE')
  $grand += $exp.Count
  $color = if ($exp.Count) { 'Red' } elseif ($may.Count) { 'Yellow' } else { 'DarkGray' }
  Write-Host ("{0,-22} {1,6} {2,6} {3,7} {4,6}" -f $name, $rows.Count, $uniq.Count, $exp.Count, $may.Count) -ForegroundColor $color

  $md.Add("## $name  -  $(Get-LensDesc $conf.FullName)")
  $md.Add("")
  $md.Add("hits=$($rows.Count) unique=$($uniq.Count) **exploitable=$($exp.Count)** maybe=$($may.Count)")
  $md.Add("")
  $show = @($findings | Sort-Object @{e={@{EXPLOITABLE=0;MAYBE=1;MANUAL=2;NO=3;SKIP=4}[$_.Verdict]}}, Path | Select-Object -First 40)
  if ($show) {
    $md.Add('| Verdict | Proc | Integrity | Op | Path | Why |')
    $md.Add('|---|---|---|---|---|---|')
    foreach ($f in $show) {
      $md.Add(('| {0} | {1} | {2} | {3} | `{4}` | {5} |' -f $f.Verdict, $f.Proc, $f.Integrity, $f.Op, $f.Path, ($f.Detail + $(if($f.Who){" &lt;- $($f.Who)"}))))
    }
  } else { $md.Add('_no hits_') }
  $md.Add("")
}

$mdPath = Join-Path $OutDir 'FINDINGS.md'
$md -join "`n" | Set-Content -Encoding UTF8 $mdPath
Write-Host ''
Write-Host ("{0} exploitable finding(s). Full report: {1}" -f $grand, $mdPath) -ForegroundColor $(if($grand){'Red'}else{'Green'})
Write-Host ("backend={0}  principal={1}  ({2}). Run elevated so every security descriptor is readable." -f `
  $(if($UseAuthz){'AuthzAccessCheck (effective access; honours Deny + inheritance)'}else{'ACE-scan fallback (Allow ACEs only)'}), `
  $Principal, $(if($Principal -eq 'self'){'generic low-priv groups + your SID'}else{'generic standard user: Everyone/AuthUsers/Users/Interactive'}))
