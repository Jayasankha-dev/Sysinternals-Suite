## 🛠️ Tool Categorization

| Category | Purpose | Tools Used |
| :--- | :--- | :--- |
| **🔍 File Authenticity** | Check if Windows files are original (Microsoft signed). | `sigcheck.exe` |
| **🔄 Persistence & Startup** | Detect malware that runs on boot. | `autorunsc.exe` |
| **⚙️ Running Processes** | Monitor active processes, memory usage, and kill threats. | `procexp.exe`, `pslist.exe`, `pskill.exe` |
| **🌐 Network Connections** | Identify suspicious outgoing/incoming connections. | `tcpvcon.exe`, `psping.exe` |
| **👤 User Sessions** | Find hidden or logged-on users. | `logonsessions.exe`, `psloggedon.exe` |
| **💾 Disk & File Analysis** | Check for alternate data streams (hiding spots). | `streams.exe`, `junction.exe` |

---

## 🤖 The Automated Master Script

Save this script as **`Invoke-SysinternalsAudit.ps1`**.

It runs the tools, saves structured logs to a new folder (e.g., `C:\Audit_2026-08-31`), and provides a color-coded summary.

```powershell
<#
.SYNOPSIS
    Sysinternals Auto-Scanner: Audits Windows security using Microsoft Sysinternals tools.
.DESCRIPTION
    This script automates digital forensics checks on a local system.
    It detects unsigned files, hidden autoruns, suspicious network connections,
    and active processes.
.NOTES
    Version: 1.0
    Author: Security Analyst
    Requires: Sysinternals Suite installed via Microsoft Store (or added to PATH).
#>

# ------------------ CONFIGURATION ------------------
$Env:Path += ";C:\Program Files\WindowsApps\Microsoft.SysinternalsSuite_8wekyb3d8bbwe\"
$AuditDate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$ReportRoot = "C:\Audit_$AuditDate"
$LogFile = "$ReportRoot\Master_Summary.txt"

# Create Report Directory
if (!(Test-Path $ReportRoot)) { New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null }

# Function to Log and Print
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $FormattedMessage = "[$TimeStamp] $Message"
    Write-Host $FormattedMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $FormattedMessage
}

Write-Log "=============================================" "Cyan"
Write-Log " STARTING SYSTEM SECURITY AUDIT" "Cyan"
Write-Log "=============================================" "Cyan"

# ------------------ 1. PROCESS ANALYSIS (pslist) ------------------
Write-Log "1. Running Process Audit (pslist)..." "Yellow"
Start-Process -Wait -FilePath "pslist.exe" -ArgumentList "/accepteula /t" -RedirectStandardOutput "$ReportRoot\Processes.txt"
Write-Log "   [+] Process list saved to Processes.txt" "Green"

# ------------------ 2. NETWORK CONNECTIONS (tcpvcon) ------------------
Write-Log "2. Checking Network Connections (tcpvcon)..." "Yellow"
Start-Process -Wait -FilePath "tcpvcon.exe" -ArgumentList "/accepteula -a -n" -RedirectStandardOutput "$ReportRoot\Network_Connections.txt"
Write-Log "   [+] Network connections saved to Network_Connections.txt" "Green"

# ------------------ 3. USER SESSIONS (logonsessions) ------------------
Write-Log "3. Checking Active Logon Sessions..." "Yellow"
Start-Process -Wait -FilePath "logonsessions.exe" -ArgumentList "/accepteula /p" -RedirectStandardOutput "$ReportRoot\Logon_Sessions.txt"
Write-Log "   [+] Active sessions saved to Logon_Sessions.txt" "Green"

# ------------------ 4. STARTUP PERSISTENCE (autorunsc) ------------------
Write-Log "4. Scanning Startup Entries (Autoruns)..." "Yellow"
Start-Process -Wait -FilePath "autorunsc.exe" -ArgumentList "/accepteula -a -c -m" -RedirectStandardOutput "$ReportRoot\Autoruns.csv"
Write-Log "   [+] Autoruns saved to Autoruns.csv (Open in Excel)" "Green"

# ------------------ 5. FILE INTEGRITY (sigcheck - FULL SCAN) ------------------
Write-Log "5. File Integrity Scan (sigcheck - This will take time)..." "Yellow"
Write-Log "   Scanning entire C: drive for unsigned files. Please wait..." "Yellow"

# We scan C:\Windows\System32 mainly to check OS files, but we'll target the whole C:
$UnsignedOutput = "$ReportRoot\Unsigned_Files.txt"
Start-Process -Wait -FilePath "sigcheck.exe" -ArgumentList "/accepteula -s -i C:\" -RedirectStandardOutput $UnsignedOutput

# Filter out Microsoft signatures and count malicious/unsigned
$UnsignedCount = (Select-String -Path $UnsignedOutput -Pattern "Verified:.*Unsigned" -SimpleMatch).Count
Write-Log "   [+] Unsigned / Unverified files found: $UnsignedCount (check Unsigned_Files.txt)" "Yellow"

# ------------------ 6. ALTERNATE DATA STREAMS (streams) ------------------
Write-Log "6. Checking for Hidden Alternate Data Streams..." "Yellow"
Start-Process -Wait -FilePath "streams.exe" -ArgumentList "/accepteula /s C:\" -RedirectStandardOutput "$ReportRoot\Hidden_Streams.txt"
Write-Log "   [+] Hidden streams scan saved to Hidden_Streams.txt" "Green"

# ------------------ 7. SUMMARY REPORT ------------------
Write-Log "=============================================" "Cyan"
Write-Log " AUDIT COMPLETE" "Cyan"
Write-Log "=============================================" "Cyan"
Write-Log "Report Folder: $ReportRoot" "Green"
Write-Log "Master Log: $LogFile" "Green"

if ($UnsignedCount -gt 50) {
    Write-Log "⚠️  WARNING: A large number of unsigned files detected. Investigate 'Unsigned_Files.txt'." "Red"
} else {
    Write-Log "✅ System files appear mostly signed and original." "Green"
}

Write-Log "To investigate further, open Autoruns.csv in Excel and check the 'Verified' column."

# Open the folder automatically
Invoke-Item $ReportRoot
```

---

## 🚀 How to Run It (Step-by-Step)

### Prerequisite
Ensure the Sysinternals Suite is installed via the Microsoft Store (you already have it) OR extract the ZIP to a folder and update the `$Env:Path` line in the script to point to that folder.

### Execution
1. Open **PowerShell** as **Administrator** (Right-click -> Run as Administrator).
2. Navigate to where you saved `Invoke-SysinternalsAudit.ps1`.
3. If you get an execution policy error, run this first:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Run the script:
   ```powershell
   .\Invoke-SysinternalsAudit.ps1
   ```

---

## 📊 What to Look For (Investigation Guide)

| File to Check | What to Look For | Why |
| :--- | :--- | :--- |
| **`Unsigned_Files.txt`** | Any `.exe` or `.dll` in `C:\Windows\System32` marked as "Unsigned". | Windows system files should **never** be unsigned. This is a massive red flag (rootkit/malware). |
| **`Autoruns.csv`** | Look at the **"Verified"** column. If it says `FALSE` and the file is in a temp/user folder, it is suspicious. | Malware always adds itself to startup. |
| **`Network_Connections.txt`** | Look for connections to **foreign IP addresses** (outside 192.168.x.x or 10.x.x.x) with ESTABLISHED state. | Malware exfiltrates data. |
| **`Hidden_Streams.txt`** | Files with `:$DATA` appended. | Malware hides in ADS (Alternate Data Streams). |
| **`Processes.txt`** | Processes running from `C:\Users\YourName\AppData\Local\Temp\` | Legitimate software rarely runs directly from temp folders. |

---

## 🔥 Advanced Customizations

1. **Quick Mode (Scan System32 only instead of entire C:\)**  
   Replace the sigcheck line with:
   ```powershell
   Start-Process -Wait -FilePath "sigcheck.exe" -ArgumentList "/accepteula -s -i C:\Windows\System32" -RedirectStandardOutput $UnsignedOutput
   ```

2. **Auto-Kill Malicious Processes**  
   You can add a line to kill processes that run from temp:
   ```powershell
   Get-Process | Where-Object { $_.Path -like "*Temp*" } | Stop-Process -Force
   ```

3. **Auto-Quarantine**  
   Move unsigned files found in system folders to a quarantine folder using `Move-Item`.

---

This script transforms your Sysinternals collection into a **legitimate Cyber Security Audit Tool**. It's perfect for incident response, forensic analysis, or simply checking if your PC has been compromised. The entire output is saved, timestamped, and easy to analyze.
