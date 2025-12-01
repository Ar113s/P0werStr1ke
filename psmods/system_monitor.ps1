function Show-LoadingAnimation {
    <#
    .SYNOPSIS
        Shows a loading animation in PowerShell console.
    .PARAMETER Message
        The message to display during loading.
    .PARAMETER Type
        Type of animation: Spinner, Dots, Progress
    .PARAMETER Duration
        Duration in seconds (for demo purposes)
    #>
    [CmdletBinding()]
    param(
        [string]$Message = "Processing",
        [ValidateSet("Spinner", "Dots", "Progress")]
        [string]$Type = "Spinner",
        [int]$Duration = 3
    )
    
    $originalCursorVisible = [Console]::CursorVisible
    [Console]::CursorVisible = $false
    
    try {
        switch ($Type) {
            "Spinner" {
                $spinChars = @('|', '/', '-', '\')
                $counter = 0
                $endTime = (Get-Date).AddSeconds($Duration)
                
                while ((Get-Date) -lt $endTime) {
                    $spin = $spinChars[$counter % 4]
                    Write-Host "`r$Message... $spin" -NoNewline
                    Start-Sleep -Milliseconds 100
                    $counter++
                }
            }
            
            "Dots" {
                $counter = 0
                $endTime = (Get-Date).AddSeconds($Duration)
                
                while ((Get-Date) -lt $endTime) {
                    $dots = "." * (($counter % 4) + 1)
                    $spaces = " " * (4 - $dots.Length)
                    Write-Host "`r$Message$dots$spaces" -NoNewline
                    Start-Sleep -Milliseconds 500
                    $counter++
                }
            }
            
            "Progress" {
                $barWidth = 30
                $progressStep = $barWidth / ($Duration * 10)
                $progress = 0
                
                while ($progress -le $barWidth) {
                    $filled = [math]::Floor($progress)
                    $percent = [math]::Round(($filled / $barWidth) * 100)
                    
                    $bar = "█" * $filled + "░" * ($barWidth - $filled)
                    Write-Host "`r$Message`: [$bar] $percent%" -NoNewline
                    
                    Start-Sleep -Milliseconds 100
                    $progress += $progressStep
                }
            }
        }
        
        # Clear the line
        Write-Host "`r$(' ' * 80)`r" -NoNewline
        
    } finally {
        [Console]::CursorVisible = $originalCursorVisible
    }
}

function Start-SystemInfoWithAnimation {
    <#
    .SYNOPSIS
        Shows system information gathering with loading animation.
    #>
    [CmdletBinding()]
    param()
    
    Show-LoadingAnimation -Message "Gathering system information" -Type "Spinner" -Duration 2
    Get-SystemInfo
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Retrieves and displays beautifully formatted system information.
    .DESCRIPTION
        This function gathers key system data including Operating System, CPU, GPU, RAM, and Disk Space,
        and presents it in a visually appealing, organized format.
    .EXAMPLE
        Get-SystemInfo
    #>
    [CmdletBinding()]
    param()

    # --- Clear Screen for a Fresh Look ---
    Clear-Host
    
    Write-Host "🔄 " -NoNewline -ForegroundColor Cyan
    Write-Host "Initializing system scan..." -ForegroundColor White
    Show-LoadingAnimation -Message "Collecting OS information" -Type "Dots" -Duration 1

    # --- Operating System Information ---
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = "$($osInfo.Caption) $($osInfo.Version)"
    $osBuild = $osInfo.BuildNumber
    $osArch = $osInfo.OSArchitecture
    $computerName = $env:COMPUTERNAME
    $currentUser = $env:USERNAME

    # --- CPU Information ---
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor
    $cpuName = $cpuInfo.Name
    $cpuCores = $cpuInfo.NumberOfCores
    $cpuThreads = $cpuInfo.NumberOfLogicalProcessors

    # --- GPU Information ---
    $gpuInfo = Get-CimInstance -ClassName Win32_VideoController
    $gpuName = $gpuInfo.Name

    # --- Memory (RAM) Information ---
    $memInfo = Get-CimInstance -ClassName Win32_PhysicalMemory
    $totalRamGb = [Math]::Ceiling((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $memSlots = $memInfo.Count
    $memSpeed = ($memInfo | Select-Object -First 1).Speed

    # --- Disk Space Information (System Drive) ---
    $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
    $diskSizeGb = [Math]::Round($systemDrive.Size / 1GB, 2)
    $diskFreeGb = [Math]::Round($systemDrive.FreeSpace / 1GB, 2)
    $diskFreePercentage = [Math]::Round(($diskFreeGb / $diskSizeGb) * 100, 2)
    $diskUsageBar = "[" + ("=" * [int]($diskFreePercentage / 5)) + (" " * (20 - [int]($diskFreePercentage / 5))) + "]"

    Write-Host "⚙️ " -NoNewline -ForegroundColor Cyan
    Write-Host "Analyzing hardware components..." -ForegroundColor White
    Show-LoadingAnimation -Message "Scanning CPU and GPU" -Type "Progress" -Duration 1

    # --- Output Formatting ---
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                 💻   System Information   💻                 ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $style = @{
        Category = @{ ForegroundColor = 'White'; Bold = $true }
        Property = @{ ForegroundColor = 'Green' }
        Value    = @{ ForegroundColor = 'White' }
    }

    Write-Host "  🖥️  " -NoNewline; Write-Host "Host" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    Write-Host "    " -NoNewline; Write-Host "Computer Name  : " -ForegroundColor Green -NoNewline; Write-Host $computerName -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Current User   : " -ForegroundColor Green -NoNewline; Write-Host $currentUser -ForegroundColor White
    Write-Host ""

    Write-Host "  📀  " -NoNewline; Write-Host "Operating System" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    Write-Host "    " -NoNewline; Write-Host "OS Version     : " -ForegroundColor Green -NoNewline; Write-Host $osVersion -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Build Number   : " -ForegroundColor Green -NoNewline; Write-Host $osBuild -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Architecture   : " -ForegroundColor Green -NoNewline; Write-Host $osArch -ForegroundColor White
    Write-Host ""

    Write-Host "  ⚙️  " -NoNewline; Write-Host "Processor (CPU)" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    Write-Host "    " -NoNewline; Write-Host "Name           : " -ForegroundColor Green -NoNewline; Write-Host $cpuName -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Cores          : " -ForegroundColor Green -NoNewline; Write-Host $cpuCores -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Logical Procs  : " -ForegroundColor Green -NoNewline; Write-Host $cpuThreads -ForegroundColor White
    Write-Host ""

    Write-Host "  🎨  " -NoNewline; Write-Host "Graphics (GPU)" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    # Handle multiple GPUs
    foreach ($gpu in $gpuName) {
        Write-Host "    " -NoNewline; Write-Host "Name           : " -ForegroundColor Green -NoNewline; Write-Host $gpu -ForegroundColor White
    }
    Write-Host ""

    Write-Host "  🧠  " -NoNewline; Write-Host "Memory (RAM)" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    Write-Host "    " -NoNewline; Write-Host "Total RAM      : " -ForegroundColor Green -NoNewline; Write-Host "$($totalRamGb) GB" -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Memory Slots   : " -ForegroundColor Green -NoNewline; Write-Host $memSlots -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Speed          : " -ForegroundColor Green -NoNewline; Write-Host "$($memSpeed) MHz" -ForegroundColor White
    Write-Host ""

    Write-Host "  💾  " -NoNewline; Write-Host "System Drive ($($systemDrive.DeviceID))" -ForegroundColor White
    Write-Host ("    " + ("-" * 50))
    Write-Host "    " -NoNewline; Write-Host "Total Size     : " -ForegroundColor Green -NoNewline; Write-Host "$($diskSizeGb) GB" -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Free Space     : " -ForegroundColor Green -NoNewline; Write-Host "$($diskFreeGb) GB ($($diskFreePercentage)%)" -ForegroundColor White
    Write-Host "    " -NoNewline; Write-Host "Usage          : " -ForegroundColor Green -NoNewline; Write-Host $diskUsageBar -ForegroundColor White
    Write-Host ""
    Write-Host ""

    Write-Host "✅ " -NoNewline -ForegroundColor Green
    Write-Host "System analysis complete!" -ForegroundColor White
    Write-Host ""

}

# To run the function, simply call its name:
Get-SystemInfo