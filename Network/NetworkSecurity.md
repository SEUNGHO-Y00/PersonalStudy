# Basic Knowledge

* Port 8883 is the official, IANA-registered TCP port for secure MQTT (Message Queuing Telemetry Transport over TLS/SSL).

* The file masvc.exe is a legitimate executable belonging to the Trellix (formerly McAfee) Agent. It securely sends traffic outside your network to communicate with the enterprise security management server (ePO) or cloud updates.

# Palo Alto Firewall

* Monitor filder command - To filter logs on the Palo Alto firewall, navigate to Monitor > Logs > Traffic. In the search bar, use the expression (addr.src in 'IP_ADDRESS') to find a specific source IP, or (addr.dst in 'IP_ADDRESS') to find traffic going to a destination IP.

# Window Command

```command prompt
netstat -an | findstr XXX
```

# Automation Script

* You can replace the standard netstat -ano command with the native PowerShell equivalent, Get-NetTCPConnection. This allows you to filter and catch any connections to the 137.137.x.x range in real-time, returning structured data with process names and PIDs.

```powershell
$targetRange = "^137\.137\."
$logFile = "C:\temp\netstat_137_log.txt"

Write-Host "Monitoring for 137.137.x.x connections... Press Ctrl+C to stop."

while ($true) {
    Get-NetTCPConnection | 
    Where-Object { $_.RemoteAddress -match $targetRange } | 
    ForEach-Object {
        $processName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name
        $logEntry = "$(Get-Date) - Connection found: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) [PID: $($_.OwningProcess) - $processName]"
        
        # Output to console
        Write-Host $logEntry -ForegroundColor Yellow
        
        # Append to log file
        Add-Content -Path $logFile -Value $logEntry
    }
    Start-Sleep -Seconds 5
}
```

# Resource

* [CheckWhois.com](https://checkwhois.com/137.137.0.0)
