# can run on Linux, use https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.2
# C:/Program Files/PowerShell/7/pwsh.exe|C:/SCRIPTS/cloudflareban/Cloudflare.PS1 -Ip &quot;###IPADDRESS###&quot; -Source &quot;###SOURCE###&quot;
# Cloudflare block IP
Param(
    [Parameter(Mandatory=$true)]
    [string]$Ip,
    
    [Parameter(Mandatory=$true)]
    [string]$Source
)
# Replace API key & Email address
$email="EMAIL_ADDRESS"
$apikey="APIKEY"

$date=Get-Date
$logdate=Get-Date -format yyyy-MM-dd
$logfile="$PSScriptRoot\Cloudflare-$logdate.log"

Write-Output "$date Ban task started" >> $logfile
Write-Output "$date Attempting to block $ip" >> $logfile

# Check if IP is IPv4 or IPv6
if ($ip -contains ":") {
    $ipv = "ip6"
} else {
    $ipv = "ip"
}

$UnixEpoch=[int]((Get-Date).ToUniversalTime() - (Get-Date "1970-01-01")).TotalSeconds

$notes = "service=IPBan;source=$Source;date=$UnixEpoch"

$Body = @{
    configuration = @{
        target=$ipv
        value=$ip
    }
	mode = 'block'
    notes = $notes
} | ConvertTo-Json

# Actual ban operation
Try {
    Invoke-WebRequest -UseBasicParsing -Uri "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" -Method 'POST' -Body $Body -ContentType "application/json" -Headers @{'Accept'='application/json';'X-Auth-Email'="$email";'X-Auth-Key'="$apikey"}
} catch {
    Write-Output "$date $_" >> $logfile
    Write-Output "$date Cloudflare API ERROR, Quitting..." >> $logfile
    exit 1
}

Write-Output "$date Task Finished Blocked $ipv $ip" >> $logfile