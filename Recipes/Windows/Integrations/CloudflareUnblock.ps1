# can run on Linux, use https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.2
# C:/Program Files/PowerShell/7/pwsh.exe|C:/SCRIPTS/cloudflareban/CloudflareUnban.ps1 -Ip &quot;###IPADDRESS###&quot;
# Cloudflare unblock.ps1 
Param(
    [Parameter(Mandatory=$true)]
    [string]$Ip
)
# Replace API keys, Email address (AbuseIPDB API key not required)
$email="EMAILADDR"
$cfapikey="CFAPIKEY"
$abuseipdbapikey="ABUSEIPDBAPIKEY"
$score = 40

$date=Get-Date
$logdate=get-date -format yyyy-MM-dd
$logfile="$PSScriptRoot\Cloudflare-$logdate.log"
Write-Output "$date Unblock task started..." >> $logfile

# Check against AbuseIPDB, Helpful so as not to unban known abusive IPs, Remove "<#" and "#>" to use this
<#
Write-Output "$date Checking AbuseIPDB Score of $ip" >> $logfile # uncomment if you're using the AbuseIPDB check
Try {
	$confidence=Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$Ip&maxAgeInDays=90" -Method 'GET' -Headers @{'Accept'='application/json';'Key'="$abuseipdbapikey"} |
        % {$_.data.abuseConfidenceScore }
} Catch {
	Write-Output "$date $_" >> $logfile
	Write-Output "$date AbuseIPDB API ERROR" >> $logfile
}

Write-Output "$date Confidence score: $confidence" >> $logfile
If ($score –lt $confidence) {
	Write-Output "$date Score above threshold, will not remove ban" >> $logfile
	exit
} Else {
	Write-Output "$date Score below threshold, will remove ban" >> $logfile
}
#>
# Get ID of Cloudflare block rule
Try {
	$id=Invoke-RestMethod -UseBasicParsing -Uri "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?page=1&per_page=20&mode=block&configuration.target=ip&configuration.value=$ip&match=all&order=mode&direction=desc" -Method 'GET' -Headers @{'Accept'='application/json';'X-Auth-Email'="$email";'X-Auth-Key'="$cfapikey"} |
              % {$_.result.id}
} catch {
	$message = $_
	Write-Output "$date $message" >> $logfile
	Write-Output "$date Cloudflare API ERROR, unable to get ID of IP, Quitting..." >> $logfile
	exit 1
}

Write-Output "$date Got ID of block rule: $id" >> $logfile

# Remove ban
Try {
    Invoke-WebRequest -UseBasicParsing -Uri "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/$id" -Method 'DELETE' -Headers @{'Accept'='application/json';'X-Auth-Email'="$email";'X-Auth-Key'="$cfapikey"}
} catch {
    $message = $_
    Write-Output "$date $message" >> $logfile
    Write-Output "$date Cloudflare API ERROR, Quitting..." >> $logfile
    exit 1
}

Write-Output "$date Task Finished Unbanned $Ip" >> $logfile
