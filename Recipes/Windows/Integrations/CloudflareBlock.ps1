# Cloudflare block IP
$ip=$args[0]
$date=Get-Date
$logdate=Get-Date -format yyyy-MM-dd
$logfile="$PSScriptRoot\Cloudflare-$logdate.log"
# Replace API key & Email address
$email="EMAILADDR"
$apikey="APIKEY"
Write-Output "$date Ban task started" >> $logfile
# Check for IP arg
if (!$args[0])  { Write-Output "$date Missing IP, Quitting..." >> $logfile
    exit
    }
Write-Output "$date Attempting to block $ip" >> $logfile
# Check if IP is IPv4 or IPv6
if($ip -like '*:*') { $ipv="ip6" }
	else { $ipv="ip" }

$BODY = @{'mode' = 'block'
    'configuration' = @{
        'target' = "$ipv"
        'value' = "$ip"
    }
    'notes' = "IPBan $date"
}
$Jsonbody = $Body | ConvertTo-Json
# Actual ban operation
Try { (Invoke-WebRequest -Uri "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules" -Method 'POST' -Body $JSONBODY -ContentType "application/json" -Headers @{'Accept'='application/json';'X-Auth-Email'="$email";'X-Auth-Key'="$apikey"}) }
         catch {
            $message = $_
            Write-Output "$date $message" >> $logfile
            Write-Output "$date Cloudflare API ERROR, Quitting..." >> $logfile
          exit
          }

Write-Output "$date Task Finished Blocked $ipv $ip" >> $logfile
