param([Parameter(Mandatory=$true)] [String]$version)

# powershell -ExecutionPolicy Bypass

$netFrameworkVersion = "net5.0"
$publishTrimmed = $True
$trimMode = "Link"
$versionDots = $version.Replace('_', '.')

Remove-Item ./package -Recurse -ErrorAction Ignore
mkdir ./package

# Convenience function to exit out if last command fail
function CheckFail
{
	if (-Not ($?))
	{
		echo "Fatal error"
		exit -1
	}
}

function CodeSign($folder, $checkFail)
{
	echo "Code signing $folder"
	Get-ChildItem $folder/* -r -inc *.exe,*.dll | Foreach-Object -Parallel {
		$signTool = $env:IPBAN_SIGN_TOOL
		$certFile = $env:IPBAN_SIGN_FILE
		$certPassword = $env:IPBAN_SIGN_PASSWORD
		$certTimestampUrl = $env:IPBAN_SIGN_URL
		$fullPath = $_.FullName
		
		& $signTool sign /q /t $certTimestampUrl /fd SHA256 /f $certFile /p $certPassword $fullPath; $checkFail
	}
}

& taskkill /im dotnet.exe /F

# IPBan Linux x64
& "c:/program files/dotnet/dotnet.exe" restore -r linux-x64; CheckFail
& "c:/program files/dotnet/dotnet.exe" clean -c Release; CheckFail
& "c:/program files/dotnet/dotnet.exe" publish IPBan.csproj -f $netFrameworkVersion -o package/linux-x64 -c Release -r linux-x64 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:TrimMode=$trimMode /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail

# IPBan Windows x64
& "c:/program files/dotnet/dotnet.exe" restore -r win-x64; CheckFail
& "c:/program files/dotnet/dotnet.exe" clean -c Release; CheckFail
& "c:/program files/dotnet/dotnet.exe" publish IPBan.csproj -f $netFrameworkVersion -o package/win-x64 -c Release -r win-x64 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:TrimMode=$trimMode /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail
CodeSign package/win-x64 CheckFail

# IPBan Windows x86
& "c:/program files (x86)/dotnet/dotnet.exe" restore -r win-x86; CheckFail
& "c:/program files (x86)/dotnet/dotnet.exe" clean -c Release; CheckFail
& "c:/program files (x86)/dotnet/dotnet.exe" publish IPBan.csproj -f $netFrameworkVersion -o package/win-x86 -c Release -r win-x86 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:TrimMode=$trimMode /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail
CodeSign package/win-x86 CheckFail

Compress-Archive -Path ./package/linux-x64/* -DestinationPath ./package/IPBan-Linux-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x64/* -DestinationPath ./package/IPBan-Windows-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x86/* -DestinationPath ./package/IPBan-Windows-x86_$version.zip; CheckFail

& taskkill /im dotnet.exe /F