param([Parameter(Mandatory=$true)] [String]$version)

# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

$netFrameworkVersion = "net10.0"
$publishTrimmed = $True
$versionDots = $version.Replace('_', '.')

Remove-Item ./package -Recurse -ErrorAction Ignore
mkdir ./package

# Convenience function to exit out if last command fail
function CheckFail
{
	#if (-Not ($?))
	if ($LASTEXITCODE -ne 0)
	{
		echo "Fatal error: $LASTEXITCODE"
		exit -1
	}
}

function CodeSign($folder, $checkFail)
{
	echo "Code signing $folder"
	Get-ChildItem $folder/* -r -inc *.exe,*.dll | Foreach-Object {
		$signTool = $env:IPBAN_SIGN_TOOL
		$certFile = $env:IPBAN_SIGN_FILE
		$certPassword = $env:IPBAN_SIGN_PASSWORD
		$certTimestampUrl = $env:IPBAN_SIGN_URL
		$certThumprint = $env:IPBAN_SIGN_THUMBPRINT
		$fullPath = $_.FullName
		
		# & $signTool sign /debug /q /t $certTimestampUrl /fd SHA256 /f $certFile /p $certPassword $fullPath; $checkFail
		& $signTool sign /fd SHA256 /tr $certTimestampUrl /td SHA256 /sha1 $certThumprint $fullPath; $checkFail
	}
}

& taskkill /im dotnet.exe /F

# IPBan Linux x64
& dotnet restore -r linux-x64; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/linux-x64 -c Release -r linux-x64 /p:DebuggerSupport=false /p:CopyOutputSymbolsToPublishDirectory=false /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishReadyToRun=false; CheckFail

# IPBan Arm Linux-arm
& dotnet restore -r linux-arm; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/linux-arm -c Release -r linux-arm /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishReadyToRun=false; CheckFail

# IPBan Arm Linux-arm64
& dotnet restore -r linux-arm64; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/linux-arm64 -c Release -r linux-arm64 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishReadyToRun=false; CheckFail

# IPBan Windows x64
& dotnet restore -r win-x64; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/win-x64 -c Release -r win-x64 /p:DebuggerSupport=false /p:CopyOutputSymbolsToPublishDirectory=false /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishReadyToRun=false; CheckFail
CodeSign package/win-x64 CheckFail

# IPBan Windows x86
& dotnet restore -r win-x86; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/win-x86 -c Release -r win-x86 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:PublishReadyToRun=false; CheckFail
CodeSign package/win-x86 CheckFail

Compress-Archive -Path ./package/linux-x64/* -DestinationPath ./package/IPBan-Linux-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/linux-arm/* -DestinationPath ./package/IPBan-Linux-Arm_$version.zip; CheckFail
Compress-Archive -Path ./package/linux-arm64/* -DestinationPath ./package/IPBan-Linux-Arm64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x64/* -DestinationPath ./package/IPBan-Windows-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x86/* -DestinationPath ./package/IPBan-Windows-x86_$version.zip; CheckFail

& taskkill /im dotnet.exe /F