param([Parameter(Mandatory=$true)] [String]$version)

# Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

$netFrameworkVersion = "net6.0"
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
		$fullPath = $_.FullName
		
		& $signTool sign /debug /q /t $certTimestampUrl /fd SHA256 /f $certFile /p $certPassword $fullPath; $checkFail
	}
}

& taskkill /im dotnet.exe /F

# IPBan Linux x64
& dotnet restore -r linux-x64; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/linux-x64 -c Release -r linux-x64 /p:DebuggerSupport=false /p:CopyOutputSymbolsToPublishDirectory=false /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail

# IPBan Windows x64
& dotnet restore -r win-x64; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/win-x64 -c Release -r win-x64 /p:DebuggerSupport=false /p:CopyOutputSymbolsToPublishDirectory=false /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail
CodeSign package/win-x64 CheckFail

# IPBan Windows x86
& dotnet restore -r win-x86; CheckFail
& dotnet clean -c Release; CheckFail
& dotnet publish IPBan.csproj --self-contained -f $netFrameworkVersion -o package/win-x86 -c Release -r win-x86 /p:Version=$versionDots /p:AssemblyVersion=$versionDots /p:FileVersion=$versionDots /p:PublishTrimmed=$publishTrimmed /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true; CheckFail
CodeSign package/win-x86 CheckFail

Compress-Archive -Path ./package/linux-x64/* -DestinationPath ./package/IPBan-Linux-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x64/* -DestinationPath ./package/IPBan-Windows-x64_$version.zip; CheckFail
Compress-Archive -Path ./package/win-x86/* -DestinationPath ./package/IPBan-Windows-x86_$version.zip; CheckFail

& taskkill /im dotnet.exe /F