param([Parameter(Mandatory=$true)] [String]$version)

Remove-Item ./package -Recurse -ErrorAction Ignore
mkdir ./package
& "c:/program files/dotnet/dotnet.exe" publish IPBan.csproj -f netcoreapp2.2 -o package/linux-x64 -c Release -r linux-x64
& "c:/program files/dotnet/dotnet.exe" publish IPBan.csproj -f netcoreapp2.2 -o package/win-x64 -c Release -r win-x64
& "c:/program files (x86)/dotnet/dotnet.exe" publish IPBan.csproj -f netcoreapp2.2 -o package/win-x86 -c Release -r win-x86
Compress-Archive -Path ./package/linux-x64/* -DestinationPath ./package/IPBan-Linux-x64.zip
Compress-Archive -Path ./package/win-x64/* -DestinationPath ./package/IPBan-Windows-x64.zip
Compress-Archive -Path ./package/win-x86/* -DestinationPath ./package/IPBan-Windows-x86.zip
Compress-Archive -Path ./package/IPBan-Linux-x64.zip,./package/IPBan-Windows-x86.zip,./package/IPBan-Windows-x64.zip -DestinationPath ./package/IPBan_$version.zip -CompressionLevel NoCompression