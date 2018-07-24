param([Parameter(Mandatory=$true)] [String]$version)

rm -r "./package"
dotnet publish IPBan.sln -f netcoreapp2.1 -o package/linux-x64 -c Release -r linux-x64
dotnet publish IPBan.sln -f netcoreapp2.1 -o package/win-x86 -c Release -r win-x86
Compress-Archive -Path ./package/linux-x64/* -DestinationPath ./package/IPBan-Linux-x64.zip
Compress-Archive -Path ./package/win-x86/* -DestinationPath ./package/IPBan-Windows-x86.zip
Compress-Archive -Path ./package/IPBan-Linux-x64.zip,./package/IPBan-Windows-x86.zip -DestinationPath ./package/IPBan_$version.zip -CompressionLevel NoCompression