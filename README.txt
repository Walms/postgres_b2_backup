
# Build as a self-contained executable (for Linux - modify for your OS)
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true
