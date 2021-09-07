go mod download
rsrc -ico resources\nebula-icon.ico -manifest resources\manifest.xml -o rsrc.syso
go build -ldflags "-H=windowsgui" -o build\nebula-ui.exe