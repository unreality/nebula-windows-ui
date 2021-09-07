Windows UI for Nebula
----------

![Nebula](resources/nebula-icon.png?raw=true "Nebula")

Basic Windows GUI for [Nebula](https://github.com/slackhq/nebula). Not recommended for production use, its very rough and hacked together. Pull requests welcome.

Tunnel Profiles
---------------

* Tunnel configs are stored in `C:\Users\<username>\AppData\Roaming\Nebula`
* Each directory in the Nebula directory is treated as a different tunnel
  * E.g `C:\Users\<username>\AppData\Roaming\Nebula\my-tunnel-config` will appear as `my-tunnel-config`

Building
--------

To build you'll need [rsrc](https://github.com/akavel/rsrc)
```
go mod download
rsrc -ico resources\nebula-icon.ico -manifest resources\manifest.xml -o rsrc.syso
go build -ldflags "-H=windowsgui" -o build\nebula-ui.exe
```