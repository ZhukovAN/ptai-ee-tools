REM consul.exe agent -bind=127.0.0.1 --data-dir=.\data -server -bootstrap -ui
REM consul.exe agent -bind=127.0.0.1 --data-dir=.\data -server -bootstrap -ui -config-file=serverConfig.json
set CONSUL_DIR=D:\TOOLS\DEVEL\MISC\CONSUL
pushd %CONSUL_DIR%
REM start %CONSUL_DIR%\consul.exe agent -config-file=%CONSUL_DIR%\serverConfig.json -join=10.0.0.3
start %CONSUL_DIR%\consul.exe agent -config-file=%CONSUL_DIR%\serverConfig.json -join=192.168.0.51
popd