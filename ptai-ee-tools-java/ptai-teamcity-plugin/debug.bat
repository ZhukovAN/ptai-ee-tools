call mvn tc-sdk:stop
call mvn install tc-sdk:start -DstartAgent=false -Dteamcity.development.mode=true
REM call mvn install tc-sdk:start -Dteamcity.development.mode=true
