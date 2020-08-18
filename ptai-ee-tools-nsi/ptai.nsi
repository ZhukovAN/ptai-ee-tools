;--------------------------------
; General

!define TRUE 1
!define FALSE 0
!define DEBUG ${FALSE}

; Name and file
Name "PT AI integration service"
OutFile "Installer.exe"
Unicode True

; Default installation folder
InstallDir "$PROGRAMFILES64\Positive Technologies\Application Inspector Integration Service"
  
; Request application privileges for Windows
RequestExecutionLevel admin

;--------------------------------
; Include Modern UI

!include "MUI2.nsh"
!include "StrFunc.nsh"
!include "functions.nsi"
  
;--------------------------------
; Declare used functions
${StrRep}

;--------------------------------
; Interface Settings

!define MUI_ABORTWARNING

;--------------------------------
;Pages

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
  
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
 
;--------------------------------
; Languages
 
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Check prerequisites, i.e. if PT AI server installed
!define PTAI_CHECK_HKLM_REGISTRY_BRANCH SYSTEM\CurrentControlSet\Services\AI.Enterprise.Gateway
; This variable will store path to Consul's serverConfig.json file (we may need to extract Consul master token from there)
Var CONSULCONFIG

Function .onInit

	${If} ${DEBUG} == ${TRUE}
		StrCpy $CONSULCONFIG "C:\DATA\DEVEL\MISC\CONSUL\1.5.3\serverConfig.json"
	${Else}
		; Check if PT AI server installed
		ReadRegStr $0 HKLM ${PTAI_CHECK_HKLM_REGISTRY_BRANCH} "ImagePath"
		
		${If} $0 == ""
			MessageBox MB_OK "PT AI server installation folder not found. Setup will now exit."
			Abort	
		${EndIf}
		; If PT AI server installed then $0 equals to something like 
		; C:\Program Files (x86)\Positive Technologies\Application Inspector Server\Services\gateway\AIE.Gateway.exe --runService
		; Get root PT AI EE server installation folder
		${StrRep} $0 $0 "Services\gateway\AIE.Gateway.exe --runService" ""
		StrCpy $CONSULCONFIG "$0Services\consul\serverConfig.json"
	${EndIf}
	
 FunctionEnd
 
;--------------------------------
;Installer Sections

Section "Core components" SectionCore
	; Save README.md
	SetOutPath "$INSTDIR"
	File /nonfatal /a "README.md"
	; Save JDK
	SetOutPath "$INSTDIR\jdk"
	File /nonfatal /a /r "jdk\"
	; Save main service JAR
	SetOutPath "$INSTDIR\bin"
	File /nonfatal /a /oname=ptai-integration-service.jar "..\ptai-ee-tools-java\ptai-integration-service\target\ptai-integration-service-0.1-spring-boot.jar"
	; Save CLI tool
	File /nonfatal /a /oname=ptai-cli-plugin.jar "..\ptai-ee-tools-java\ptai-cli-plugin\target\ptai-cli-plugin-0.1-jar-with-dependencies.jar"
	; Save Java service wrapper as EXE file
	File /nonfatal /a /oname=ptai-integration-service.exe "tools\WinSW.NET461.exe"
	; Save Java service wrapper configuration and replace template java path with correct value
	File /nonfatal /a "..\ptai-ee-tools-java\ptai-integration-service\service\windows\ptai-integration-service.xml"
	Push "<executable>java</executable>"
	Push "<executable>$\"$INSTDIR\jdk\bin\java.exe$\"</executable>"
	Push all
	Push all
	Push $INSTDIR\bin\ptai-integration-service.xml
	Call AdvReplaceInFile
	; Save Consul configuration file path to INI file
	WriteINIStr "$INSTDIR\bin\install.ini" "CONSUL" "CONFIGFILE" $CONSULCONFIG
	DetailPrint "Consul configuration file path $0 written to $INSTDIR\bin\install.ini"

	; Register service
	ExecWait '"$INSTDIR\bin\ptai-integration-service.exe" install' $0
	DetailPrint "Service registration result $0"

	; Create uninstaller
	WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

;--------------------------------
; Uninstaller Section

Section "Uninstall"

	; Unregister service
	ExecWait '"$INSTDIR\bin\ptai-integration-service.exe" uninstall' $0
	DetailPrint "Service unregistration result $0"

	Delete "$INSTDIR\Uninstall.exe"
	
	RMDir /r "$INSTDIR"
	
SectionEnd

