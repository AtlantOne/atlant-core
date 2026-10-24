@echo off
setlocal
chcp 65001 >nul
echo [Atlant VPN] Сборка библиотеки atlant.aar на локальном ПК...

set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
if not defined JAVA_HOME set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%USERPROFILE%\go\bin;%PATH%"

cd /d "%~dp0client\android"

echo Проверка наличия NDK...
if not exist "%ANDROID_HOME%\ndk" (
    echo [ОШИБКА] NDK не найден в %ANDROID_HOME%\ndk!
    echo Установите NDK через Android Studio:
    echo 1. Откройте Android Studio -> Tools -> SDK Manager
    echo 2. Вкладка SDK Tools -> отметьте "NDK (Side by side)"
    echo 3. Нажмите Apply и дождитесь загрузки.
    pause
    exit /b 1
)

echo Запуск gomobile bind...
if not exist "%~dp0artifacts\android" mkdir "%~dp0artifacts\android"
gomobile bind -target=android/arm64,android/arm -androidapi 24 -o "%~dp0artifacts\android\atlant.aar" .
set "ATLANT_BUILD_EXIT=%ERRORLEVEL%"

if %ATLANT_BUILD_EXIT% EQU 0 (
    echo [УСПЕХ] Библиотека artifacts\android\atlant.aar успешно собрана локально!
) else (
    echo [ОШИБКА] Сборка gomobile завершилась с кодом %ATLANT_BUILD_EXIT%.
)

exit /b %ATLANT_BUILD_EXIT%
