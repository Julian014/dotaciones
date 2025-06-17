@echo off
echo 🔄 Limpiando proyecto Flutter y dependencias previas...

:: Elimina archivos temporales y caché
del /f /q pubspec.lock 2>nul
rd /s /q .dart_tool
rd /s /q build
flutter clean

echo ✅ Obteniendo paquetes correctos desde pubspec.yaml...
flutter pub get

echo 🔍 Verificando versión de workmanager usada...
flutter pub deps | findstr workmanager

echo 🚀 Compilando APK en modo release...
flutter build apk --release

pause
