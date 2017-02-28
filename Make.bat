REM ---------
REM Variables
REM ---------
if "%ARCH%" == "" (
    set ARCH=x86
)

set SRC=%CD%\src
set B=release
set C=msvc-14.0-%ARCH%
set BDIR=c:\projects\build\%C%\%B%
set DEFS=-D_CRT_SECURE_NO_WARNINGS

REM -------------------------------
REM Setup Visual Studio environment
REM -------------------------------
if "%C%"=="msvc-14.0-x86" ( call "c:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86 )
if "%C%"=="msvc-14.0-x64" ( call "c:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64 )

REM ------------------
REM Build dependencies
REM ------------------
rmdir /S /Q %BDIR%
md %BDIR% %BDIR%\ucl-1.03 %BDIR%\upx %BDIR%\upx-testsuite %BDIR%\zlib-1.2.8

cd /D %BDIR%\ucl-1.03
SET s=c:\projects\deps\ucl-1.03
cl -MT -O2 -W4 %DEFS% -I%s%\include -I%s% -c %s%\src\*.c
link -lib -out:ucl.lib *.obj

cd /D %BDIR%\zlib-1.2.8
cl -MT -O2 -W2 %DEFS% -c c:\projects\deps\zlib-1.2.8\*.c
link -lib -out:zlib.lib *.obj

REM ----------------
REM Get Git Revision
REM ----------------
git rev-parse --short=12 HEAD > %BDIR%\upx\.GITREV.txt
set /p GITREV=<.GITREV.txt

cd /D %BDIR%\upx

REM ---------
REM Build upx
REM ---------
cl -MT -EHsc -J -O2 -W4 -DUPX_VERSION_GITREV="""%GITREV%""" %DEFS% -DWITH_LZMA=0x443 -DUCL_NO_ASM -I%SRC%\lzma-sdk -Ic:\projects\deps\ucl-1.03\include -Ic:\projects\deps\zlib-1.2.8 -Feupx.exe %SRC%\*.cpp %BDIR%\ucl-1.03\ucl.lib %BDIR%\zlib-1.2.8\zlib.lib
