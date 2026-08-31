# -*- mode: python ; coding: utf-8 -*-
import os

# 어디서 pyinstaller를 실행하든 동일하게 동작하도록, 이 spec 파일이 있는 폴더(src\)를
# 기준으로 모든 경로를 잡는다. SPECPATH는 PyInstaller가 주입해주는 전역이다.
SRC = SPECPATH
ASSETS = os.path.join(SRC, 'assets')

# v1.9.16: 창 아이콘용 크기별 PNG를 _internal 안에 넣는다 — 배포 폴더 루트를 EzDrops.exe
# 하나로 유지하기 위함. main.py의 get_resource_dir()가 sys._MEIPASS에서 이 파일들을 읽는다.
# (쓰기가 필요한 run_log.txt / browser_profiles는 종전대로 exe 옆에 생성된다.)
icon_datas = [
    (os.path.join(ASSETS, f'icon_{s}.png'), '.')
    for s in (16, 24, 32, 48, 64, 128, 256)
]

a = Analysis(
    [os.path.join(SRC, 'main.py')],
    pathex=[],
    binaries=[],
    datas=icon_datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='EzDrops',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # [주의] UPX가 PATH에 없으면 PyInstaller가 아무 경고 없이 이 옵션을 건너뛴다.
    # 현재 이 PC에는 UPX가 없어 실제로는 압축이 적용되지 않는 상태다.
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(ASSETS, 'icon.ico')],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='EzDrops',
)
