# PyInstaller spec for Sentinel Scan on Windows.
#
#   pip install pyinstaller
#   pyinstaller packaging/windows/sentinel.spec --clean --noconfirm
#
# Produces dist/sentinel/ containing sentinel.exe (console) and
# sentinel-gui.exe (windowed), sharing one set of libraries.
#
# Two notes that cost real debugging time if missed:
#
# 1. Detectors register themselves on import, and the registry looks them up
#    by name. PyInstaller's static analysis cannot see that indirection, so
#    every detector module is listed in `hiddenimports`. A missing one shows
#    up as a silently absent detector, not as an ImportError.
#
# 2. The bundled YARA rules and the Qt stylesheet are data, not code. They
#    must be listed in `datas` or the frozen app starts with no rules and an
#    unstyled window.

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent.parent
SRC = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC))
from sentinel.version import __version__  # noqa: E402

block_cipher = None

# --- data files -------------------------------------------------------
datas = [
    (str(SRC / "sentinel" / "signatures" / "manifest.json"), "sentinel/signatures"),
    (str(SRC / "sentinel" / "signatures" / "local" / "rules"),
     "sentinel/signatures/local/rules"),
    (str(SRC / "sentinel" / "ui" / "styles"), "sentinel/ui/styles"),
]

# Signature bundles are downloaded at runtime, but ship any that are present
# so an offline install still has something to match on.
for name in ("hashes.db", "main.cvd", "daily.cvd"):
    candidate = SRC / "sentinel" / "signatures" / "local" / name
    if candidate.is_file() and candidate.stat().st_size > 0:
        datas.append((str(candidate), "sentinel/signatures/local"))

# --- hidden imports ---------------------------------------------------
hiddenimports = [
    # Detectors are discovered through the registry, never imported by name.
    "sentinel.engine.detectors.hash_detector",
    "sentinel.engine.detectors.yara_detector",
    "sentinel.engine.detectors.clamav_detector",
    "sentinel.engine.detectors.pe_heuristic",
    "sentinel.engine.detectors.script_detector",
    "sentinel.engine.detectors.archive_detector",
    "sentinel.engine.detectors.cloud_detector",
    # Platform backends are imported conditionally at runtime.
    "sentinel.system.platform_win",
    # Optional back-ends: present only if installed at build time.
    "yara",
    "pefile",
    "psutil",
    "clamd",
]
hiddenimports += collect_submodules("sentinel.ui.windows")

# --- exclusions -------------------------------------------------------
# These pull in tens of megabytes and nothing imports them.
excludes = [
    "tkinter", "matplotlib", "numpy", "scipy", "pandas",
    "IPython", "jupyter", "notebook", "pytest", "setuptools",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.Qt3DCore", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtMultimedia", "PySide6.QtQuick", "PySide6.QtQml",
]

analysis = Analysis(
    [str(SRC / "sentinel" / "__main__.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

gui_analysis = Analysis(
    [str(SRC / "sentinel" / "ui" / "app.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    excludes=excludes,
    cipher=block_cipher,
    noarchive=False,
)

# Share one PYZ between both executables rather than duplicating ~40 MB.
MERGE(
    (analysis, "sentinel", "sentinel"),
    (gui_analysis, "sentinel-gui", "sentinel-gui"),
)

pyz = PYZ(analysis.pure, analysis.zipped_data, cipher=block_cipher)
gui_pyz = PYZ(gui_analysis.pure, gui_analysis.zipped_data, cipher=block_cipher)

VERSION_TUPLE = tuple(
    int(part) for part in (__version__.split(".") + ["0", "0", "0", "0"])[:4]
)

cli_exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX is deliberately off. Packing our own binary would make every
    # heuristic engine on the planet — including ours — flag the scanner as
    # suspicious, which is a self-inflicted support burden.
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(SPEC_DIR / "icon.ico") if (SPEC_DIR / "icon.ico").is_file() else None,
    version=None,
)

gui_exe = EXE(
    gui_pyz,
    gui_analysis.scripts,
    [],
    exclude_binaries=True,
    name="sentinel-gui",
    debug=False,
    strip=False,
    upx=False,
    console=False,  # windowed: no console flash on launch
    disable_windowed_traceback=False,
    icon=str(SPEC_DIR / "icon.ico") if (SPEC_DIR / "icon.ico").is_file() else None,
)

collection = COLLECT(
    cli_exe,
    analysis.binaries,
    analysis.zipfiles,
    analysis.datas,
    gui_exe,
    gui_analysis.binaries,
    gui_analysis.zipfiles,
    gui_analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="sentinel",
)
