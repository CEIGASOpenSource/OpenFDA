# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for OpenFDA standalone binary.

Build:
    pip install pyinstaller
    pyinstaller openfda.spec

Produces a single executable in dist/openfda (or dist/openfda.exe on Windows).
No Python installation required on the target machine.
"""

import os

a = Analysis(
    ['run.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    datas=[],
    hiddenimports=[
        'fda',
        'fda.gates',
        'fda.gates.mdm',
        'fda.gates.domain',
        'fda.gates.gov',
        'fda.gates.hypervisor',
        'fda.scan',
        'fda.scan.account',
        'fda.scan.ai_environment',
        'fda.scan.drives',
        'fda.scan.resources',
        'fda.scan.profile',
        'fda.scan.tools',
        'fda.attest',
        'fda.attest.machine_id',
        'fda.attest.hmac_sign',
        'fda.report',
        'fda.report.builder',
        'fda.report.display',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'unittest', 'email', 'http.server',
        'xmlrpc', 'pydoc', 'doctest', 'PIL', 'numpy',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='openfda',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=True,
    icon=None,
)
