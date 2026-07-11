#!/usr/bin/env python3
"""Windows/Admin/WinDivert capability probe.

This does not validate packet interception; it only reports whether Level 1 tests are possible.
"""
from __future__ import annotations
import ctypes, json, os, platform, shutil, subprocess
from pathlib import Path


def is_admin():
    if platform.system() != 'Windows': return False
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False

def cmd(args):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=10)
        return {'returncode':p.returncode,'stdout':p.stdout[-2000:],'stderr':p.stderr[-2000:]}
    except Exception as e:
        return {'error':repr(e)}

def main():
    is_win=platform.system()=='Windows'
    out={'os':platform.platform(),'python':platform.python_version(),'is_windows':is_win,'is_admin':is_admin(),'tools':{'cargo':shutil.which('cargo'),'rustc':shutil.which('rustc'),'netsh':shutil.which('netsh'),'sc':shutil.which('sc.exe')},'windivert':{'driver_query':None,'dll_candidates':[]},'level':0,'unsupported_reasons':[]}
    if not is_win: out['unsupported_reasons'].append('requires_windows')
    if is_win and not out['is_admin']: out['unsupported_reasons'].append('requires_admin')
    if is_win:
        out['windivert']['driver_query']=cmd(['sc.exe','query','WinDivert']) if shutil.which('sc.exe') else {'error':'sc.exe not found'}
        for base in [Path.cwd(), Path.cwd()/'src', Path.cwd()/'src/vendor/windivert']:
            for name in ['WinDivert.dll','WinDivert64.sys','WinDivert32.sys']:
                p=base/name
                if p.exists(): out['windivert']['dll_candidates'].append(str(p))
    if is_win and out['is_admin']: out['level']=1
    print(json.dumps(out,indent=2,ensure_ascii=False))
if __name__=='__main__': main()
