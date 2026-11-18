"""造「非 UTF-8 文件名」的 ZIP 样例（不置 flag bit 11）。

Python 的 zipfile 对非 ASCII 名会自动置 UTF-8 标志，做不出我们要的病态包，
所以这里直接按 ZIP 结构手写：本地头 + 数据 + 中央目录 + EOCD。

用法: python make_legacy_zip.py <编码> <输出.zip> <条目...>
    条目里用 / 分隔目录；只支持 store（不压缩）。
"""
import struct
import sys
import time
import zlib
from pathlib import Path

def build(codec: str, out: Path, names: list[str]) -> None:
    now = time.localtime()[:6]
    dos_time = (now[3] << 11) | (now[4] << 5) | (now[5] // 2)
    dos_date = ((now[0] - 1980) << 9) | (now[1] << 5) | now[2]

    locals_: list[bytes] = []
    centrals: list[bytes] = []
    offset = 0
    for name in names:
        raw_name = name.encode(codec)
        is_dir = name.endswith("/")
        payload = b"fixture\n" if not is_dir else b""
        flags = 0  # 关键：不置 0x800
        version = 20
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        local = struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, version, flags, 0, dos_time, dos_date,
            crc, len(payload), len(payload), len(raw_name), 0,
        ) + raw_name + payload
        central = struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, version, version, flags, 0,
            dos_time, dos_date, crc, len(payload), len(payload), len(raw_name),
            0, 0, 0, 0, 0, offset,
        ) + raw_name
        locals_.append(local)
        centrals.append(central)
        offset += len(local)

    cd = b"".join(centrals)
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(centrals), len(centrals),
        len(cd), offset, 0,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"".join(locals_) + cd + eocd)

if __name__ == "__main__":
    codec, out, *names = sys.argv[1:]
    build(codec, Path(out), names)
    print(f"wrote {out} ({codec})")
