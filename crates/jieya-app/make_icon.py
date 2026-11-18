"""生成 32x32 的 icon.ico（Tauri 的 Windows 资源需要）。"""
import struct

SIZE = 32
pixels = []
for y in range(SIZE):
    row = []
    for x in range(SIZE):
        # 圆角方块 + 向下的"解压箭头"
        inside = 3 <= x <= 28 and 3 <= y <= 28
        corner = (x in (3, 4) and y in (3, 4)) or (x in (27, 28) and y in (3, 4)) \
            or (x in (3, 4) and y in (27, 28)) or (x in (27, 28) and y in (27, 28))
        if not inside or corner:
            row.append((0, 0, 0, 0))
        else:
            # 背景渐变：深蓝 -> 青
            t = (x + y) / (2 * SIZE)
            r = int(18 + 20 * t)
            g = int(60 + 120 * t)
            b = int(110 + 90 * t)
            # 箭头主体
            arrow = (16 <= y <= 22 and 14 <= x <= 18) or \
                    (20 <= y <= 24 and abs(x - 16) <= (y - 19)) or \
                    (7 <= y <= 11 and 10 <= x <= 22)
            if arrow:
                r, g, b = 240, 246, 255
            row.append((b, g, r, 255))  # BMP 是 BGRA
        # 底部再加 1 行透明（BMP 的行序从下到上，最后统一翻转）
    pixels.append(row)

pixels.reverse()
# BITMAPINFOHEADER（高度写两倍：XOR + AND 掩码）
header = struct.pack("<IiiHHIIiiII", 40, SIZE, SIZE * 2, 1, 32, 0, 0, 0, 0, 0, 0)
data = bytearray(header)
for row in pixels:
    for px in row:
        data += bytes(px)
# AND 掩码：32x32 单色，每行 4 字节对齐
mask = b"\x00" * (SIZE * 4)
data += mask

ico = struct.pack("<HHH", 0, 1, 1)
ico += struct.pack("<BBBBHHII", SIZE, SIZE, 0, 0, 1, 32, len(data), 6 + 16)
ico += data

with open("icons/icon.ico", "wb") as f:
    f.write(ico)
print("icon.ico written:", 6 + 16 + len(data), "bytes")
