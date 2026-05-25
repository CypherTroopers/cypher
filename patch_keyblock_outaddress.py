from pathlib import Path
import sys

path = Path("core/types/keyblock.go")

old = '''func (b *KeyBlock) OutAddress(flag int) string {
\tif flag == 1 && b.outAddress != "" && b.outAddress[0] == '*' {
\t\treturn b.outAddress[1:]
\t}
\treturn b.outAddress
}
'''

new = '''func (b *KeyBlock) OutAddress(flag int) string {
\tif flag == 1 {
\t\tif b.outAddress == "" {
\t\t\treturn b.leaderAddress
\t\t}
\t\tif b.outAddress[0] == '*' {
\t\t\treturn b.outAddress[1:]
\t\t}
\t}
\treturn b.outAddress
}
'''

if not path.exists():
    print(f"[ERROR] file not found: {path}")
    sys.exit(1)

text = path.read_text()

if new in text:
    print("[OK] already patched")
    sys.exit(0)

if old not in text:
    print("[ERROR] target block not found")
    print("Current OutAddress function is different from expected.")
    sys.exit(1)

backup = path.with_suffix(path.suffix + ".bak")
backup.write_text(text)

text = text.replace(old, new, 1)
path.write_text(text)

print(f"[OK] patched: {path}")
print(f"[OK] backup created: {backup}")
