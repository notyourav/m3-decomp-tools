import codecs

font_offset = 0xCE39F8

binary = []

map = {}

with open("baserom.gba", "rb") as rom:
    binary = rom.read()

for i in range(7332):
    byte1 = binary[font_offset + i * 22]
    byte2 = binary[font_offset + i * 22 + 1]
    result = codecs.decode(binary[font_offset + i * 22:font_offset + i * 22 + 2], "shiftjis", "ignore")
    map[i] = result
    # print(result, end="")

print("const char* jp_charmap[] = {")
for (key, value) in map.items():
    print(f'"{value}",')
print("};")
