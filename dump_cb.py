import sys

with open("baserom.gba", "rb") as rom:
    offset = sys.argv[1]
    rom.seek(int(offset, 16))
    # read little endian
    print("\n\n\t.4byte 0x" + hex(int.from_bytes(rom.read(4), byteorder="little")).upper()[2:])
    print("\t.4byte sub_" + hex(int.from_bytes(rom.read(4), byteorder="little") - 1).upper()[2:].zfill(8) + "+1")
    print("\n")
