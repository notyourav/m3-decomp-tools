import sys

rom: bytearray

functions = []

with open("baserom.gba", "rb") as f:
    rom = f.read()

with open("mother3.map", "r") as map:
    functions = map.readlines()

with open (sys.argv[1], "r") as file:
    lastline = ""
    for line in file:
        if line.find(".incbin") != -1:
            if line.find("0x00120E94") != -1 or line.find("0x00D0B010") != -1 or line.find("0D3B4E0") != -1 or line.find("0x00CE39F8") != -1 or line.find("0x00D34F44") != -1 or line.find("0x0D3B4E0") != -1 or line.find("1132B58") != -1 or line.find("014383E4") != -1 or line.find("194BC30") != -1 or line.find("1A012B8") != -1 or line.find("1A36AA0") != -1 or line.find("1A442A4") != -1:
                continue

            begin = int(line.split(",")[1].strip(), 16)
            size = int(line.split(",")[2].strip(), 16)

            for i in range(size >> 2):
                # read integer from byte array at position begin + i * 4
                intval = int.from_bytes(rom[begin + i * 4:begin + i * 4 + 4], byteorder='little')
                if intval >= 0x08000000 and intval <= 0x09000000:
                    for line in functions:
                        if line.find(hex(intval)[2:]) != -1:
                            if line.find("0808") != -1 or line.find("080000") != -1:
                                break
                            print(lastline.strip() + ":" + hex(0x08000000 + begin + i * 4), line.strip())
                            break
        lastline = line
