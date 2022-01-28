import os

vt_list = []

def repl_vt(file):
    global vt_list

    newfile = ""

    with open(file, "r") as f:
        for line in f:
            if line.find("0x") != -1:
                offset = line.split("0x")[1].upper().strip()
                #print(offset)
                for vtl in vt_list:
                    # if vtl.find("vt_") != -1:
                    #     vt_sym = vtl.split(":")[0]
                        #print(vt_sym.split("vt_0")[1])
                    if vtl.split("vt_")[1] == offset:
                        #print(offset + "->" + vt_sym)
                        line = line.replace("0x" + offset, vtl)
                        print(line.strip())
                        break
            newfile += line

    with open(file, "w") as f:
        f.write(newfile)

def do_recurse(dir):
    print(dir)
    iter = os.walk(dir)
    for dirpath, dirnames, filelist in iter:
        for subdir in dirnames:
            do_recurse(dirpath + "/" + subdir)

        for file in filelist:
            print(dirpath + "/" + file)
            repl_vt(dirpath + "/" + file)

with open("./data/vtables.s") as vts:
    for line in vts:
        if line.find("vt_") != -1:
            vt_list.append(line.split(":")[0].strip())


do_recurse("./asm")
