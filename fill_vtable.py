map_file = []

def find_repl(offset):
    global map_file
    for map_line in map_file:
        if map_line.find(offset) != -1:
            if (map_line.find(".o") != -1):
                continue
            return map_line
    print("error could not find symbol for offset %s" % offset)
    exit()

with open("./mother3.map", "r") as map:
    map_file = map.readlines()


with open("./data/vtables_new.s", "w") as vtables_new:
    with open("./data/vtables.s", "r") as vtables:
        for line in vtables:
            if line.find("sub_") != -1:
                offset = line.split("sub_")[1].strip().lower()
                map_line = find_repl(offset)
                function_name = map_line.split(" ")[-1].strip()
                new_line = line.split("sub_")[0] + function_name
                print(new_line, function_name)
                vtables_new.write(new_line + "\n")
            else:
                vtables_new.write(line)
