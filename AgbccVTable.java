//Create a virtual table struct for GCC2 virtual tables
//@author 
//@category C++
//@keybinding 
//@menupath 
//@toolbar function.png

import ghidra.app.plugin.core.instructionsearch.InstructionSearchApi;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.program.model.util.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import java.util.*;

/**
 * GCC 2 has a special ABI and vtable format. Instead of using thunk functions to adjust thisptr,
 * an offset is stored directly inside the vtable, between each function pointer.
 * 
 * In order to use this plugin, put the cursor on the start of a vtable.
 **/
public class AgbccVTable extends GhidraScript {
    int entries = 0;
    static final int MAX_ENTRIES = 500;

    public void run() throws Exception {
        Listing l = currentProgram.getListing();
        // jump past initial offset bytes
        Address cur = currentLocation.getAddress().add(4);

        List<Address> addresses = new ArrayList<Address>();

        for (Data d = l.getDataAt(cur); d.isPointer(); entries++) {
            Address p = (Address)d.getValue();
            addresses.add(p);
            println("address is " + p);

            if (l.getDataAt(cur.add(4)).getReferenceIteratorTo().hasNext()) {
                break; // new vtable detected
            }
            if (entries > MAX_ENTRIES) {
                printerr("too many entries (overrun vtable?)");
                break;
            }

            // advance to next entry
            cur = cur.add(8);
            d = l.getDataAt(cur);
        }
        if (addresses.size() == 0) {
            printerr("no vtable found");
            return;
        }
        println("length is " + addresses.size());

        ProgramBasedDataTypeManager man = currentProgram.getDataTypeManager();
        DataTypeSelectionDialog dg = new DataTypeSelectionDialog(state.getTool(), man, -1, AllowedDataTypes.ALL);
        state.getTool().showDialog(dg);

        DataType base = dg.getUserChosenDataType();
        if (base == null) {
            println("No data type chosen");
            return;
        }
        if (base instanceof PointerDataType) {
            base = ((PointerDataType)base).getDataType();
        }

        StructureDataType dt = new StructureDataType(base.getName() + "_vptr", 0, man);
        int n = 0;
        for (Address a : addresses) {
            Function f = l.getFunctionAt(a.subtractWrap(1)); // for thumb
            dt.add(new ShortDataType(), "voff" + n, "");
            dt.add(new ShortDataType(), "rsrv" + n, "");
            if (f != null) {
                dt.add(new PointerDataType(), f.getName(), "");
            } else {
                dt.add(new PointerDataType(), "pure_" + n, "");
            }
            n++;
        }

        Category vt_category = man.createCategory(new CategoryPath("/vtables"));
        vt_category.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
    }
}
