//Dump virtual tables
//@author 
//@category Decomp
//@keybinding 
//@menupath 
//@toolbar table.png

import java.io.File;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import java.util.SortedMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class VTDumper extends GhidraScript {
	class VTEntry {
		BigInteger this_off;
		Address func;
	}

	static final boolean THIS_OFFSET_ENABLED = true;
	
	LinkedHashMap<Address, VTEntry[]> tables = new LinkedHashMap<Address, VTEntry[]>();
	
	Data tryCreateData(Address addr, DataType dt) {
		Data d = null;
		try {
			d = currentProgram.getListing().createData(addr, dt);
		} catch (CodeUnitInsertionException e) {
			printerr("Overlapping data found at " + addr.toString());
		} catch (DataTypeConflictException e) {
			e.printStackTrace();
		}
		return d;
	}
	
	private void put_vtable(Address start_addr, ArrayList<VTEntry> table) {
		VTEntry[] entries = new VTEntry[table.size()];
		tables.put(start_addr, table.toArray(entries));
	}
	
    public void run() throws Exception {
    	Address addr = askAddress("Virtual Tables Location", "Enter the starting address:");
    	
    	int ptr_size = currentProgram.getDefaultPointerSize();    	
    	Listing listing = currentProgram.getListing();

    	ArrayList<VTEntry> current_table = new ArrayList<VTEntry>();
    	Address vt_start_addr = addr;
    	Data d = null;
    	while ((d = listing.getDataAt(addr)) != null) {
    		ReferenceIterator refs = d.getReferenceIteratorTo();
    		if (refs.hasNext()) {
    			// xref found, lets assume this is the beginning of a new vtable
    			d.setComment(CodeUnit.PLATE_COMMENT, "Start of VTable");
    			if (current_table.size() != 0) {
    				put_vtable(vt_start_addr, current_table);
    				current_table.clear();
    			}
    			vt_start_addr = addr;    			
    		}
    		
    		VTEntry current_entry = new VTEntry();
    		
    		// this offset is first
    		if (THIS_OFFSET_ENABLED) {
    			if (!d.isDefined()) {
        			d = tryCreateData(addr, new IntegerDataType());
    			} else if (!(d.getBaseDataType() instanceof IntegerDataType)) {
    				if (d.getBaseDataType() instanceof Pointer) {
    					// in case the entire vtable was defined as pointers by accident
    					clearListing(addr);
    					d = tryCreateData(addr, new IntegerDataType());
    				} else {
        				println("data defined at " + addr.toString() + ", stopping.");
        				put_vtable(vt_start_addr, current_table);
        				break;
    				}
    			}
    			current_entry.this_off = d.getBigInteger(0, ptr_size, false);
    			
				if (!current_entry.this_off.and(BigInteger.valueOf(0xFFFF0000)).equals(BigInteger.ZERO)) {
					println("invalid this offset at " + addr.toString() + ", stopping.");
					put_vtable(vt_start_addr, current_table);
					break;
				}

    			// move fwd
    			addr = addr.addNoWrap(ptr_size);
    			d = listing.getDataAt(addr);
    			assert d != null;
    		}

    		if (!d.isDefined()) {
    			d = tryCreateData(addr, new PointerDataType());
    		} else if (!(d.getBaseDataType() instanceof Pointer)) {
    			println("data defined at " + addr.toString() + ", stopping.");
    			put_vtable(vt_start_addr, current_table);
    			break;
    		}
			current_entry.func = PointerDataType.getAddressValue(d, ptr_size, addr.getAddressSpace());

    		current_table.add(current_entry);
    		addr = addr.addNoWrap(ptr_size);
    	}
    	
    	println(Integer.toString(tables.size()) + " virtual tables found.");
    	File dumpfile = askFile("Destination", "Select dump output file");
    	if (!dumpfile.createNewFile()) {
    		if (!askYesNo("Overwrite?", "Destination already exists. Overwrite?"))
    			return;
    	}
    	
    	PrintWriter pw = new PrintWriter(dumpfile);

    	for (Entry<Address, VTEntry[]> vt : tables.entrySet()) {
    		pw.format("vt_%08X::\n", vt.getKey().getOffset());
    		for (VTEntry ent : vt.getValue()) {
    			// each entry is technically { s16, s16, void* }
				pw.format("\t.2byte %d\n", ent.this_off.shortValue());
    			pw.format("\t.2byte 0\n");
    			
    			long func_off = ent.func.getOffset() /* thumb */ & ~1;
    			
    			if (func_off == 0) {
    				pw.format("\t.4byte 0\n");
    			} else {
    				pw.format("\t.4byte sub_%08X\n", func_off);    				
    			}
    		}
    		pw.println();
    	}
    	pw.close();
    }
}
