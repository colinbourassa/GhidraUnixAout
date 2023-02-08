package ghidra.app.util.bin.format.aout;

/**
 * Represents the content of a single entry in the symbol table format used by
 * the UNIX a.out executable.
 */
public class UnixAoutSymbolTableEntry {
	
	// TODO: there may be additional symbol types that are defined and that
	// need special handling; these would currently get marked as UNKNOWN
	enum SymbolType { N_UNDF, N_ABS, N_TEXT, N_DATA, N_BSS, N_FN, N_EXT, UNKNOWN }

	public long nameStringOffset;
	public String name;
	public SymbolType type;
	public byte otherByte;
	public short desc;
	public long value;
	public boolean isExt;
	
	public UnixAoutSymbolTableEntry(long nameStringOffset, byte typeByte, byte otherByte, short desc, long value) {
		this.nameStringOffset = nameStringOffset;
		this.otherByte = otherByte;
		this.desc = desc;
		this.value = value;
		this.isExt = (typeByte & 1) == 1;
		
		switch (typeByte & 0xfe) {
		case 0:
			type = SymbolType.N_UNDF;
			break;
		case 1:
			type = SymbolType.N_EXT;
			break;
		case 2:
			type = SymbolType.N_ABS;
			break;
		case 4:
			type = SymbolType.N_TEXT;
			break;
		case 6:
			type = SymbolType.N_DATA;
			break;
		case 8:
			type = SymbolType.N_BSS;
			break;
		default:
			type = SymbolType.N_UNDF;
		}
	}

}