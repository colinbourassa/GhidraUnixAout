package ghidra.app.util.bin.format.aout;

/**
 * Represents the content of a single entry in the relocation table format
 * used by the UNIX a.out executable.
 */
public class UnixAoutRelocationTableEntry {
	public long address;
	public long symbolNum;
	public boolean pcRelativeAddressing;
	public byte pointerLength;
	public boolean extern;
	public boolean baseRelative;
	public boolean jmpTable;
	public boolean relative;
	public boolean copy;
	
	/**
	 * 
	 * @param address First of the two words in the table entry (a 32-bit address)
	 * @param flags Second of the two words in the table entry (containing several bitfields)
	 */
	public UnixAoutRelocationTableEntry(long address, long flags) {
		this.address = (0xFFFFFFFF & address);
		symbolNum = ((flags & 0xFFFFFF00) >> 8);
		pcRelativeAddressing = ((flags & 0x80) != 0);
		pointerLength = (byte)(1 << ((flags & 0x60) >> 5));
		extern = ((flags & 0x10) != 0);
		baseRelative = ((flags & 0x8) != 0);
		jmpTable = ((flags & 0x4) != 0);
		relative = ((flags & 0x2) != 0);
		copy = ((flags & 0x1) != 0);
	}
}
