package ghidra.app.util.bin.format.aout;

public class UnixAoutMachineType {
	public final static short M_OLDSUN2 = 0;
	public final static short M_68010 = 1;
	public final static short M_68020 = 2;
	public final static short M_SPARC = 3;
	public final static short M_R3000 = 4;
	
	// Linux extensions to a.out machine type list
	public final static short M_386 = 100;
	public final static short M_MIPS1 = 151;
	public final static short M_MIPS2 = 152;
}
