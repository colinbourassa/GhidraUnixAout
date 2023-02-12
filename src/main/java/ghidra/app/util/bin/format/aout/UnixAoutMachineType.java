package ghidra.app.util.bin.format.aout;

public class UnixAoutMachineType {
	
	// These values come from a combination of sources, including:
	//
	// output_aout.h from vasm (http://sun.hasenbraten.de/vasm/)
	// https://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/sys/sys/aout_mids.h
	//
	// (TODO: double check that the values from the BSD aout_mids.h match up!)
	
	public final static short M_OLDSUN2 = 0;
	public final static short M_68010 = 1;
	public final static short M_68020 = 2;
	public final static short M_SPARC = 3;
	public final static short M_R3000 = 4;	
	public final static short M_386 = 100;
	public final static short M_I386 = 134;
	public final static short M_M68K = 135; // m68k BSD, 8K pages
	public final static short M_M68K4K = 136; // m68k BSD, 4K pages
	public final static short M_NS32532 = 137;
	public final static short M_SPARCBSD = 138;
	public final static short M_PMAX = 139;
	public final static short M_VAX1K = 140; // 1K pages
	public final static short M_ALPHA = 141; // BSD
	public final static short M_MIPS = 142; // big-endian
	public final static short M_ARM6 = 143;
	public final static short M_SH3 = 145;
	public final static short M_POWERPC = 149; // big-endian
	public final static short M_VAX = 150;
	public final static short M_MIPS1 = 151; // or is this SPARC64?
	public final static short M_MIPS2 = 152;
	public final static short M_HP200 = 200; // HP200 / 68010 BSD
	public final static short M_HP300 = 300; // HP300 (68020+68881) BSD binary
	public final static short M_HPUX800 = 523; // HP800
	public final static short M_HPUX = 524; // HP200/300
}
