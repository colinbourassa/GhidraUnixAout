package ghidra.app.util.bin.format.aout;

public class UnixAoutMachineType {
	
	// These values come from a combination of sources, including NetBSD's aout_mids.h
	// and the GNU BFD Library's libaout.h.
	//
	// Note that a few of the HP values exceed a full eight-bit count.
	// The GNU Binary File Descriptor (bfd) library seems to take the 8-bit modulus of
	// these values rather than let them interfere with the flags in the high byte of a_info. 
	// See: https://sourceware.org/git/?p=binutils-gdb.git;a=blob_plain;f=bfd/libaout.h;hb=HEAD
	
	public final static short M_OLDSUN2        = 0x00;
	public final static short M_68010          = 0x01;
	public final static short M_68020          = 0x02;
	public final static short M_SPARC          = 0x03;
	public final static short M_R3000          = 0x04;
	public final static short M_NS32032        = 0x40;
	public final static short M_NS32532        = 0x45;
	public final static short M_386            = 0x64;
	public final static short M_29K            = 0x65; // AMD 29000
	public final static short M_386_DYNIX      = 0x66; // i386-based Sequet machine running DYNIX	
	public final static short M_ARM            = 0x67;
	public final static short M_SPARCLET       = 0x83; // Sparclet = M_SPARC + 128
	public final static short M_386_NETBSD     = 0x86; // NetBSD/i386
	public final static short M_M68K_NETBSD    = 0x87; // NetBSD/m68k, 8K pages
	public final static short M_M68K4K_NETBSD  = 0x88; // NetBSD/m68k, 4K pages
	public final static short M_532_NETBSD     = 0x89; // NetBSD/ns32k
	public final static short M_SPARC_NETBSD   = 0x8a; // NetBSD/sparc
	public final static short M_PMAX_NETBSD    = 0x8b; // NetBSD/pmax (MIPS little-endian)
	public final static short M_VAX_NETBSD     = 0x8c; // NetBSD/VAX (1K pages?)
	public final static short M_ALPHA_NETBSD   = 0x8d; // NetBSD/Alpha
	public final static short M_MIPS           = 0x8e; // big-endian
	public final static short M_ARM6_NETBSD    = 0x8f; // NetBSD/arm32
	public final static short M_SH3            = 0x91;
	public final static short M_POWERPC64      = 0x94; // PowerPC 64
	public final static short M_POWERPC_NETBSD = 0x95; // NetBSD/PowerPC (big-endian)
	public final static short M_VAX4K_NETBSD   = 0x96; // NetBSD/VAX (4K pages)
	public final static short M_MIPS1          = 0x97; // MIPS R2000/R3000
	public final static short M_MIPS2          = 0x98; // MIPS R4000/R6000
	public final static short M_88K_OPENBSD    = 0x99; // OpenBSD/m88k
	public final static short M_HPPA_OPENBSD   = 0x9a; // OpenBSD/hppa (PA-RISC)
	public final static short M_SH5_64         = 0x9b; // SuperH 64-bit
	public final static short M_SPARC64_NETBSD = 0x9c; // NetBSD/sparc64
	public final static short M_X86_64_NETBSD  = 0x9d; // NetBSD/amd64
	public final static short M_SH5_32         = 0x9e; // SuperH 32-bit (ILP 32)
	public final static short M_IA64           = 0x9f; // Itanium
	public final static short M_HP200          = 0xc8; // HP200 (68010) BSD
	public final static short M_HP300          = (0x12c % 0x100); // HP300 (68020+68881) BSD
	public final static short M_HPUX800        = (0x20b % 0x100); // HP800
	public final static short M_HPUX           = (0x20C % 0x100); // HP200/300 HPUX (8-bit value: 12)
	public final static short M_CRIS           = 0xff; // Axis ETRAX CRIS
}
