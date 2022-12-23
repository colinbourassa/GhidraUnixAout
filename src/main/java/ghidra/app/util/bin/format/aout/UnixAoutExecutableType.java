package ghidra.app.util.bin.format.aout;

public class UnixAoutExecutableType {
	public final static short OMAGIC = 0x107; // 0407: object file or impure executable
	public final static short NMAGIC = 0x108; // 0410: pure executable
	public final static short ZMAGIC = 0x10B; // 0413: demand-paged executable
	public final static short QMAGIC = 0x0CC; // 0314: demand-paged exe w/ header in .text
	public final static short CMAGIC = 0x111; // 0421: core file
}
