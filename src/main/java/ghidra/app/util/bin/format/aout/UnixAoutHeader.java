package ghidra.app.util.bin.format.aout;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class UnixAoutHeader {

	enum ExecutableType {
		OMAGIC, NMAGIC, ZMAGIC, QMAGIC, CMAGIC, UNKNOWN
	}

	private long binarySize;
	private ExecutableType exeType;
	private boolean machineTypeValid;
	private String languageSpec;
	private String compilerSpec = "default";
	private long pageSize;

	private long a_magic;
	private long a_text;
	private long a_data;
	private long a_bss;
	private long a_syms;
	private long a_entry;
	private long a_trsize;
	private long a_drsize;

	private long txtOffset;
	private long datOffset;
	private long txtRelOffset;
	private long datRelOffset;
	private long symOffset;
	private long strOffset;

	private long txtAddr;
	private long txtEndAddr;
	private long datAddr;
	private long bssAddr;

	// The Linux implementation of a.out support might have a different header
	// size, but it looks as though that might be caused by a strange mix of
	// 32- and 64-bit integers being padded out in the struct. The intended
	// size seems to be eight 32-bit words (32 bytes total.)
	private static final int sizeOfExecHeader = 32;
	private static final int _N_HDROFF = (1024 - sizeOfExecHeader);

	// TODO: These values are not required to compute load addresses for all
	// executable types, and they can be different depending on the OS/arch.
	// There are probably only specific exeType/OS/arch combinations for which
	// accurate values are important.
	private static final int SEGMENT_SIZE = 1024;

	/**
	 * Interprets binary data as an exec header from a UNIX-style a.out executable,
	 * and validates the contained fields.
	 *
	 * @param provider       Source of header binary data
	 * @param isLittleEndian Flag indicating whether to interpret the data as
	 *                       little-endian.
	 * @throws IOException
	 */
	public UnixAoutHeader(ByteProvider provider, boolean isLittleEndian) throws IOException {
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);

		// TODO: this first word might contain some additional flags (in the
		// high byte) that we're not yet checking. The BSD implementation of
		// the format mentions EX_DYNAMIC and EX_PIC, while the SunOS version
		// apparently has a toolset version number indicator. The former may
		// be important, while the latter is probably not.
		a_magic = reader.readNextUnsignedInt();
		a_text = reader.readNextUnsignedInt();
		a_data = reader.readNextUnsignedInt();
		a_bss = reader.readNextUnsignedInt();
		a_syms = reader.readNextUnsignedInt();
		a_entry = reader.readNextUnsignedInt();
		a_trsize = reader.readNextUnsignedInt();
		a_drsize = reader.readNextUnsignedInt();
		binarySize = reader.length();

		checkExecutableType();
		checkMachineTypeValidity();

		if (exeType == ExecutableType.ZMAGIC) {
			txtOffset = _N_HDROFF + sizeOfExecHeader;
		} else if (exeType == ExecutableType.QMAGIC) {
			txtOffset = 0;
		} else {
			txtOffset = sizeOfExecHeader;
		}

		datOffset = txtOffset + a_text;
		txtRelOffset = datOffset + a_data;
		datRelOffset = txtRelOffset + a_trsize;
		symOffset = datRelOffset + a_drsize;
		strOffset = symOffset + a_syms;

		txtAddr = (exeType == ExecutableType.QMAGIC) ? pageSize : 0;
		txtEndAddr = txtAddr + a_text;
		datAddr = (exeType == ExecutableType.OMAGIC) ? txtEndAddr : segmentRound(txtEndAddr);
		bssAddr = datAddr + a_data;
	}

	/**
	 * Returns the processor/language specified by this header.
	 */
	public String getLanguageSpec() {
		return languageSpec;
	}

	/**
	 * Returns the compiler used by this executable. This is left as 'default' for
	 * all machine types other than i386, where it is assumed to be gcc.
	 */
	public String getCompilerSpec() {
		return compilerSpec;
	}
	
	/**
	 * Returns the enumerated type of executable contained in this A.out file.
	 */
	public ExecutableType getExecutableType() {
		return exeType;
	}

	/**
	 * Returns an indication of whether this header's fields are all valid; this
	 * includes the machine type, executable type, and section offsets.
	 */
	public boolean isValid() {
		return isMachineTypeValid() &&
			   (exeType != ExecutableType.UNKNOWN) &&
			   areOffsetsValid();
	}

	public long getTextSize() {
		return a_text;
	}

	public long getDataSize() {
		return a_data;
	}

	public long getBssSize() {
		return a_bss;
	}

	public long getSymSize() {
		return a_syms;
	}

	public long getEntryPoint() {
		return a_entry;
	}

	public long getTextRelocSize() {
		return a_trsize;
	}

	public long getDataRelocSize() {
		return a_drsize;
	}

	public long getTextOffset() {
		return txtOffset;
	}

	public long getDataOffset() {
		return datOffset;
	}

	public long getTextRelocOffset() {
		return txtRelOffset;
	}

	public long getDataRelocOffset() {
		return datRelOffset;
	}

	public long getSymOffset() {
		return symOffset;
	}

	public long getStrOffset() {
		return strOffset;
	}

	public long getTextAddr() {
		return txtAddr;
	}

	public long getDataAddr() {
		return datAddr;
	}

	public long getBssAddr() {
		return bssAddr;
	}

	/**
	 * Checks the magic word in the header for a known machine type ID, and sets the
	 * languageSpec string accordingly.
	 */
	private void checkMachineTypeValidity() {

		machineTypeValid = true;
		pageSize = 4096; // TODO: find the best default for this
		final short machtype = (short) ((a_magic >> 16) & 0xFF);

		// TODO: Does Ghidra have language support that corresponds
		// to the OLDSUN2, MIPS1, and MIPS2 machine types?
		// (For reference, the Linux a.out.h describes MIPS1 as
		// R3000/R3000 and MIPS2 as R6000/R4000.)

		switch (machtype) {
		case UnixAoutMachineType.M_OLDSUN2:
			languageSpec = "UNKNOWN:BE:32:default";
			break;
		case UnixAoutMachineType.M_68010:
			languageSpec = "68000:BE:32:default";
			break;
		case UnixAoutMachineType.M_68020:
			languageSpec = "68000:BE:32:MC68020";
			break;
		case UnixAoutMachineType.M_SPARC:
			languageSpec = "sparc:BE:32:default";
			pageSize = 8192;
			break;
		case UnixAoutMachineType.M_R3000:
			languageSpec = "MIPS:LE:32:default";
			break;
		case UnixAoutMachineType.M_386:
			languageSpec = "x86:LE:32:default";
			compilerSpec = "gcc";
			break;
		case UnixAoutMachineType.M_MIPS1:
			languageSpec = "UNKNOWN:BE:32:default";
			break;
		case UnixAoutMachineType.M_MIPS2:
			languageSpec = "UNKNOWN:BE:32:default";
			break;
		default:
			machineTypeValid = false;
		}
	}

	/**
	 * Returns a flag indicating whether the header contains a known machine type
	 * ID.
	 */
	private boolean isMachineTypeValid() {
		return machineTypeValid;
	}

	/**
	 * Returns a flag indicating whether this header contains a representation of a
	 * valid executable type.
	 */
	private void checkExecutableType() {
		final short exetypeMagic = (short) (a_magic & 0xFFFF);

		switch (exetypeMagic) {
		case 0x111: // 0421: core file
			exeType = ExecutableType.CMAGIC;
			break;
		case 0x108: // 0410: pure executable
			exeType = ExecutableType.NMAGIC;
			break;
		case 0x107: // 0407: object file or impure executable
			exeType = ExecutableType.OMAGIC;
			break;
		case 0x0CC: // 0314: demand-paged exe w/ header in .text
			exeType = ExecutableType.QMAGIC;
			break;
		case 0x10B: // 0413: demand-paged executable
			exeType = ExecutableType.ZMAGIC;
			break;
		default:
			exeType = ExecutableType.UNKNOWN;
		}
	}

	/**
	 * Returns a flag indicating whether all the file offsets in the header fall
	 * within the size of the file.
	 */
	private boolean areOffsetsValid() {
		boolean status = (txtOffset < binarySize) &&
				         (datOffset < binarySize) &&
				         (txtRelOffset < binarySize) &&
				         (datRelOffset < binarySize) &&
				         (symOffset < binarySize) &&
				         (strOffset < binarySize);
		return status;
	}

	private long segmentRound(long addr) {
		final long mask = SEGMENT_SIZE - 1;
		long rounded = ((addr + mask) & ~mask);
		return rounded;
	}
}
