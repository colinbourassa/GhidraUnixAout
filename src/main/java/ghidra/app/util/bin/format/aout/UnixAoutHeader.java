package ghidra.app.util.bin.format.aout;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class UnixAoutHeader {
	private long binarySize;
	private boolean machineTypeValid;
	private String languageSpec;
	private String compilerSpec = "default";
	
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
	private static final int sizeOfExecHeader = 32;
	private static final int _N_HDROFF = (1024 - sizeOfExecHeader);
	
	UnixAoutHeader(ByteProvider provider, boolean isLittleEndian) throws IOException {
		BinaryReader reader = new BinaryReader(provider, isLittleEndian);
		
		a_magic  = reader.readNextUnsignedInt();
		a_text   = reader.readNextUnsignedInt();
		a_data   = reader.readNextUnsignedInt();
		a_bss    = reader.readNextUnsignedInt();
		a_syms   = reader.readNextUnsignedInt();
		a_entry  = reader.readNextUnsignedInt();
		a_trsize = reader.readNextUnsignedInt();
		a_drsize = reader.readNextUnsignedInt();
		binarySize = reader.length();
		
		final short exetype = (short)(a_magic & 0xFFFF);
		
		txtOffset = 0;
		if (exetype == UnixAoutExecutableType.ZMAGIC) {
			txtOffset = _N_HDROFF + sizeOfExecHeader;
		} else if (exetype != UnixAoutExecutableType.QMAGIC) {
			txtOffset = sizeOfExecHeader;
		}
		
		datOffset = txtOffset + a_text;
		txtRelOffset = datOffset + a_data;
		datRelOffset = txtRelOffset + a_trsize;
		symOffset = datRelOffset + a_drsize;
		strOffset = symOffset + a_syms;
		
		checkMachineTypeValidity();
	}
	
	public String getLanguageSpec() {
		return languageSpec;
	}
	
	public boolean isValid() {
		return isMachineTypeValid() &&
			   isExecutableTypeValid() &&
			   areOffsetsValid();
	}
	
	private void checkMachineTypeValidity() {
		
		machineTypeValid = true;
		final short machtype = (short)((a_magic >> 16) & 0xFF);

		// TODO: Does Ghidra have language support that corresponds
		// to the OLDSUN2, MIPS1, and MIPS2 machine types?
		// For reference, the Linux a.out.h describes MIPS1 as
		// R3000/R3000 and MIPS2 as R6000/R4000

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
			languageSpec = "Sparc:BE:32:default";
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
	
	private boolean isMachineTypeValid() {
		return machineTypeValid;
	}
	
	/**
	 * Returns a flag indicating whether this header contains
	 * a representation of a valid executable type.
	 */
	private boolean isExecutableTypeValid() {
		boolean status = false;
		final short exetype = (short)(a_magic & 0xFFFF);
		switch (exetype) {
		case UnixAoutExecutableType.CMAGIC:
		case UnixAoutExecutableType.NMAGIC:
		case UnixAoutExecutableType.OMAGIC:
		case UnixAoutExecutableType.QMAGIC:
		case UnixAoutExecutableType.ZMAGIC:
			status = true;
		}
		return status;
	}
	
	private boolean areOffsetsValid() {
		boolean status = (txtOffset < binarySize)    &&
      		             (datOffset < binarySize)    &&
				         (txtRelOffset < binarySize) &&
				         (datRelOffset < binarySize) &&
				         (symOffset < binarySize)    &&
				         (strOffset < binarySize);
		return status;
	}

	public String getCompilerSpec() {
		return compilerSpec;
	}
}
