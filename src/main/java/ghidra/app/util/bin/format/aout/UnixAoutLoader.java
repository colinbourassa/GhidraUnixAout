/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.aout;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loads the old UNIX a.out executable format. This style was also used by
 * UNIX-like systems such as BSD and VxWorks, as well as some early
 * distributions of Linux.
 */
public class UnixAoutLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {

		// Must match the name of the loader in the .opinion files.
		return "UNIX a.out executable";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Attempt to parse the header as both little- and big-endian.
		// It is likely that only one of these will produce sensible values.
		UnixAoutHeader hdrBE = new UnixAoutHeader(provider, false);
		UnixAoutHeader hdrLE = new UnixAoutHeader(provider, true);
		
		if (hdrBE.isValid()) {
			final String lang = hdrBE.getLanguageSpec();
			final String comp = hdrBE.getCompilerSpec();
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang, comp), true));
		}
		if (hdrLE.isValid()) {
			final String lang = hdrLE.getLanguageSpec();
			final String comp = hdrLE.getCompilerSpec();
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(lang, comp), false));			
		}
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		final boolean bigEndian = program.getLanguage().isBigEndian();
		UnixAoutHeader header = new UnixAoutHeader(provider, !bigEndian);
		Memory mem = program.getMemory();

		final long txtSize = header.getTextSize();
		final long datSize = header.getDataSize();
		final long bssSize = header.getBssSize();

		if (txtSize > 0) {
			Address txtAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getTextAddr());
			MemoryBlock txtBlock;
			try {
				txtBlock = program.getMemory().createInitializedBlock(".text", txtAddr, txtSize, (byte)0x00, monitor, false);
				txtBlock.setRead(true);
				txtBlock.setWrite(false);
				txtBlock.setExecute(true);
				byte txtBytes[] = provider.readBytes(header.getTextOffset(), txtSize);
				mem.setBytes(txtAddr, txtBytes);

			} catch (MemoryAccessException | LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
				e.printStackTrace();
			}
		}

		if (datSize > 0) {
			Address datAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getDataAddr());
			MemoryBlock datBlock;
			try {
				datBlock = program.getMemory().createInitializedBlock(".data", datAddr, datSize, (byte)0x00, monitor, false);
				datBlock.setRead(true);
				datBlock.setWrite(true);
				datBlock.setExecute(false);
				byte datBytes[] = provider.readBytes(header.getDataOffset(), datSize);
				mem.setBytes(datAddr, datBytes);

			} catch (MemoryAccessException | LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
				e.printStackTrace();
			}			
		}

		if (bssSize > 0) {
			try {
				api.createMemoryBlock(".bss", api.toAddr(header.getBssAddr()), null, bssSize, false);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		BinaryReader reader = new BinaryReader(provider, !bigEndian);

		Vector<UnixAoutSymbolTableEntry> symtab =
			getSymbolTable(reader, header.getSymOffset(), header.getSymSize(), header.getStrOffset());

		Vector<UnixAoutRelocationTableEntry> txtRelocTab =
			getRelocationTable(reader, header.getTextRelocOffset(), header.getTextRelocSize());

		Vector<UnixAoutRelocationTableEntry> datRelocTab =
			getRelocationTable(reader, header.getDataRelocOffset(), header.getDataRelocSize());
		
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}

	/**
	 * Reads a single relocation table for either text or data relocations, depending
	 * on the offset/length provided.
	 * @param reader Source of file data
	 * @param offset File byte offset to the start of the relocation table
	 * @param len Length of the relocation table in bytes
	 * @return Vector of relocation table entries
	 */
	private Vector<UnixAoutRelocationTableEntry> getRelocationTable(BinaryReader reader, long offset, long len) {
		Vector<UnixAoutRelocationTableEntry> relocTable = new Vector<UnixAoutRelocationTableEntry>();
		reader.setPointerIndex(offset);

		try {
			while (reader.getPointerIndex() < (offset + len)) {
				long address = reader.readNextUnsignedInt();
				long flags = reader.readNextUnsignedInt();
				relocTable.add(new UnixAoutRelocationTableEntry(address, flags));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return relocTable;
	}

	/**
	 * Reads all the symbol table entries from the file, returning their representation.
	 * @param reader Source of file data
	 * @param offset File byte offset to the start of the symbol table
	 * @param len Length of the symbol table in bytes
	 * @param strTabBaseOffset File byte offset to the start of the string table (containing symbol names)
	 * @return Vector of symbol table entries
	 */
	private Vector<UnixAoutSymbolTableEntry> getSymbolTable(BinaryReader reader, long offset, long len, long strTabBaseOffset) {
		Vector<UnixAoutSymbolTableEntry> symtab = new Vector<UnixAoutSymbolTableEntry>();
		reader.setPointerIndex(offset);

		try {
			// read each symbol table entry
			while (reader.getPointerIndex() < (offset + len)) {
				long strOffset = reader.readNextUnsignedInt();
				byte typeByte = reader.readNextByte();
				byte otherByte = reader.readNextByte();
				short desc = reader.readNextShort();
				long value = reader.readNextUnsignedInt();
				symtab.add(new UnixAoutSymbolTableEntry(strOffset, typeByte, otherByte, desc, value));
			}

			// lookup and set each string table symbol name
			for (Integer i = 0; i < symtab.size(); i++) {
				String symstr = reader.readAsciiString(strTabBaseOffset + symtab.get(i).nameStringOffset);
				symtab.get(i).name = symstr;
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

		return symtab;
	}
}
