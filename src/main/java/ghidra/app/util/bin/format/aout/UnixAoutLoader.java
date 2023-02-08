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
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.aout.UnixAoutHeader.ExecutableType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
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
	public boolean supportsLoadIntoProgram() {
		return true;
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
		String filename = provider.getFile().getName();

		final long textSize = header.getTextSize();
		final long dataSize = header.getDataSize();
		final long bssSize = header.getBssSize();
		
		// TODO: confirm whether it is appropriate to load OMAGIC A.out files as overlays
		boolean isOverlay = (header.getExecutableType() == ExecutableType.OMAGIC);
		
		// TODO: loading an A.out into an existing program as an overlay seems to create it
		// in the 'OverlayAddressSpace'. Do we need to more explicitly create (or rename) the
		// address space so that any subsequent A.out files can have their content differentiated?

		MemoryBlock textBlock = null;
		MemoryBlock dataBlock = null;
		MemoryBlock bssBlock = null;
		AddressSpace textAddrSpace = null;
		AddressSpace dataAddrSpace = null;
		AddressSpace bssAddrSpace = null;

		if (textSize > 0) {
			Address textAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getTextAddr());
			try {
				InputStream textStream = provider.getInputStream(header.getTextOffset());
				textBlock = program.getMemory().createInitializedBlock(
					filename + ".text", textAddr, textStream, textSize, monitor, isOverlay);
				textAddrSpace = textBlock.getStart().getAddressSpace();
				textBlock.setRead(true);
				textBlock.setWrite(false);
				textBlock.setExecute(true);
			} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
				e.printStackTrace();
			}
		}
		
		if (dataSize > 0) {
			Address dataAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(header.getDataAddr());
			try {
				InputStream dataStream = provider.getInputStream(header.getDataOffset());
				dataBlock = program.getMemory().createInitializedBlock(
					filename + ".data", dataAddr, dataStream, dataSize, monitor, isOverlay);
				dataAddrSpace = dataBlock.getStart().getAddressSpace();
				dataBlock.setRead(true);
				dataBlock.setWrite(true);
				dataBlock.setExecute(false);
			} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException e) {
				e.printStackTrace();
			}
		}

		if (bssSize > 0) {
			try {
				bssBlock = api.createMemoryBlock(".bss",
					api.toAddr(header.getBssAddr()), null, bssSize, isOverlay);
				bssAddrSpace = bssBlock.getStart().getAddressSpace();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		BinaryReader reader = new BinaryReader(provider, !bigEndian);

		Vector<UnixAoutSymbolTableEntry> symTab =
			getSymbolTable(reader, header.getSymOffset(), header.getSymSize(), header.getStrOffset());

		Vector<UnixAoutRelocationTableEntry> textRelocTab =
			getRelocationTable(reader, header.getTextRelocOffset(), header.getTextRelocSize());

		Vector<UnixAoutRelocationTableEntry> dataRelocTab =
			getRelocationTable(reader, header.getDataRelocOffset(), header.getDataRelocSize());

		int defaultAddrSpaceId = program.getAddressFactory().getDefaultAddressSpace().getSpaceID();
		
		// look through the symbol table to find any that are local,
		// and apply the names at the appropriate locations
		for (Integer i = 0; i < symTab.size(); i++) {
			UnixAoutSymbolTableEntry symTabEntry = symTab.elementAt(i);
			try {
				if (symTabEntry.value != 0) {
					if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_TEXT) {
						// TODO: establish namespace earlier so that it may be used here
						api.createLabel(textAddrSpace.getAddress(symTabEntry.value), symTabEntry.name,
							null, true, SourceType.IMPORTED);
					} else if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_DATA) {
						api.createLabel(dataAddrSpace.getAddress(symTabEntry.value), symTabEntry.name,
							null, true, SourceType.IMPORTED);
					} else if (symTabEntry.type == UnixAoutSymbolTableEntry.SymbolType.N_BSS) {
						api.createLabel(bssAddrSpace.getAddress(symTabEntry.value), symTabEntry.name,
							null, true, SourceType.IMPORTED);
					}
				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		for (Integer i = 0; i < textRelocTab.size(); i++) {
			UnixAoutRelocationTableEntry relocationEntry = textRelocTab.elementAt(i);

			// TODO: There are other flags/fields in the relocation table entry that need to be
			// taken into account (e.g. size of the pointer, offset relativity)
			UnixAoutSymbolTableEntry sym = symTab.elementAt((int) relocationEntry.symbolNum);

			if (relocationEntry.extern) {
				Address relocAddr = textAddrSpace.getAddress(relocationEntry.address);
				if (textBlock.contains(relocAddr)) {

					// TODO: is getGlobalFunctions appropriate? It works when an A.out object file
					// is being loaded into an existing program
					List<Function> funcs = program.getListing().getGlobalFunctions(sym.name);
					if (funcs.size() > 0) {

						// for now, we're just taking the first function with that name
						Address funcAddr = funcs.get(0).getEntryPoint();

						// TODO: take the pointer size and endianness into account.
						// TODO: is it possible that we may sometimes need to use an absolute address
						// as opposed to an offset from the current location?
						long displacement = funcAddr.getOffset() - relocAddr.getOffset();
						byte[] displacementBytes = new byte[] {
							(byte) ((displacement >> 24) & 0xff),
							(byte) ((displacement >> 16) & 0xff),
							(byte) ((displacement >> 8) & 0xff),
							(byte) ((displacement >> 0) & 0xff),
						};

						try {
							textBlock.putBytes(relocAddr, displacementBytes);
						} catch (MemoryAccessException e) {
							e.printStackTrace();
						}
					} else {
						log.appendMsg("Symbol'" + sym.name + "' was not found in global function list.");
					}
				}
			} else {
				// TODO: if the relocation is not marked as external
				log.appendMsg("AOUT: Symbol '" + sym.name + "' is not marked as external.");
			}
		}
		// TODO: iterate through the data relocation table as well
	}
	
	private boolean fixAddress(MemoryBlock block, Address pointerLocation, long newAddress) {
		return false;
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
