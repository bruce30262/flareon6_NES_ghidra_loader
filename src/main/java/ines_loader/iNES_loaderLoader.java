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
package ines_loader;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.mem.MemoryBlock;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class iNES_loaderLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "iNES";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		byte NES_SIG[] = {0x4e, 0x45, 0x53, 0x1a};
		byte sig[] = provider.readBytes(0, 4);
		if(Arrays.equals(sig, NES_SIG)) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6502:LE:16:default", "default"), true));
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		// TODO: Load the bytes from 'provider' into the 'program'.
		try {
				// 0xc000 PRG ROM
				Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0xc000);
				MemoryBlock block = program.getMemory().createInitializedBlock("ROM", addr, 0x4000, (byte)0x00, monitor, false);
				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);
				// read the ROM bytes and attach them to the Ghidra program
				byte romBytes[] = provider.readBytes(0x10, 0x4000);			
				program.getMemory().setBytes(addr, romBytes);
				// execution starts at 0xc000 (addr)
				AddressSet addrSet = new AddressSet(addr);
				program.getFunctionManager().createFunction("entry", addr, addrSet, SourceType.IMPORTED);

				MakeSym(program, monitor, log, 0x2000, 1, "PPU_CTRL_REG1");
				MakeSym(program, monitor, log, 0x2001, 1, "PPU_CTRL_REG2");
				MakeSym(program, monitor, log, 0x2002, 1, "PPU_STATUS");
				MakeSym(program, monitor, log, 0x2003, 1, "PPU_SPR_ADDR");
				MakeSym(program, monitor, log, 0x2004, 1, "PPU_SPR_DATA");
				MakeSym(program, monitor, log, 0x2005, 1, "PPU_SCROLL_REG");
				MakeSym(program, monitor, log, 0x2006, 1, "PPU_ADDRESS");
				MakeSym(program, monitor, log, 0x2007, 1, "PPU_DATA");
				MakeSym(program, monitor, log, 0x4000, 4, "SND_SQUARE1_REG");
				MakeSym(program, monitor, log, 0x4004, 4, "SND_SQUARE2_REG");
				MakeSym(program, monitor, log, 0x4008, 4, "SND_TRIANGLE_REG");
				MakeSym(program, monitor, log, 0x400c, 2, "SND_NOISE_REG");
				MakeSym(program, monitor, log, 0x4010, 4, "SND_DELTA_REG");
				MakeSym(program, monitor, log, 0x4014, 1, "SPR_DMA");
				MakeSym(program, monitor, log, 0x4015, 1, "SND_MASTERCTRL_REG");
				MakeSym(program, monitor, log, 0x4016, 1, "JOYPAD_PORT1");
				MakeSym(program, monitor, log, 0x4017, 1, "JOYPAD_PORT2");
				MakeSym(program, monitor, log, 0xfffa, 2, "NMI_VECTOR_START_ADDRESS");
				MakeSym(program, monitor, log, 0xfffc, 2, "RESET_VECTOR_START_ADDRESS");
				MakeSym(program, monitor, log, 0xfffe, 2, "IRQ_VECTOR_START_ADDRESS");
				MakeSym(program, monitor, log, 0x0, 0x800, "RAM");
			
		}catch(Exception e) {
			log.appendException(e);
		}
	}
	
	private void MakeSym(Program program, TaskMonitor monitor, MessageLog log, int address, int size, String name) {
		try {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			MemoryBlock block = program.getMemory().createInitializedBlock(name, addr, size, (byte)0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
		}catch(Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
