import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;

/** Seed the caller-supplied raw-binary entry before default auto-analysis. */
public final class ReaGhidraPrepareRaw extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 3) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language, load base and entry address"
            );
        }
        String expectedLanguage = arguments[0];
        String baseHex = arguments[1];
        String entryHex = arguments[2];
        if (!currentProgram.getLanguageID().getIdAsString().equals(expectedLanguage) ||
            !currentProgram.getExecutableFormat().equals("Raw Binary")) {
            throw new IllegalArgumentException(
                "Raw binary preparation requires the committed language and BinaryLoader import"
            );
        }
        Address base = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(baseHex);
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entryHex);
        MemoryBlock block = base == null ? null : currentProgram.getMemory().getBlock(base);
        boolean fileStart = false;
        if (block != null) {
            // Processor-defined zero page/stack blocks can precede the imported file.
            for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                if (source.getFileBytes().isPresent() && source.getFileBytesOffset() == 0 &&
                    base.equals(source.getMinAddress())) {
                    fileStart = true;
                    break;
                }
            }
        }
        if (!fileStart) {
            throw new IllegalArgumentException(
                "Raw binary import must map file offset 0 at the caller-supplied load base"
            );
        }
        if (entry == null || !block.contains(entry) ||
            !currentProgram.getMemory().getBlock(entry).equals(block)) {
            throw new IllegalArgumentException("Raw binary entry must lie inside the source-backed load block");
        }
        if (expectedLanguage.equals("ARM:LE:32:Cortex")) {
            Register thumb = currentProgram.getRegister("TMode");
            if (thumb == null || !BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(thumb, entry, false)))
                throw new IllegalStateException("Cortex-M entry must be in Thumb mode");
        }
        addEntryPoint(entry);
        if (!disassemble(entry) || createFunction(entry, "entry") == null) {
            throw new IllegalStateException("Raw binary entry cannot be decoded as a function");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setBoolean("REA raw binary prepared", true);
    }
}
