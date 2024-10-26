# Python extension designed to find Windows device names in binary files
# @author github.com/philsajdak
# @category Analysis
# @keybinding Shift E
# @menupath
# @toolbar

# Note: Ghidra uses Jython, which uses Python 2.7, so this is written with Python 2.7 in mind

# Core Functionality:
#   Scans memory blocks for Windows device name patterns (e.g., "\device", "\dosdevices", "\.", "??")
#   Analyzes functions that commonly handle device names (IoCreateSymbolicLink, RtlInitUnicodeString, IoDeleteSymbolicLink)
#   Uses both direct memory scanning and decompiler analysis to find device names

# Detection Methods:
#   Direct string scanning in memory blocks
#   Parameter analysis in function calls
#   Analysis of decompiled C code
#   Pattern matching using regular expressions

# Limitations:
#   Cannot detect dynamically generated device names
#   May miss obfuscated or encrypted strings
#   Only works on device names following standard Windows naming patterns
#   Relies on Ghidra's decompilation accuracy
#   May produce false positives if similar patterns appear in non-device strings

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.data import UnicodeDataType
from ghidra.program.model.pcode import PcodeOp
from java.lang import String
from ghidra.program.model.listing import CodeUnit, Data, Instruction
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
import re

def decompileFunction(function):
    """Helper function to decompile a function using DecompInterface"""
    decompiler = DecompInterface()
    decompiler.openProgram(getCurrentProgram())
    # use a timeout of 60 seconds
    results = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
    decompiler.dispose()
    return results

def scan_c_code_for_device_names(c_code):
    """Scan decompiled C code for device name strings"""
    string_pattern = r'(?:L?"([^"]*)")'
    strings = re.findall(string_pattern, c_code)
    device_strings = []
    for string in strings:
        if is_valid_device_name(string):
            device_strings.append(string)
    return device_strings

def is_valid_device_name(string):
    if not string:
        return False
    
    indicators = ["\\device\\", "\\dosdevices\\", "\\\\.\\", "\\??\\"]
    try:
        string_lower = string.lower()
        return any(indicator.lower() in string_lower for indicator in indicators)
    except:
        return False

def safe_str_conversion(value):
    """Safely convert a value to string, handling Unicode characters"""
    try:
        if isinstance(value, unicode):
            return value.encode('utf-8', errors='ignore')
        return str(value)
    except UnicodeEncodeError:
        return unicode(value).encode('utf-8', errors='ignore')

def scan_memory_block(block, listing):
    """Scan a memory block for strings that might be device names"""
    strings = []
    start_addr = block.getStart()
    end_addr = block.getEnd()
    current_addr = start_addr
    
    while current_addr <= end_addr:
        # try both defined and undefined data
        data = listing.getDataAt(current_addr)
        if not data:
            data = listing.getUndefinedDataAt(current_addr)
            
        if data and data.hasStringValue():
            try:
                string_value = safe_str_conversion(data.getValue())
                if is_valid_device_name(string_value):
                    strings.append((data.getAddress(), string_value))
            except:
                pass
        
        # move to next address
        if data:
            current_addr = data.getAddress().add(data.getLength())
        else:
            current_addr = current_addr.add(1)
            
    return strings

def find_device_names():
    program = getCurrentProgram()
    memory = program.getMemory()
    function_manager = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    
    print "[+] Scanning for device names in %s" % program.getName()

    found_any = False

    # first scan all memory blocks for strings
    print "\nScanning memory for device names..."
    for block in memory.getBlocks():
        if not block.isInitialized() or not block.isRead():
            continue
            
        print "[*] Scanning block: %s (Start: %s, Size: %d)" % (
            block.getName(), block.getStart(), block.getSize()
        )
        
        strings = scan_memory_block(block, listing)
        for addr, string in strings:
            print "[+] Found potential device name at %s: %s" % (addr, string)
            found_any = True

    # then, look for usage in functions
    print "\nAnalyzing functions..."
    for symbol_name in ["IoCreateSymbolicLink", "RtlInitUnicodeString", "IoDeleteSymbolicLink"]:
        symbols = symbol_table.getSymbols(symbol_name)
        
        if symbols.hasNext():
            symbol = symbols.next()
            print "[*] Found %s at %s" % (symbol_name, symbol.getAddress())
            
            # get references
            refs = getReferencesTo(symbol.getAddress())
            print "[*] Found %d references to %s" % (len(refs), symbol_name)
            
            for ref in refs:
                function = function_manager.getFunctionContaining(ref.getFromAddress())
                if not function:
                    continue
                    
                print "[*] Analyzing function: %s at %s" % (function.getName(), function.getEntryPoint())
                
                # add decompiler analysis
                results = decompileFunction(function)
                if results is not None and results.decompileCompleted():
                    # get high function for pcode analysis
                    high_function = results.getHighFunction()
                    if high_function:
                        pcodeOps = high_function.getPcodeOps()
                        while pcodeOps.hasNext():
                            pcodeOp = pcodeOps.next()
                            if pcodeOp.getOpcode() == PcodeOp.CALL:
                                params = pcodeOp.getInputs()
                                if len(params) >= 2:
                                    for param in params[1:2]:  # check second parameter
                                        if param.isAddress():
                                            addr = param.getAddress()
                                            data = listing.getDataAt(addr)
                                            if isinstance(data, Data) and data.hasStringValue():
                                                string_value = safe_str_conversion(data.getValue())
                                                if is_valid_device_name(string_value):
                                                    print "[+] Found device name in parameter at %s: %s" % (addr, string_value)
                                                    found_any = True
                    
                    # scan decompiled C code for strings
                    decompiled_c = results.getDecompiledFunction().getC()
                    device_strings = scan_c_code_for_device_names(decompiled_c)
                    if device_strings:
                        print "[+] Found device names in decompiled C code of %s:" % function.getName()
                        for string in device_strings:
                            print "    - %s" % string
                            found_any = True

    if not found_any:
        print "\n[!] No device names found. This could indicate:"
        print "    - Dynamic device name generation"
        print "    - Obfuscated strings"
        print "    - Device name stored in encrypted form"
        print "    - Device name constructed at runtime"
        
    print "\n[+] Scan complete"

if __name__ == '__main__':
    find_device_names()