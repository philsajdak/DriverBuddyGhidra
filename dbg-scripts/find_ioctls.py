# Python extension designed to find Windows device IOCTLs (I/O control codes) in binary files
# @author github.com/philsajdak
# @category Analysis
# @keybinding Shift T
# @menupath
# @toolbar

# Note: Ghidra uses Jython, which uses Python 2.7, so this is written with Python 2.7 in mind

# Core Functionality:
#   Locates device control dispatch routines in Windows drivers
#   Identifies IOCTL codes used by the driver
#   Analyzes each IOCTL handler to determine:
#       Input/output buffer requirements
#       Buffer size checks
#       Expected buffer field values
#       Memory operations
#       Error codes returned
#       Function calls made

# Detection Methods:
#   Uses pattern matching to find IOCTL dispatch routines (looking for specific offset patterns like +0xe0, +0x38 (although some might be overkill))
#   Analyzes decompiled C code for IOCTL codes (typically values >= 0x200000)
#   Looks for buffer validation patterns and size checks
#   Tracks memory operations and API calls

# Limitations:
#   Relies on Ghidra's decompilation accuracy
#   May miss dynamically constructed IOCTL codes
#   Pattern matching could miss non-standard implementations
#   May generate false positives when similar patterns appear in non-IOCTL code
#   Cannot detect runtime-generated validation checks
#   Only works on relatively standard Windows driver implementations

# TODO: Working on a better way to determine the IOCTL details (since right now it's not great at detecting buffer requirements).

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
import re

def decompileFunction(function):
    """Helper function to decompile a function using DecompInterface"""
    decompiler = DecompInterface()
    decompiler.openProgram(getCurrentProgram())
    results = decompiler.decompileFunction(function, 60, ConsoleTaskMonitor())
    decompiler.dispose()
    return results

def find_function_by_name(function_manager, name):
    """Helper function to find a function by its name"""
    functions = function_manager.getFunctions(True)  # true for forward iteration
    for func in functions:
        if func.getName() == name:
            return func
    return None

def extract_function_name(line):
    """Extract function name from a line of decompiled code"""
    # first try to find FUN_ pattern
    fun_match = re.search(r'(FUN_[0-9a-fA-F]+)', line)
    if fun_match:
        return fun_match.group(1)
        
    # then, try to find assignment to a named function
    name_match = re.search(r'=\s*&?([a-zA-Z_][a-zA-Z0-9_]*)\s*;', line)
    if name_match:
        return name_match.group(1)
        
    return None

def find_dispatch_routine():
    """Find the IRP_MJ_DEVICE_CONTROL dispatch routine"""
    program = getCurrentProgram()
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # true for forward
    
    dispatch_candidates = []
    
    for function in functions:
        results = decompileFunction(function)
        if results is not None and results.decompileCompleted():
            c_code = results.getDecompiledFunction().getC()
            
            patterns = [
                r'\(param_[1-9] \+ 0xe0\) =',    # standard pointer arithmetic with any param_N
                r'MajorFunction\[0xe\]',         # array index hex
                r'MajorFunction\[14\]',          # array index decimal, possibly not needed?
                # r'\(param_[1-9] \+ 0x38\)',      # 32-bit pointer arithmetic with any param_N, possibly not needed?
                # r'\(param_[1-9] \+ 0x70\)'       # 64-bit pointer arithmetic with any param_N, possibly not needed?
            ]
            
            for pattern in patterns:
                for line in c_code.splitlines():
                    if re.search(pattern, line):
                        func_name = extract_function_name(line)
                        if func_name and func_name not in dispatch_candidates:
                            if not func_name.startswith("FUN_"):
                                resolved_func = find_function_by_name(function_manager, func_name)
                                if resolved_func:
                                    func_addr = resolved_func.getEntryPoint()
                                    func_name = "FUN_" + func_addr.toString()
                            
                            dispatch_candidates.append(func_name)
                            print "[*] Found dispatch routine candidate in %s" % function.getName()
                            print "    - Match: %s" % line.strip()
                            print "    - Resolved to: %s" % func_name
                            
    return dispatch_candidates

def find_ioctls_in_function(c_code):
    """Find all IOCTL codes in a decompiled function"""
    ioctls = set()
    
    # first, normalize the code by removing newlines and extra spaces
    normalized_code = re.sub(r'\s+', ' ', c_code)
    
    # enhanced patterns for finding IOCTL codes
    patterns = [
        # original patterns
        r'case\s+0x([0-9A-Fa-f]+)\s*:',
        r'if\s*\(\s*iVar\d+\s*==\s*0x([0-9A-Fa-f]+)\)',
        r'ioControlCode\s*==\s*0x([0-9A-Fa-f]+)',
        
        # new patterns for deeply nested conditions
        r'(?:if|else if)\s*\(\s*(?:\([^)]*\))?\s*(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)',
        r'(?:\(\s*)+(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)(?:\s*\))+',
        
        # specific pattern for nested else-if with multiple conditions
        r'else\s*{[^}]*if\s*\(\s*\(\s*\([^)]*==\s*0x([0-9A-Fa-f]+)[^}]*}',
        
        # direct comparisons
        r'(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)',
        
        # handle multiple AND conditions
        r'\(\s*(?:\([^)]*\)\s*&&\s*)*[^)]*==\s*0x([0-9A-Fa-f]+)',
        
        # catch deeply nested conditions in else blocks
        r'else\s*{[^}]*==\s*0x([0-9A-Fa-f]+)[^}]*}',
        
        # handle negative values
        r'==\s*-0x([0-9A-Fa-f]+)',
        r'if\s*\([^)]*-0x([0-9A-Fa-f]+)',
        
        # IOCTL definitions
        r'IOCTL_[A-Z_]+\s*=\s*0x([0-9A-Fa-f]+)',
        r'#define\s+IOCTL_[A-Z_]+\s+0x([0-9A-Fa-f]+)'
    ]
    
    # additional preprocessing to handle multi-line conditions
    code_blocks = re.split(r'(else\s*{[^}]*})', normalized_code)
    
    for block in code_blocks:
        for pattern in patterns:
            matches = re.finditer(pattern, block, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                try:
                    value = match.group(1)
                    
                    # Handle negative values
                    if '-0x' in pattern:
                        ioctl_int = -int(value, 16) & 0xFFFFFFFF
                    else:
                        ioctl_int = int(value, 16)
                    
                    # filter for valid IOCTLs, typically 3rd party drivers minimum IOCTL is 0x20000
                    if ioctl_int >= 0x200000:
                        # debug print for pattern matching
                        # print "Found IOCTL %s with pattern: %s" % (hex(ioctl_int), pattern)
                        # print "In block: %s..." % block[:100]  # Show first 100 chars of matching block
                        ioctls.add(ioctl_int)
                except Exception as e:
                    # debug exception handling
                    # print "Error processing match: %s" % str(e)
                    continue
    
    return sorted(list(ioctls))

def is_valid_buffer_check(line, offset, value):
    """Filter out false positive buffer checks"""
    # skip loop condition checks
    if 'while' in line or 'for' in line:
        return False
        
    return True

def analyze_ioctl_handler(decompiled_func, ioctl_code):
    """Analyze an IOCTL handler to determine its input/output requirements"""
    analysis = {
        'ioctl_code': hex(ioctl_code).rstrip('L'),
        'input_buffer': {
            'required': False,
            'size': None,
            'min_size': None,
            'structure': []
        },
        'output_buffer': {
            'required': False,
            'size': None,
            'structure': []
        },
        'function_calls': [],
        'buffer_operations': [],
        'error_codes': set(),
        'size_checks': [],
        'buffer_checks': []
    }
    
    # normalize code and extract IOCTL block
    normalized_code = re.sub(r'\s+', ' ', decompiled_func)
    
    # enhanced block extraction for nested conditions
    ioctl_hex = hex(ioctl_code).rstrip('L')
    block_patterns = [
        r'if\s*\(\s*(?:\([^)]*\))?\s*(?:iVar\d+|uVar\d+|\w+)\s*==\s*%s[^}]*{([^}]+)}' % ioctl_hex,
        r'else\s*{[^}]*if\s*\(\s*\(\s*\([^)]*==\s*%s[^}]*{([^}]+)}' % ioctl_hex,
        r'case\s+%s:\s*{([^}]+)}' % ioctl_hex
    ]
    
    ioctl_block = None
    for pattern in block_patterns:
        match = re.search(pattern, normalized_code, re.DOTALL)
        if match:
            ioctl_block = match.group(1)
            break
    
    if not ioctl_block:
        return analysis
        
    # check for buffer requirements
    if re.search(r'plVar\d+\s*==\s*\(longlong \*\)0x0', ioctl_block):
        analysis['input_buffer']['required'] = True
    
    # look for size checks
    size_checks = re.findall(r'(?:uVar\d+|iVar\d+|\w+)\s*==\s*0x([0-9a-fA-F]+)', ioctl_block)
    for size in size_checks:
        try:
            size_value = int(size, 16)
            if size_value > 0 and size_value < 0x10000:  # reasonable size check
                analysis['size_checks'].append(size_value)
        except:
            continue
    
    # extract function calls
    func_calls = re.findall(r'(?:FUN_[0-9a-fA-F]+|[A-Z][A-Za-z]+)\([^)]+\)', ioctl_block)
    for call in func_calls:
        if call.startswith(('Mm', 'Ke', 'Rtl', 'Ob', 'mem')):
            analysis['buffer_operations'].append(call)
        else:
            analysis['function_calls'].append(call)
    
    # look for error codes
    error_codes = re.findall(r'(?:status|uVar\d+)\s*=\s*0x([cC][0-9a-fA-F]+)', ioctl_block)
    for code in error_codes:
        analysis['error_codes'].add('0x' + code)
    
    return analysis

def extract_ioctl_block(decompiled_code, ioctl_int):
    """Extract the code block handling a specific IOCTL"""
    # get both positive and negative representations
    pos_hex = hex(ioctl_int).rstrip('L')
    neg_value = -ioctl_int & 0xFFFFFFFF  # get negative two's complement
    neg_hex = "-0x%x" % neg_value
    
    patterns = [
        # positive value patterns
        r'if\s*\(\s*\w+\s*==\s*%s\)\s*{([^}]+)}' % pos_hex,
        r'case\s+%s:\s*{([^}]+)}' % pos_hex,
        # negative value patterns
        r'if\s*\(\s*\w+\s*==\s*%s\)\s*{([^}]+)}' % neg_hex,
        r'if\s*\(\s*iVar\d+\s*==\s*%s\)\s*{([^}]+)}' % neg_hex,
        r'if\s*\(\s*[^{]+%s[^{]+\)\s*{([^}]+)}' % neg_hex
    ]
    
    for pattern in patterns:
        match = re.search(pattern, decompiled_code, re.DOTALL)
        if match:
            return match.group(1)
    
    return None

def find_ioctls():
    """Main function to find and analyze IOCTLs"""
    print "[+] Scanning for IOCTLs in %s" % getCurrentProgram().getName()

    valid_ioctl_count = 0  # this is to track total valid IOCTLs
    
    dispatch_routines = find_dispatch_routine()
    if not dispatch_routines:
        print "[-] No dispatch routine found"
        return
    
    print "\n[+] Found potential dispatch routine(s):"
    for routine in dispatch_routines:
        print "    - %s" % routine
        
        # get the function
        program = getCurrentProgram()
        function_manager = program.getFunctionManager()
        function = None
        
        if routine.startswith("FUN_"):
            addr = program.getAddressFactory().getAddress(routine[4:])
            function = function_manager.getFunctionAt(addr)
        else:
            function = find_function_by_name(function_manager, routine)
            
        if not function:
            continue
            
        # decompile the function
        results = decompileFunction(function)
        if not results or not results.decompileCompleted():
            continue
            
        c_code = results.getDecompiledFunction().getC()
        
        # find all IOCTLs in the function
        ioctls = find_ioctls_in_function(c_code)
        
        if not ioctls:
            print "[-] No IOCTLs found in dispatch routine"
            continue
        
        for ioctl in ioctls:
            analysis = analyze_ioctl_handler(c_code, ioctl)
            if analysis:
                valid_ioctl_count += 1
                print_ioctl_analysis(analysis, valid_ioctl_count)
        
    print "\n[+] Found %d valid IOCTLs in %s!" % (valid_ioctl_count, routine)

def print_ioctl_analysis(analysis, index):
    """Pretty print the IOCTL analysis"""
    print "\n[%d] IOCTL %s Analysis:" % (index, analysis['ioctl_code'])
    print "    ----------------------------------------"
    
    print "    Buffer Requirements:"
    print "        Input Buffer:  %s" % ("Required" if analysis['input_buffer']['required'] else "Optional")
    if analysis['input_buffer']['min_size']:
        print "        Minimum Input Size: 0x%x" % analysis['input_buffer']['min_size']
    if analysis['size_checks']:
        print "        Size Checks: %s" % ', '.join(hex(x) for x in analysis['size_checks'])
    
    if analysis['buffer_checks']:
        print "\n    Buffer Field Checks:"
        for check in analysis['buffer_checks']:
            print "        Offset 0x%x: Expected %s" % (check['offset'], check['expected_value'])
    
    if analysis['buffer_operations']:
        print "\n    Buffer Operations:"
        for op in analysis['buffer_operations']:
            print "        - %s" % op
    
    if analysis['function_calls']:
        print "\n    Function Calls:"
    for func in analysis['function_calls']:
        print "        - %s" % func
    
    if analysis['error_codes']:
        print "\n    Error Codes:"
        for code in sorted(analysis['error_codes']):
            print "        - %s" % code
    
    if analysis['output_buffer']['size']:
        print "\n    Output Buffer Size: 0x%x" % analysis['output_buffer']['size']
    
    print "    ----------------------------------------"

if __name__ == '__main__':
    find_ioctls()