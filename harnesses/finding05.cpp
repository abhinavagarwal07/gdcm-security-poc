// Finding 5: unbounded nested-sequence recursion (CWE-674).
// No depth limit in DataSet::ReadNested -> Item::Read -> SequenceOfItems::Read;
// gdcm::Reader::Read() recurses once per nested SQ item. The fixture's 15000
// levels exhaust the stack and the process receives SIGSEGV, which no catch(...)
// can intercept. The runner bounds the child's stack so the depth needed to
// reach exhaustion does not depend on the host's default.

#include "gdcmReader.h"
#include <iostream>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>" << std::endl;
        return 1;
    }

    std::cout << "[*] Opening file: " << argv[1] << std::endl;
    std::cout.flush();

    gdcm::Reader reader;
    reader.SetFileName(argv[1]);
    bool result = reader.Read();

    // Reached only if the file wasn't nested deeply enough to overflow the stack.
    std::cout << "[!] Read() returned: " << (result ? "true" : "false") << std::endl;
    return result ? 0 : 1;
}
