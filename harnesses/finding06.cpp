// Finding 6: RLE NumSegments = 0 divide-by-zero.
// The fault fires inside ImageReader::Read() itself: ComputeLossyFlag() runs
// the RLE decode, which reaches `length /= numSegments` in
// RLECodec::DecodeByStreams with numSegments == 0. On x86 an integer divide by
// zero raises SIGFPE; on arm64 it does not trap, which is why this case is
// classified by the UBSan diagnostic rather than by the signal.
#include "gdcmImageReader.h"
#include <iostream>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>" << std::endl;
        return 1;
    }

    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);

    std::cerr << "[*] Calling ImageReader::Read() -- div-by-zero expected here" << std::endl;
    if (!reader.Read()) {
        // Reached only if the file is rejected before the RLE decode runs.
        std::cerr << "[-] ImageReader::Read() returned false" << std::endl;
        return 1;
    }

    // Not reached on the crafted PoC (Read() aborts during the RLE decode).
    std::cerr << "[!] Read() returned without crashing" << std::endl;
    return 0;
}
