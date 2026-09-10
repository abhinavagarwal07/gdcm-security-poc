// Finding 3 ASan trigger: out-of-bounds heap read in the DiscreteSegment
// constructor (gdcmSegmentedPaletteColorLookupTable.cxx), which derives the
// segment end from an unchecked attacker-supplied length word.
// gdcm::ImageReader::Read() -> SetLUT -> ExpandPalette -> DiscreteSegment.
#include "gdcmImageReader.h"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>\n";
        return 1;
    }
    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);
    bool ok = reader.Read();
    if (!ok) {
        std::cerr << "ImageReader::Read() returned false\n";
        // Still may have triggered the bug during the attempt
        return 2;
    }
    const gdcm::Image& img = reader.GetImage();
    // Force pixel decode: get the buffer
    size_t len = img.GetBufferLength();
    std::vector<char> buf(len);
    bool got = img.GetBuffer(buf.data());
    std::cout << "Read OK, buffer_len=" << len << " got=" << got << "\n";
    return 0;
}
