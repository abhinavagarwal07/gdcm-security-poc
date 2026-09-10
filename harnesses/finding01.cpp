// Minimal trigger for Finding 1: RLE + YBR_FULL_422 multi-frame heap overflow.
// ImageReader::Read() alone reaches the overflow via ComputeLossyFlag(),
// which decodes the pixel data internally -- no explicit GetBuffer() needed.
#include "gdcmImageReader.h"
#include <vector>
#include <iostream>
int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>" << std::endl;
        return 2;
    }
    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);
    if (!reader.Read()) {
        std::cerr << "Read failed" << std::endl;
        return 1;
    }
    std::cout << "Read succeeded" << std::endl;
    const gdcm::Image &image = reader.GetImage();
    unsigned long buflen = image.GetBufferLength();
    std::cout << "Buffer length: " << buflen << std::endl;
    std::vector<char> buffer(buflen);
    std::cout << "Calling GetBuffer()..." << std::endl;
    bool ok = image.GetBuffer(buffer.data());
    std::cout << "GetBuffer returned: " << ok << std::endl;
    return ok ? 0 : 1;
}
