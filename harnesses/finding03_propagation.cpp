// Finding 3 propagation trigger: shows that the OOB heap read in
// gdcm::DiscreteSegment<T>::Expand (gdcmSegmentedPaletteColorLookupTable.cxx,
// ~line 64) is not merely a read past the end of a buffer -- the
// out-of-bounds words it copies travel all the way into the decoded pixel
// buffer a caller receives.
//
// Mechanism (see generators/finding-03.py and harnesses/finding03_sentinel.cpp):
// a segment's declared length word is trusted with no bound, so
// std::copy(first+2, first+2+length, ...) reads heap memory past the
// Segmented Palette Color LUT Data element. With N=257 declared entries,
// LookupTable::InitializeLUT sets IncompleteLUT=true, which skips the
// Internal->RGB.size() guard in LookupTable::SetLUT -- so the OOB-expanded
// palette (255 foreign words) is accepted into Internal->RGB and reaches
// every pixel decoded through that palette via ImageApplyLookupTable.
//
// This harness never prints heap contents. It only reports whether decoded
// pixel words fall outside the set of values the file's LUT element
// physically supplied.
#include "gdcmImageReader.h"
#include "gdcmImageApplyLookupTable.h"
#include "gdcmTag.h"
#include "gdcmByteValue.h"
#include "gdcmDataElement.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <set>
#include <vector>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>" << std::endl;
        return 2;
    }

    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);
    if (!reader.Read()) {
        std::cerr << "ImageReader::Read() failed" << std::endl;
        return 2;
    }

    // Collect every uint16 word physically present in the Segmented Red
    // Palette Color LUT Data element (0028,1221). These are the only
    // palette values the FILE legitimately supplies.
    const gdcm::DataElement &lutde =
        reader.GetFile().GetDataSet().GetDataElement(gdcm::Tag(0x0028, 0x1221));
    const gdcm::ByteValue *bv = lutde.GetByteValue();
    if (!bv) {
        std::cerr << "(0028,1221) has no ByteValue" << std::endl;
        return 2;
    }

    std::set<uint16_t> in_file_words;
    const char *lutptr = bv->GetPointer();
    const size_t lutlen = bv->GetLength();
    for (size_t i = 0; i + 1 < lutlen; i += 2) {
        uint16_t w;
        std::memcpy(&w, lutptr + i, sizeof(w));
        in_file_words.insert(w);
    }

    gdcm::ImageApplyLookupTable lutfilt;
    lutfilt.SetInput(reader.GetImage());
    if (!lutfilt.Apply()) {
        std::cerr << "ImageApplyLookupTable::Apply() failed" << std::endl;
        return 3;
    }

    const gdcm::Pixmap &out = lutfilt.PixmapToPixmapFilter::GetOutput();
    const unsigned long buflen = out.GetBufferLength();
    std::vector<char> buffer(buflen);
    if (!out.GetBuffer(buffer.data())) {
        std::cerr << "GetBuffer() failed" << std::endl;
        return 3;
    }

    // Walk the decoded output as uint16 words and count how many are
    // neither 0 nor a member of the in-file set -- i.e. values that could
    // only have reached the output via the OOB read.
    size_t words_examined = 0;
    size_t foreign_count = 0;
    for (size_t i = 0; i + 1 < buflen; i += 2) {
        uint16_t w;
        std::memcpy(&w, buffer.data() + i, sizeof(w));
        ++words_examined;
        if (w != 0 && in_file_words.find(w) == in_file_words.end()) {
            ++foreign_count;
        }
    }

    std::cout << "in_file_palette_words=" << in_file_words.size() << std::endl;
    std::cout << "decoded_words_examined=" << words_examined << std::endl;
    std::cout << "foreign_words=" << foreign_count << std::endl;

    if (foreign_count > 0) {
        std::cout << "OOB_PROPAGATION_CONFIRMED" << std::endl;
        return 0;
    }

    std::cout << "OOB_PROPAGATION_NOT_OBSERVED" << std::endl;
    return 1;
}
