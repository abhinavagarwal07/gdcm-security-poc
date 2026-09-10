#include "gdcmSegmentedPaletteColorLookupTable.h"

#include <cstdint>
#include <cstring>
#include <iostream>

int main()
{
  // Five words are physically allocated. Only the first four are declared to GDCM:
  // opcode, count, and two values. The third declared value is a known guard word.
  // This confirms a logical bounds violation without reading unrelated heap memory.
  uint16_t storage[5] = {0, 3, 0x1111, 0x2222, 0xC0DE};
  const unsigned int logical_bytes = 4 * sizeof(uint16_t);

  gdcm::SegmentedPaletteColorLookupTable lut;
  lut.Allocate(16);
  lut.InitializeRedLUT(3, 0, 16);
  lut.InitializeGreenLUT(3, 0, 16);
  lut.InitializeBlueLUT(3, 0, 16);
  lut.SetRedLUT(reinterpret_cast<unsigned char *>(storage), logical_bytes);
  lut.SetGreenLUT(reinterpret_cast<unsigned char *>(storage), logical_bytes);
  lut.SetBlueLUT(reinterpret_cast<unsigned char *>(storage), logical_bytes);

  const uint16_t input = 2;
  uint16_t output[3] = {0, 0, 0};
  const bool ok = lut.Decode(reinterpret_cast<char *>(output), sizeof(output),
                             reinterpret_cast<const char *>(&input), sizeof(input));

  if (ok && output[0] == 0xC0DE && output[1] == 0xC0DE && output[2] == 0xC0DE) {
    std::cout << "SENTINEL_PROPAGATION_CONFIRMED\n";
    return 0;
  }

  std::cout << "SENTINEL_NOT_OBSERVED\n";
  return 1;
}
