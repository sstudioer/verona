// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#include "child_malloc.h"
#include "host_service_calls.h"
#include "platform/platform.h"
#include "sandbox.hh"
#include "shared.h"
#include "shared_memory_region.h"

#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

using address_t = snmalloc::Aal::address_t;

// A few small platform-specific tweaks that aren't yet worth adding to the
// platform abstraction layer.
#ifdef __FreeBSD__
// On FreeBSD, libc interposes on some system calls and does so in a way that
// causes them to segfault if they are invoked before libc is fully
// initialised.  We must instead call the raw system call versions.
extern "C" ssize_t __sys_write(int fd, const void* buf, size_t nbytes);
extern "C" ssize_t __sys_read(int fd, void* buf, size_t nbytes);
#  define write __sys_write
#  define read __sys_read
#elif defined(__linux__)
namespace
{
  /**
   * Linux run-time linkers do not currently support fdlopen, but it can be
   * emulated with a wrapper that relies on procfs.  Each fd open in a
   * process exists as a file (typically a symlink) in /proc/{pid}/fd/{fd
   * number}, so we can open that.  This does depend on the running process
   * having access to its own procfs entries, which may be a problem for some
   * possible sandboxing approaches.
   */
  void* fdlopen(int fd, int flags)
  {
    char* str;
    asprintf(&str, "/proc/%d/fd/%d", (int)getpid(), fd);
    void* ret = dlopen(str, flags);
    free(str);
    return ret;
  }
  typedef void (*dlfunc_t)(void);

  /**
   * It is undefined behaviour in C to cast from a `void*` to a function
   * pointer, but POSIX only provides a single function to get a pointer from a
   * library.  BSD systems provide `dlfunc` to avoid this but glibc does not,
   * so we provide our own.
   */
  dlfunc_t dlfunc(void* handle, const char* symbol)
  {
    return (dlfunc_t)dlsym(handle, symbol);
  }
}
#endif

extern "C"
{
  /**
   * The `environ` symbol is exported by libc, but not exposed in any header.
   *  We need to access this directly during bootstrap, when the libc functions
   *  that access it may not yet be ready.
   */
  extern char** environ;
}

sandbox::ProxyPageMap sandbox::ProxyPageMap::p;

using namespace snmalloc;
using namespace sandbox;

namespace
{
  /**
   * Flag indicating that bootstrapping has finished.  Note that we cannot
   * create any threads until after malloc is set up and so this does not need
   * to be atomic: It is never modified after the second thread is created.
   */
  bool done_bootstrapping = false;

  /**
   * Bootstrap function.  Map the shared memory region and configure everything
   * needed for malloc.
   */
  SNMALLOC_SLOW_PATH
  void bootstrap();

  /**
   * Always-inlined wrapper to call `bootstrap` if bootstrapping is still
   * needed.
   */
  SNMALLOC_FAST_PATH
  void bootstrap_if_needed()
  {
    if (unlikely(!done_bootstrapping))
    {
      bootstrap();
    }
  }

  /**
   * A pointer to the object that manages the vtable exported by this library.
   */
  ExportedLibrary* library;

  /**
   * The start of the shared memory region.  Passed as a command-line argument.
   */
  void* shared_memory_start = 0;

  /**
   * The end of the shared memory region.  Passed as a command-line argument.
   */
  void* shared_memory_end = 0;

  /**
   * Pointer to the shared memory region.  This will be equal to
   * `shared_memory_start` and is simply a convenience to have a pointer of the
   * correct type.
   */
  SharedMemoryRegion* shared = nullptr;

  /**
   * The exported function that returns the type encoding of an exported
   * function.  This is used by the library caller for type checking.
   */
  char* exported_types(int idx)
  {
    return library->type_encoding(idx);
  }

  /**
   * Synchronous RPC call to the parent environment.  This sends a message to
   * the parent and waits for a response.  These calls should never return an
   * error and so this aborts the process if they do.
   *
   * This function is called during early bootstrapping and so cannot use any
   * libc features that either depend on library initialisation or which
   * allocate memory.
   */
  uintptr_t
  requestHostService(HostServiceCallID id, uintptr_t arg0, uintptr_t arg1 = 0)
  {
    static std::atomic_flag lock;
    FlagLock g(lock);
    HostServiceRequest req{id, arg0, arg1};
    auto written_bytes = write(PageMapUpdates, &req, sizeof(req));
    assert(written_bytes == sizeof(req));
    HostServiceResponse response;
    auto read_bytes = read(PageMapUpdates, &response, sizeof(response));
    assert(read_bytes == sizeof(response));

    if (response.error)
    {
      DefaultPal::error("Host returned an error.");
    }
    return response.ret;
  }
}

namespace sandbox
{
  void ProxyPageMap::set(uintptr_t p, uint8_t x)
  {
    assert(
      (p >= reinterpret_cast<uintptr_t>(shared_memory_start)) &&
      (p < reinterpret_cast<uintptr_t>(shared_memory_end)));
    requestHostService(
      ChunkMapSet, reinterpret_cast<uintptr_t>(p), static_cast<uintptr_t>(x));
  }

  uint8_t ProxyPageMap::get(address_t p)
  {
    return GlobalPagemap::pagemap().get(p);
  }

  uint8_t ProxyPageMap::get(void* p)
  {
    return GlobalPagemap::pagemap().get(address_cast(p));
  }

  void ProxyPageMap::set_slab(snmalloc::Superslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMSuperslab);
  }

  void ProxyPageMap::clear_slab(snmalloc::Superslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMNotOurs);
  }

  void ProxyPageMap::clear_slab(snmalloc::Mediumslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMNotOurs);
  }

  void ProxyPageMap::set_slab(snmalloc::Mediumslab* slab)
  {
    set(reinterpret_cast<uintptr_t>(slab), (size_t)CMMediumslab);
  }

  void ProxyPageMap::set_large_size(void* p, size_t size)
  {
    size_t size_bits = bits::next_pow2_bits(size);
    assert((p >= shared_memory_start) && (p < shared_memory_end));
    requestHostService(
      ChunkMapSetRange,
      reinterpret_cast<uintptr_t>(p),
      static_cast<uintptr_t>(size_bits));
  }

  void ProxyPageMap::clear_large_size(void* p, size_t size)
  {
    assert((p >= shared_memory_start) && (p < shared_memory_end));
    size_t size_bits = bits::next_pow2_bits(size);
    requestHostService(
      ChunkMapClearRange,
      reinterpret_cast<uintptr_t>(p),
      static_cast<uintptr_t>(size_bits));
  }

  void* MemoryProviderProxy::pop_large_stack(size_t large_class)
  {
    bootstrap_if_needed();
    return reinterpret_cast<void*>(requestHostService(
      MemoryProviderPopLargeStack, static_cast<uintptr_t>(large_class)));
  }

  void
  MemoryProviderProxy::push_large_stack(Largeslab* slab, size_t large_class)
  {
    bootstrap_if_needed();
    requestHostService(
      MemoryProviderPushLargeStack,
      reinterpret_cast<uintptr_t>(slab),
      static_cast<uintptr_t>(large_class));
  }

  void* MemoryProviderProxy::reserve_committed_size(size_t size) noexcept
  {
    bootstrap_if_needed();
    size_t size_bits = snmalloc::bits::next_pow2_bits(size);
    size_t large_class = std::max(size_bits, SUPERSLAB_BITS) - SUPERSLAB_BITS;
    return reserve_committed(large_class);
  }
  void* MemoryProviderProxy::reserve_committed(size_t large_class) noexcept
  {
    bootstrap_if_needed();
    return reinterpret_cast<void*>(requestHostService(
      MemoryProviderReserve, static_cast<uintptr_t>(large_class)));
  }

  /**
   * The class that represents the internal side of an exported library.  This
   * manages a run loop that waits for calls, invokes them, and returns the
   * result.
   */
  class ExportedLibraryPrivate
  {
    friend class ExportedLibrary;

    /**
     * The socket that should be used for passing new file descriptors into
     * this process.
     *
     * Not implemented yet.
     */
    __attribute__((unused)) platform::handle_t socket_fd;

    /**
     * The shared memory region owned by this sandboxed library.
     */
    struct SharedMemoryRegion* shared_mem;

  public:
    /**
     * Constructor.  Takes the socket over which this process should receive
     * additional file descriptors and the shared memory region.
     */
    ExportedLibraryPrivate(platform::handle_t sock, SharedMemoryRegion* region)
    : socket_fd(sock), shared_mem(region)
    {}

    /**
     * The run loop.  Takes the public interface of this library (effectively,
     * the library's vtable) as an argument.
     */
    void runloop(ExportedLibrary* library)
    {
      while (1)
      {
        shared_mem->wait(true);
        if (shared_mem->should_exit)
        {
          exit(0);
        }
        assert(shared_mem->is_child_executing);
        try
        {
          (*library->functions[shared_mem->function_index])(
            shared_mem->msg_buffer);
        }
        catch (...)
        {
          // FIXME: Report error in some useful way.
          printf("Exception!\n");
        }
        shared_mem->signal(false);
      }
    }
  };

}

char* ExportedLibrary::type_encoding(int idx)
{
  return functions.at(idx)->type_encoding();
}

namespace
{
  SNMALLOC_SLOW_PATH
  void bootstrap()
  {
    void* addr = nullptr;
    size_t length = 0;
    // Find the correct environment variables.  Note that libc is not fully
    // initialised when this is called and so we have to be very careful about
    // the libc function that we call.  We use the `environ` variable directly,
    // rather than `getenv`, which may allocate memory.
    //
    // The parent process provides the shared memory object in the file
    // descriptor with the number given by `SharedMemRegion` and the location
    // where it should be mapped in an environment variable.  The child has to
    // map this as the first step in bootstrapping (before most of libc
    // initialises itself) to get a working heap.
    for (char** e = environ; *e != nullptr; e++)
    {
      char* ev = *e;
      const char ev_name[] = "SANDBOX_LOCATION=";
      const size_t name_length = sizeof(ev_name) - 1;
      if (strncmp(ev_name, ev, name_length) == 0)
      {
        ev += name_length;
        char* end;
        addr = reinterpret_cast<void*>(strtoull(ev, &end, 16));
        assert(end[0] == ':');
        length = strtoull(end + 1, nullptr, 16);
        break;
      }
    }
    // Abort if we weren't able to find the correct lengths.
    if ((addr == nullptr) || (length == 0))
    {
      DefaultPal::error("Unable to find memory location");
    }

    // fprintf(stderr, "Child starting\n");
    // printf(
    //"Child trying to map fd %d at addr %p (0x%zx)\n", SharedMemRegion, addr,
    // length);
    void* ptr = mmap(
      addr,
      length,
      PROT_READ | PROT_WRITE,
      MAP_FIXED | MAP_SHARED | MAP_NOCORE,
      SharedMemRegion,
      0);

    // printf("%p\n", ptr);
    if (ptr == MAP_FAILED)
    {
      err(1, "Mapping shared heap failed");
    }

    shared = reinterpret_cast<SharedMemoryRegion*>(ptr);
    // Splice the pagemap page inherited from the parent into the pagemap.
    void* pagemap_chunk = GlobalPagemap::pagemap().page_for_address(
      reinterpret_cast<uintptr_t>(ptr));
    munmap(pagemap_chunk, 4096);
    void* shared_pagemap = mmap(
      pagemap_chunk, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, PageMapPage, 0);
    if (shared_pagemap == MAP_FAILED)
    {
      err(1, "Mapping shared pagemap page failed");
    }
    shared_memory_start = shared->start;
    shared_memory_end = shared->end;
    assert(shared_pagemap == pagemap_chunk);
    (void)shared_pagemap;

    done_bootstrapping = true;
  }
}

int main()
{
  sandbox::platform::Sandbox sb;
  sb.apply_sandboxing_policy();
  bootstrap_if_needed();
  // Close the shared memory region file descriptor before we call untrusted
  // code.
  close(SharedMemRegion);
  close(PageMapPage);

#ifndef NDEBUG
  // Check that our bootstrapping actually did the right thing and that
  // allocated objects are in the shared region.
  auto check_is_in_shared_range = [](void* ptr) {
    assert((ptr >= shared_memory_start) && (ptr < shared_memory_end));
  };
  check_is_in_shared_range(current_alloc_pool());
  check_is_in_shared_range(ThreadAlloc::get_reference());
  void* obj = malloc(42);
  check_is_in_shared_range(obj);
  free(obj);
  fprintf(stderr, "Sandbox: %p--%p\n", shared_memory_start, shared_memory_end);
#endif

  // Load the library using the file descriptor that the parent opened.  This
  // allows a Capsicum sandbox to prevent any access to the global namespace.
  // It is hopefully possible to implement something similar with seccomp-bpf,
  // though this may require calling into the parent to request additional file
  // descriptors and proxying all open / openat calls.
  void* handle = fdlopen(MainLibrary, RTLD_GLOBAL | RTLD_LAZY);
  if (handle == nullptr)
  {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 1;
  }

  // Find the library initialisation function.  This function will generate the
  // vtable.
  void (*sandbox_init)(ExportedLibrary*) =
    reinterpret_cast<void (*)(ExportedLibrary*)>(
      dlfunc(handle, "sandbox_init"));
  if (sandbox_init == nullptr)
  {
    fprintf(stderr, "dlfunc failed: %s\n", dlerror());
    return 1;
  }
  // Set up the exported functions
  ExportedLibraryPrivate* libPrivate;
  libPrivate = new ExportedLibraryPrivate(FDSocket, shared);
  library = new ExportedLibrary();
  library->export_function(exported_types);
  sandbox_init(library);

  // Enter the run loop, waiting for calls from trusted code.
  libPrivate->runloop(library);

  return 0;
}
