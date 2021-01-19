// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

/**
 * Platform interface.  This is the top-level include for anything
 * platform-specific.
 */

#include <pal/pal.h>

#pragma once
namespace sandbox
{
  namespace platform
  {
#ifdef __unix__
    /**
     * The `handle_t` type represents a handle used to access OS resources.  On
     * POSIX systems, this is a file descriptor or, more accurately, an integer
     * index into the process's file-descriptor table.
     */
    using handle_t = int;
    /**
     * Class encapsulating a file descriptor.  This handles deallocation.
     */
    struct Handle
    {
      /**
       * The file descriptor that this wraps.  POSIX file descriptors are
       * indexes into a file descriptor table. Negative indexes are invalid and
       * so -1 is used as a default invalid value.
       *
       * This field is specific to the POSIX implementation and so should be
       * used only in POSIX-specific code paths.
       */
      handle_t fd = -1;

      /**
       * Check if this is a valid file descriptor.  This should be used only to
       * check whether this class has been initialised with a valid descriptor:
       * even if the file descriptor is valid at the call, another thread could
       * manipulate the file descriptor table and invalidate it immediately
       * after this function returns.
       *
       * In debug builds, this will check if the file descriptor refers to a
       * valid entry in the file descriptor table, though the above caveats
       * still apply.
       */
      bool is_valid()
      {
        assert(
          ((fd < 0) || (fcntl(fd, F_GETFD) >= 0)) &&
          "File descriptor is a valid index but does not refer to a valid file "
          "descriptor");
        return fd >= 0;
      }
      void reset(int new_fd)
      {
        if (is_valid())
        {
          close(fd);
        }
        fd = new_fd;
      }

      Handle() = default;
      Handle(int new_fd) : fd(new_fd) {}

      /**
       * Copy constructor is deleted.  File descriptors are not reference
       * counted and so must have a single deleter.  If a file descriptor needs
       * to be multiply owned, this should be done via a
       * `std::shared_ptr<Handle>`.
       */
      Handle(const Handle&) = delete;

      /**
       * Move constructor.  Takes ownership of a file descriptor.
       */
      Handle(Handle&& other) : fd(other.fd)
      {
        other.fd = -1;
      }

      Handle& operator=(Handle&& other)
      {
        reset(other.fd);
        other.fd = -1;
        return *this;
      }

      Handle& operator=(int new_fd)
      {
        reset(new_fd);
        return *this;
      }

      /**
       * Destructor, closes the file descriptor if it is valid.
       */
      ~Handle()
      {
        reset(-1);
      }
    };
#else
#  error Handle type not defined for your platform
#endif
  }
}

#include "poller.h"
#include "shm.h"
