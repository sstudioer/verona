// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#ifdef __unix__
#  include <poll.h>
#  ifndef INFTIM
#    define INFTIM -1
#  endif
#  include <mutex>
#  include <queue>
#  include <unordered_set>

namespace sandbox
{
  namespace platform
  {
    /**
     * Poll-based implementation of the Poller interface.
     *
     * Poll is the lowest-common-denominator interface.  It originated with
     * Sys V UNIX but became part of POSIX in 2001 and so is now supported
     * everywhere.  It is inefficient for large numbers of calls and so
     * exists primarily as a fallback until any given platform has an
     * implementation of this interface that uses a  less-portable but
     * more-performance system call added.
     */
    class PollPoller
    {
      /**
       * Mutex that protects the metadata about registered file descriptors.
       */
      std::mutex fds_lock;
      /**
       * Vector of all file descriptors that we're waiting for.
       */
      std::unordered_set<handle_t> fds;

      /**
       * Wrapper around a pair of fie descriptors defining endpoints of a pipe.
       * We use this to fall out of a `::poll` call after the file descriptors
       * vector has been updated.
       */
      struct pipepair
      {
        /**
         * The read end of the pipe.
         */
        int in;
        /**
         * The write end of the pipe.
         */
        int out;
        /**
         * Open the pipe and initialise the descriptors.
         */
        pipepair()
        {
          int p[2] = {-1, -1};
          pipe(p);
          in = p[0];
          out = p[1];
        }
        /**
         * Destroy the pipe by closing both descriptors.
         */
        ~pipepair()
        {
          close(in);
          close(out);
        }
      } pipes;

      /**
       * Queue of ready results from a `::poll` call.  These are cached if
       * `::poll` returns more than one ready descriptor to avoid the expensive
       * call (and its associated setup).
       */
      std::queue<pollfd> ready_fds;

      /**
       * Register a file descriptor.  This may be called from any thread.
       */
      void register_fd(handle_t socket_fd)
      {
        // With the lock held, add this to our bookkeeping metadata.
        {
          std::lock_guard g(fds_lock);
          fds.insert(socket_fd);
        }
        // Prod the polling end to wake up.
        write(pipes.out, " ", 1);
      }

      /**
       * Wait for one of the registered file descriptors to become readable.
       * This blocks and returns true if there is a message, false if an error
       * occurred.  On success, `fd` will be set to the file descriptor
       * associated with the event and `eof` will be set to true if the socket
       * has been closed at the remote end, false otherwise.
       *
       * This may be called only from a single thread.
       */
      bool poll(handle_t& fd, bool& eof)
      {
        // Put everything in a nested scope so that all destructors are run
        // before the tail call.  This allows the compiler to perform tail-call
        // elimination.
        {
          // Check if there's a cached result from a previous poll call and
          // return it if so.
          auto check_ready = [&]() {
            if (!ready_fds.empty())
            {
              auto back = ready_fds.front();
              fd = back.fd;
              eof = (back.revents & POLLHUP);
              ready_fds.pop();
              return true;
            }
            return false;
          };
          if (check_ready())
          {
            return true;
          }
          // Construct the vector of pollfd structures.
          std::vector<pollfd> pfds;
          // Add the pipe so that we can be interrupted if the list of fds
          // changes.
          pfds.push_back({pipes.in, POLLRDNORM, 0});
          {
            std::lock_guard g(fds_lock);
            for (int i : fds)
            {
              pfds.push_back({i, POLLRDNORM, 0});
            }
          }
          if (::poll(pfds.data(), pfds.size(), INFTIM) == -1)
          {
            return false;
          }
          for (auto& pfd : pfds)
          {
            // If the pipe has some data, read it out so that we don't get woken
            // up again next time.
            if ((pfd.fd == pipes.in) && (pfd.revents & POLLRDNORM))
            {
              char buf[1];
              read(pipes.in, buf, 1);
              // Don't hand this one out to the caller!
              continue;
            }
            // If we found one, push it into the cached list.
            if (pfd.revents != 0)
            {
              ready_fds.push(pfd);
            }
            // If we found an fd that is closed, do cache it so we can send the
            // eof result to the caller, but also remove it so that we don't try
            // to poll for this one again.
            if (pfd.revents & POLLHUP)
            {
              std::lock_guard g(fds_lock);
              fds.erase(pfd.fd);
            }
          }
          if (check_ready())
          {
            return true;
          }
        }
        // If we were woken up by the pipe and didn't have any other
        // notifications, try again.
        return poll(fd, eof);
      }
    };

  }
}
#endif
