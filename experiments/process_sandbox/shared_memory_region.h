// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#ifdef __unix__
#  include <pthread.h>
#endif

namespace sandbox
{
  /**
   * Class representing a view of a shared memory region.  This provides both
   * the parent and child views of the region.
   */
  struct SharedMemoryRegion
  {
    /**
     * The start of the sandbox region.  Note: This is writeable from within
     * the sandbox and should not be trusted outside.
     */
    void* start;

    /**
     * The end of the sandbox region.  Note: This is writeable from within
     * the sandbox and should not be trusted outside.
     */
    void* end;

    /**
     * A flag indicating that the parent has instructed the sandbox to exit.
     */
    std::atomic<bool> should_exit = false;
    /**
     * The index of the function currently being called.  This interface is not
     * currently reentrant.
     */
    int function_index;
    /**
     * A pointer to the tuple (in the shared memory range) that contains the
     * argument frame provided by the sandbox caller.
     */
    void* msg_buffer = nullptr;
    /**
     * The message queue for the parent's allocator.  This is stored in the
     * shared region because the child must be able to free memory allocated by
     * the parent.
     */
    snmalloc::RemoteAllocator allocator_state;
#ifdef __unix__
    /**
     * Mutex used to protect `cv`.
     */
    pthread_mutex_t mutex;
    /**
     * The condition variable that the child sleeps on when waiting for
     * messages from the parent.
     */
    pthread_cond_t cv;
    /**
     * Flag indicating whether the child is executing.  Set on startup and
     */
    std::atomic<bool> is_child_executing = false;
#endif
    /**
     * Waits until the `is_child_executing` flag is in the `expected` state.
     * This is used to wait for the child to start and to stop.
     */
    void wait(bool expected)
    {
      pthread_mutex_lock(&mutex);
      while (expected != is_child_executing)
      {
        pthread_cond_wait(&cv, &mutex);
      }
      pthread_mutex_unlock(&mutex);
    }
    /**
     * Wait until the `is_child_executing` flag is in the `expected` state.
     * Returns true if the condition was met or false if the timeout was
     * exceeded before the child entered the desired state.
     */
    bool wait(bool expected, struct timespec timeout)
    {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      long nsec;
      time_t carry =
        __builtin_add_overflow(now.tv_nsec, timeout.tv_nsec, &nsec);
      timeout.tv_nsec = nsec;
      timeout.tv_sec += now.tv_sec + carry;
      pthread_mutex_lock(&mutex);
      pthread_cond_timedwait(&cv, &mutex, &timeout);
      bool ret = expected == is_child_executing;
      pthread_mutex_unlock(&mutex);
      return ret;
    }

    /**
     * Update the `is_child_executing` flag and wake up any waiters.  Note that
     * the `wait` functions will only unblock if `is_child_executing` is
     * modified using this function.
     */
    void signal(bool new_state)
    {
      pthread_mutex_lock(&mutex);
      is_child_executing = new_state;
      pthread_cond_signal(&cv);
      pthread_mutex_unlock(&mutex);
    }

    /**
     * Constructor.  Initialises the mutex and condition variables.
     */
    SharedMemoryRegion()
    {
      pthread_mutexattr_t mattrs;
      pthread_mutexattr_init(&mattrs);
      pthread_mutexattr_setpshared(&mattrs, PTHREAD_PROCESS_SHARED);
      pthread_mutex_init(&mutex, &mattrs);
      pthread_condattr_t cvattrs;
      pthread_condattr_init(&cvattrs);
      pthread_condattr_setpshared(&cvattrs, PTHREAD_PROCESS_SHARED);
      pthread_condattr_setclock(&cvattrs, CLOCK_MONOTONIC);
      pthread_cond_init(&cv, &cvattrs);
    }

    /**
     * Tear down the parent-owned contents of this shared memory region.
     */
    void destroy()
    {
      pthread_mutex_destroy(&mutex);
      pthread_cond_destroy(&cv);
    }
  };
}
