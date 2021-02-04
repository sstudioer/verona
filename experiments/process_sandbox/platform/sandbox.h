// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#pragma once

/**
 * This file contains the definition of a per-platform sandboxing policy.
 * Because this interface currently has only one implementation, it is almost
 * certainly the wrong abstraction and will change when others (e.g.
 * seccomp-bpf) are added.
 */

#include "sandbox_capsicum.h"

namespace sandbox
{
  namespace platform
  {
    struct SandboxNoOp
    {
      template<typename T, typename U>
      void restrict_file_descriptors(const T&, const U&)
      {}

      void apply_sandboxing_policy() {}
    };

    using Sandbox =
#ifdef USE_CAPSICUM
      SandboxCapsicum
#else
      SandboxNoOp
#endif
      ;
  }
}
