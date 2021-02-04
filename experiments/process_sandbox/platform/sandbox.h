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
