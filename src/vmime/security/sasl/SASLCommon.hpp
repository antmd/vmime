#pragma once

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#if VMIME_USE_CYRUS_SASL
#include "CyrusSASLImpl.hpp"
namespace vmime { namespace security { namespace sasl {
using SASLImplementation = vmime::security::sasl::detail::CyrusSASLImpl;
}}}
#else
#include "GnuSASLImpl.hpp"
namespace vmime { namespace security { namespace sasl {
using SASLImplementation = vmime::security::sasl::detail::GnuSASLImpl;
}}}
#endif


#endif
