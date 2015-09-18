//
//  SASLImpl.hpp
//  vmime
//
//  Created by Ant on 13/04/2013.
//
//

#ifndef vmime_SASLImpl_hpp
#define vmime_SASLImpl_hpp

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "vmime/security/sasl/SASLContext.hpp"
#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLSocket.hpp"
#include "vmime/security/sasl/SASLAuthenticator.hpp"
#include "vmime/security/sasl/SASLMechanismFactory.hpp"
#include "vmime/security/sasl/builtinSASLMechanism.hpp"
#include "vmime/security/sasl/defaultSASLAuthenticator.hpp"

#if VMIME_HAVE_GNU_SASL
#include "vmime/security/sasl/GnuSASLImpl.hpp"
using vmime::security::sasl::detail::GnuSASLImpl;
#endif

#if VMIME_HAVE_CYRUS_SASL
#include "vmime/security/sasl/CyrusSASLImpl.hpp"
using vmime::security::sasl::detail::CyrusSASLImpl;
#endif

namespace vmime { namespace security { namespace sasl {
    typedef detail::SASLSession<SASL_POLICY> SASLSession;
    typedef detail::SASLContext<SASL_POLICY> SASLContext;
    typedef detail::SASLMechanism<SASL_POLICY> SASLMechanism;
    typedef detail::SASLSocket<SASL_POLICY> SASLSocket;
    typedef detail::SASLAuthenticator<SASL_POLICY> SASLAuthenticator;
    typedef detail::SASLMechanismFactory<SASL_POLICY> SASLMechanismFactory;
    typedef detail::builtinSASLMechanism<SASL_POLICY> builtinSASLMechanism;
    typedef detail::defaultSASLAuthenticator<SASL_POLICY> defaultSASLAuthenticator;
    
} } }
#endif 

#endif
