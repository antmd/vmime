//
// VMime library (http://www.vmime.org)
// Copyright (C) 2002-2013 Vincent Richard <vincent@vmime.org>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of
// the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// Linking this library statically or dynamically with other modules is making
// a combined work based on this library.  Thus, the terms and conditions of
// the GNU General Public License cover the whole combination.
//

#include "SASLSession.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "vmime/security/sasl/SASLAuthenticator.hpp"
#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/security/sasl/SASLSocket.hpp"

#define SHARED_THIS (dynamicCast<SASLSession<SASLImpl>>(shared_from_this()))

namespace vmime {
namespace security {
namespace sasl {
namespace detail {


template <class SASLImpl>
SASLSession<SASLImpl>::~SASLSession()
{
	this->teardownContext();
	m_nativeSession = 0;
}

template <class SASLImpl>
SASLSession<SASLImpl>::SASLSession(
    const string &serviceName, shared_ptr<authenticator> auth,
    std::shared_ptr<SASLMechanism<SASLImpl>> mech)
    : m_serviceName(serviceName), m_auth(auth), m_mech(mech)
{
	this->startSessionImpl();
}

template <class SASLImpl> void SASLSession<SASLImpl>::init()
{
	shared_ptr<SASLAuthenticator<SASLImpl>> saslAuth =
	    dynamicCast<SASLAuthenticator<SASLImpl>>(m_auth);

	if (saslAuth)
	{
		saslAuth->setSASLMechanism(m_mech);
		saslAuth->setSASLSession(SHARED_THIS);
	}
}

template <class SASLImpl>
shared_ptr<authenticator> SASLSession<SASLImpl>::getAuthenticator()
{
	return m_auth;
}

template <class SASLImpl>
std::shared_ptr<SASLMechanism<SASLImpl>> SASLSession<SASLImpl>::getMechanism()
{
	return m_mech;
}

template <class SASLImpl>
bool SASLSession<SASLImpl>::evaluateChallenge(const byte_t *challenge,
                                              const size_t challengeLen,
                                              byte_t **response,
                                              size_t *responseLen)
{
	return m_mech->step(SHARED_THIS, challenge, challengeLen, response, responseLen);
}

template <class SASLImpl>
shared_ptr<net::socket>
SASLSession<SASLImpl>::getSecuredSocket(shared_ptr<net::socket> sok)
{
	return make_shared<SASLSocket<SASLImpl>>(SHARED_THIS, sok);
}

template <class SASLImpl>
const string SASLSession<SASLImpl>::getServiceName() const
{
	return m_serviceName;
}

template <class SASLImpl>
typename SASLImpl::SASLNativeSessionType
SASLSession<SASLImpl>::getNativeSession()
{
	return m_nativeSession;
}

template class VMIME_EXPORT SASLSession<SASLImplementation>;

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT
