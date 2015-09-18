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

#ifndef VMIME_SECURITY_SASL_SASLSESSION_HPP_INCLUDED
#define VMIME_SECURITY_SASL_SASLSESSION_HPP_INCLUDED

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "vmime/security/sasl/SASLCommon.hpp"
#include "vmime/base.hpp"

namespace vmime {

namespace net { class socket; }

namespace security {
namespace sasl {
namespace detail {

template <class T> class SASLContext;

/** An SASL client session.
 */
template <class SASLImpl>
class VMIME_EXPORT SASLSession : public SASLImpl, public object
{
	template <class T> friend class builtinSASLMechanism;
	template <class T> friend class SASLSocket;

  public:
	~SASLSession();

	/** Construct a new SASL session.
	 *
	 * @param serviceName name of the service using this session
	 * @param ctx SASL context
	 * @param auth authenticator to use for this session
	 * @param mech SASL mechanism
	 */
	SASLSession(const string &serviceName, shared_ptr<authenticator> auth,
	            std::shared_ptr<SASLMechanism<SASLImpl>> mech);

	/** Initialize this SASL session. This must be called before
	 * calling any other method on this object (except accessors).
	 */
	void init();

	/** Return the authenticator used for this session. This is the
	 * authenticator which has been previously set with a call to
	 * setAuthenticator().
	 *
	 * @return authenticator object
	 */
	shared_ptr<authenticator> getAuthenticator();

	/** Return the mechanism used for this session.
	 *
	 * @return SASL mechanism
	 */
	std::shared_ptr<SASLMechanism<SASLImpl>> getMechanism();

	/** Perform one step of SASL authentication. Accept data from the
	 * server (challenge), process it and return data to be returned
	 * in response to the server.
	 *
	 * If the challenge is empty (challengeLen == 0), the initial
	 * response is returned, if the mechanism has one.
	 *
	 * @param challenge challenge sent from the server
	 * @param challengeLen length of challenge
	 * @param response response to send to the server (allocated by
	 * this function, free with delete[])
	 * @param responseLen length of response buffer
	 * @return true if authentication terminated successfully, or
	 * false if the authentication process should continue
	 * @throw exceptions::sasl_exception if an error occured during
	 * authentication (in this case, the values in 'response' and
	 * 'responseLen' are undetermined)
	 */
	bool evaluateChallenge(const byte_t *challenge, const size_t challengeLen,
	                       byte_t **response, size_t *responseLen);

	/** Return a socket in which transmitted data is integrity
	 * and/or privacy protected, depending on the QOP (Quality of
	 * Protection) negotiated during the SASL authentication.
	 *
	 * @param sok socket to wrap
	 * @return secured socket
	 */
	shared_ptr<net::socket> getSecuredSocket(shared_ptr<net::socket> sok);

	/** Return the name of the service which is using this
	 * SASL session (eg. "imap"). This value should be returned
	 * by the authenticator when INFO_SERVICE is requested.
	 *
	 * @return service name
	 */
	const string getServiceName() const;

	typename SASLImpl::SASLNativeSessionType getNativeSession();

  private:
	const string m_serviceName;

	shared_ptr<authenticator> m_auth;
	shared_ptr<SASLMechanism<SASLImpl>> m_mech;

	typename SASLImpl::SASLNativeSessionType m_nativeSession;
};

extern template class VMIME_EXPORT SASLSession<SASLImplementation>;

} // detail

using SASLSession = detail::SASLSession<SASLImplementation>;

} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#endif // VMIME_SECURITY_SASL_SASLSESSION_HPP_INCLUDED
