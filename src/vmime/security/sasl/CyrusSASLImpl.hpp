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

#ifndef VMIME_SECURITY_SASL_CyrusSASLImpl_HPP_INCLUDED
#define VMIME_SECURITY_SASL_CyrusSASLImpl_HPP_INCLUDED

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&                \
    VMIME_USE_CYRUS_SASL

#include <sasl/sasl.h>
#include "vmime/types.hpp"

namespace vmime {
namespace security {

class authenticator;

namespace sasl {
namespace detail {

template <typename T> class SASLSession;
template <typename T> class SASLMechanism;

/** An SASL client context.
 */
class VMIME_EXPORT CyrusSASLImpl
{
	template <class T> friend class SASLSession;
	template <class T> friend class SASLContext;
	template <class T> friend class builtinSASLMechanism;

  public:
	using SASLNativeSessionType = sasl_conn_t*; 

	void teardownContext();
	void startSessionImpl();
	void stopSessionImpl();

	bool isMechanismSupportedImpl(const string &name) const;

	/** Construct and initialize a new SASL context.
	 */
	CyrusSASLImpl();

	/** Create and initialize a new SASL session.
	 *
	 * @param serviceName name of the service which will use the session
	 * @param auth authenticator object to use during the session
	 * @param mech SASL mechanism
	 * @return a new SASL session
	 */
	shared_ptr<SASLSession<CyrusSASLImpl>>
	createSessionImpl(const string &serviceName, shared_ptr<authenticator> auth,
	                  shared_ptr<SASLMechanism<CyrusSASLImpl>> mech);


	/** Suggests an SASL mechanism among a set of mechanisms
	 * supported by the server.
	 *
	 * @param mechs list of mechanisms
	 * @return suggested mechanism (usually the safest mechanism
	 * supported by both the client and the server)
	 */
	shared_ptr<SASLMechanism<CyrusSASLImpl>> suggestMechanismImpl(
	    const std::vector<shared_ptr<SASLMechanism<CyrusSASLImpl>>> &mechs);

//------------------------------------------------------------------------------------------
#pragma mark - SASL Mechanism
	//------------------------------------------------------------------------------------------

	/** Perform one step of SASL authentication. Accept data from the
	 * server (challenge), process it and return data to be returned
	 * in response to the server.
	 *
	 * @param sess SASL session
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
	bool stepImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
	              const byte_t *challenge, const size_t challengeLen,
	              byte_t **response, size_t *responseLen);

	/** Check whether authentication has completed. If false, more
	 * calls to evaluateChallenge() are needed to complete the
	 * authentication process).
	 *
	 * @return true if the authentication has finished, or false
	 * otherwise
	 */
	bool isCompleteImpl() const;

	/** Encode data according to negotiated SASL mechanism. This
	 * might mean that data is integrity or privacy protected.
	 *
	 * @param sess SASL session
	 * @param input input buffer
	 * @param inputLen length of input buffer
	 * @param output output buffer (allocated bu the function,
	 * free with delete[])
	 * @param outputLen length of output buffer
	 * @throw exceptions::sasl_exception if an error occured during
	 * the encoding of data (in this case, the values in 'output' and
	 * 'outputLen' are undetermined)
	 */
	void encodeImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
	                const byte_t *input, const size_t inputLen, byte_t **output,
	                size_t *outputLen);

	/** Decode data according to negotiated SASL mechanism. This
	 * might mean that data is integrity or privacy protected.
	 *
	 * @param sess SASL session
	 * @param input input buffer
	 * @param inputLen length of input buffer
	 * @param output output buffer (allocated bu the function,
	 * free with delete[])
	 * @param outputLen length of output buffer
	 * @throw exceptions::sasl_exception if an error occured during
	 * the encoding of data (in this case, the values in 'output' and
	 * 'outputLen' are undetermined)
	 */
	void decodeImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
	                const byte_t *input, const size_t inputLen, byte_t **output,
	                size_t *outputLen);

        std::vector<string> getNativeMechanisms(shared_ptr<SASLSession<CyrusSASLImpl>> sess) const;
        
  private:
	static const string getErrorMessageImpl(const string &fname,
	                                        const int code);

};

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&
       // VMIME_HAVE_CYRUS_SASL

#endif // VMIME_SECURITY_SASL_SASLCONTEXT_HPP_INCLUDED
