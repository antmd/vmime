//
// VMime library (http://www.vmime.org)
// Copyright (C) 2002-2009 Vincent Richard <vincent@vincent-richard.net>
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

#ifndef VMIME_SECURITY_SASL_GnuSASLImpl_HPP_INCLUDED
#define VMIME_SECURITY_SASL_GnuSASLImpl_HPP_INCLUDED

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&                \
    !VMIME_USE_CYRUS_SASL

#include <gsasl.h>
#include <map>

#include "vmime/types.hpp"

#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLMechanismFactory.hpp"
#include "vmime/security/sasl/SASLContext.hpp"

namespace vmime {
namespace security {
namespace sasl {
namespace detail {

/** An SASL client context.
 */
class GnuSASLImpl
{
	template <class T> friend class SASLSession;
	template <class T> friend class builtinSASLMechanism;
	friend class SASLSession<GnuSASLImpl>;

  public:
	/** Construct and initialize a new SASL context.
	 */
	GnuSASLImpl();
#ifdef GSASL_VERSION
	typedef Gsasl_session *SASLNativeSessionType;
#else
	typedef void *SASLNativeSessionType;
#endif // GSASL_VERSION
	void startSessionImpl(SASLNativeSessionType &m_gsaslSession);
	void stopSessionImpl();
	void teardownContext();

	void getNativeMechanisms(std::vector<string> &list) const;
	bool isNativeMechanismSupported(const string &name) const;

	/** Create and initialize a new SASL session.
	 *
	 * @param serviceName name of the service which will use the session
	 * @param auth authenticator object to use during the session
	 * @param mech SASL mechanism
	 * @return a new SASL session
	 */
	std::shared_ptr<SASLSession<GnuSASLImpl>>
	createSessionImpl(const string &serviceName, ref<authenticator> auth,
	                  std::shared_ptr<SASLMechanism<GnuSASLImpl>> mech);

	/** Create an instance of an SASL mechanism.
	 *
	 * @param name mechanism name
	 * @return a new instance of the specified SASL mechanism
	 * @throw exceptions::no_such_mechanism if no mechanism is
	 * registered for the specified name
	 */
	std::shared_ptr<SASLMechanism<GnuSASLImpl>>
	createMechanismImpl(const string &name);

	/** Suggests an SASL mechanism among a set of mechanisms
	 * supported by the server.
	 *
	 * @param mechs list of mechanisms
	 * @return suggested mechanism (usually the safest mechanism
	 * supported by both the client and the server)
	 */
	const char *suggestMechanismImpl(const string &mechList);

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
	bool stepImpl(SASLSession<GnuSASLImpl> &sess, const byte_t *challenge,
	              const long challengeLen, byte_t **response,
	              long *responseLen);

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
	void encodeImpl(SASLSession<GnuSASLImpl> &sess, const byte_t *input,
	                const long inputLen, byte_t **output, size_t *outputLen);

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
	void decodeImpl(SASLSession<GnuSASLImpl> &sess, const byte_t *input,
	                const long inputLen, byte_t **output, size_t *outputLen);

	/** Helper function for decoding Base64-encoded challenge.
	 *
	 * @param input input buffer
	 * @param output output buffer
	 * @param outputLen length of output buffer
	 */
	static void decodeB64(const string &input, byte_t **output,
	                      size_t *outputLen);

	/** Helper function for encoding challenge in Base64.
	 *
	 * @param input input buffer
	 * @param inputLen length of input buffer
	 * @return Base64-encoded challenge
	 */
	static const string encodeB64(const byte_t *input, const size_t inputLen);

	static SASLMechanismFactory<GnuSASLImpl> *getMechanismFactoryInstance();

  public:
	static unsigned int m_contextRefCount;
	static pthread_mutex_t m_saslContextMutex;
#ifdef GSASL_VERSION
	Gsasl* m_gsaslContext;
	Gsasl_session* m_gsaslSession;

	static int gsaslCallback(Gsasl* ctx, Gsasl_session* sctx, Gsasl_property prop);
#else
	void* m_gsaslContext;
	void* m_gsaslSession;

	static int gsaslCallback(void* ctx, void* sctx, int prop);
#endif // GSASL_VERSION

	/** Authentication process status. */
	bool m_complete;

  protected:
	static const string getErrorMessageImpl(const string &fname,
	                                        const int code);
	~GnuSASLImpl() {}
};

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&
       // VMIME_HAVE_GNU_SASL

#endif // VMIME_SECURITY_SASL_SASLCONTEXT_HPP_INCLUDED
