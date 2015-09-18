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

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&                \
    !VMIME_USE_CYRUS_SASL

#include <sstream>

#include <gsasl.h>

#include "vmime/security/sasl/GnuSASLImpl.hpp"
#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLMechanism.hpp"

#include "vmime/base.hpp"

#include "vmime/utility/encoder/encoderFactory.hpp"

#include "vmime/utility/stream.hpp"
#include "vmime/utility/outputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamByteBufferAdapter.hpp"

#include <memory>

#define SESSION (static_cast<SASLSession<GnuSASLImpl> *>(this))

namespace vmime {
namespace security {
namespace sasl {
namespace detail {

template class SASLMechanismFactory<GnuSASLImpl>;

#ifdef GSASL_VERSION
Gsasl *GnuSASLImpl::m_gsaslContext = 0;
#else
void *GnuSASLImpl::m_gsaslContext = 0;
#endif
unsigned int GnuSASLImpl::m_contextRefCount = 0;
pthread_mutex_t GnuSASLImpl::m_saslContextMutex = PTHREAD_MUTEX_INITIALIZER;

GnuSASLImpl::GnuSASLImpl()
{
	bool fatal(false);
	pthread_mutex_lock(&m_saslContextMutex);
	if (m_gsaslContext == 0 && gsasl_init(&m_gsaslContext) != GSASL_OK)
		if (!fatal)
		{
			m_contextRefCount++;
		}
	pthread_mutex_unlock(&m_saslContextMutex);
	if (fatal)
	{
		throw std::bad_alloc();
	}
}

void GnuSASLImpl::teardownContext()
{
	pthread_mutex_lock(&m_saslContextMutex);
	if (m_contextRefCount == 0)
	{
		gsasl_done(m_gsaslContext);
		m_gsaslContext = 0;
	}
	pthread_mutex_unlock(&m_saslContextMutex);
}

void GnuSASLImpl::startSessionImpl(SASLNativeSessionType &m_gsaslSession)
{
	gsasl_client_start(m_gsaslContext,
	                   SESSION->getMechanism()->getName().c_str(),
	                   &m_gsaslSession);

	gsasl_callback_set(m_gsaslContext, gsaslCallback);
	gsasl_callback_hook_set(m_gsaslContext, this);
}

std::shared_ptr<SASLSession<GnuSASLImpl>>
GnuSASLImpl::createSessionImpl(const string &serviceName,
                               ref<authenticator> auth,
                               std::shared_ptr<SASLMechanism<GnuSASLImpl>> mech)
{
	return std::make_shared<SASLSession<GnuSASLImpl>>(serviceName, auth, mech);
}

SASLMechanismFactory<GnuSASLImpl> *GnuSASLImpl::getMechanismFactoryInstance()
{
	static SASLMechanismFactory<GnuSASLImpl> instance;
	return &instance;
}

const char *GnuSASLImpl::suggestMechanismImpl(const string &mechList)
{
	const char *suggested =
	    gsasl_client_suggest_mechanism(m_gsaslContext, mechList.c_str());
	return suggested;
}

bool GnuSASLImpl::stepImpl(SASLSession<GnuSASLImpl> &sess,
                           const byte_t *challenge, const long challengeLen,
                           byte_t **response, long *responseLen)
{
	char *output = 0;
	size_t outputLen = 0;

	const int result = gsasl_step(sess.getNativeSession(),
	                              reinterpret_cast<const char *>(challenge),
	                              challengeLen, &output, &outputLen);

	if (result == GSASL_OK || result == GSASL_NEEDS_MORE)
	{
		byte_t *res = new byte_t[outputLen];

		for (size_t i = 0; i < outputLen; ++i)
			res[i] = output[i];

		*response = res;
		*responseLen = outputLen;

		gsasl_free(output);
	}
	else
	{
		*response = 0;
		*responseLen = 0;
	}

	if (result == GSASL_OK)
	{
		// Authentication process completed
		m_complete = true;
		return true;
	}
	else if (result == GSASL_NEEDS_MORE)
	{
		// Continue authentication process
		return false;
	}
	else if (result == GSASL_MALLOC_ERROR)
	{
		throw std::bad_alloc();
	}
	else
	{
		throw exceptions::sasl_exception(
		    "Error when processing challenge: " +
		    getErrorMessageImpl("gsasl_step", result));
	}
}

bool GnuSASLImpl::isCompleteImpl() const { return m_complete; }

void GnuSASLImpl::encodeImpl(SASLSession<GnuSASLImpl> &sess,
                             const byte_t *input, const long inputLen,
                             byte_t **output, long *outputLen)
{
	char *coutput = 0;
	size_t coutputLen = 0;

	if (gsasl_encode(sess.getNativeSession(),
	                 reinterpret_cast<const char *>(input), inputLen, &coutput,
	                 &coutputLen) != GSASL_OK)
	{
		throw exceptions::sasl_exception("Encoding error.");
	}

	try
	{
		byte_t *res = new byte_t[coutputLen];

		std::copy(coutput, coutput + coutputLen, res);

		*output = res;
		*outputLen = static_cast<int>(coutputLen);
	}
	catch (...)
	{
		gsasl_free(coutput);
		throw;
	}

	gsasl_free(coutput);
}

void GnuSASLImpl::decodeImpl(SASLSession<GnuSASLImpl> &sess,
                             const byte_t *input, const long inputLen,
                             byte_t **output, long *outputLen)
{
	char *coutput = 0;
	size_t coutputLen = 0;

	try
	{
		if (gsasl_decode(sess.getNativeSession(),
		                 reinterpret_cast<const char *>(input), inputLen,
		                 &coutput, &coutputLen) != GSASL_OK)
		{
			throw exceptions::sasl_exception("Decoding error.");
		}

		byte_t *res = new byte_t[coutputLen];

		std::copy(coutput, coutput + coutputLen, res);

		*output = res;
		*outputLen = static_cast<int>(coutputLen);
	}
	catch (...)
	{
		gsasl_free(coutput);
		throw;
	}

	gsasl_free(coutput);
}

void GnuSASLImpl::getNativeMechanisms(std::vector<string> &list) const
{
	// Built-in mechanisms
	char *out = 0;

	if (gsasl_client_mechlist(m_gsaslContext, &out) == GSASL_OK)
	{
		// 'out' contains SASL mechanism names, separated by spaces
		for (char *start = out, *p = out;; ++p)
		{
			if (*p == ' ' || !*p)
			{
				list.push_back(string(start, p));
				start = p + 1;

				// End of string
				if (!*p)
					break;
			}
		}

		gsasl_free(out);
	}
}

bool GnuSASLImpl::isNativeMechanismSupported(const string &name) const
{
	return (gsasl_client_support_p(m_gsaslContext, name.c_str()) != 0);
}

// static
int GnuSASLImpl::gsaslCallback(Gsasl *ctx, Gsasl_session *sctx,
                               Gsasl_property prop)
{
	SASLSession<GnuSASLImpl> *sess =
	    reinterpret_cast<SASLSession<GnuSASLImpl> *>(
	        gsasl_callback_hook_get(ctx));
	if (!sess)
		return GSASL_AUTHENTICATION_ERROR;

	ref<authenticator> auth = sess->getAuthenticator();

	try
	{
		string res;

		switch (prop)
		{
		case GSASL_AUTHID:

			res = auth->getUsername();
			break;

		case GSASL_PASSWORD:

			res = auth->getPassword();
			break;

		case GSASL_ANONYMOUS_TOKEN:

			res = auth->getAnonymousToken();
			break;

		case GSASL_HOSTNAME:

			res = auth->getHostname();
			break;

		case GSASL_SERVICE:

			res = auth->getServiceName();
			break;

		case GSASL_AUTHZID:
		case GSASL_GSSAPI_DISPLAY_NAME:
		case GSASL_PASSCODE:
		case GSASL_SUGGESTED_PIN:
		case GSASL_PIN:
		case GSASL_REALM:

		default:

			return GSASL_NO_CALLBACK;
		}

		gsasl_property_set(sctx, prop, res.c_str());

		return GSASL_OK;
	}
	// catch (exceptions::no_auth_information&)
	catch (...)
	{
		return GSASL_NO_CALLBACK;
	}
}

// static
const string GnuSASLImpl::getErrorMessageImpl(const string &fname,
                                              const int code)
{
	string msg = fname + "() returned ";

#define ERROR(x)                                                               \
	case x:                                                                    \
		msg += #x;                                                             \
		break;

	switch (code)
	{
		ERROR(GSASL_NEEDS_MORE)
		ERROR(GSASL_UNKNOWN_MECHANISM)
		ERROR(GSASL_MECHANISM_CALLED_TOO_MANY_TIMES)
		ERROR(GSASL_MALLOC_ERROR)
		ERROR(GSASL_BASE64_ERROR)
		ERROR(GSASL_CRYPTO_ERROR)
		ERROR(GSASL_SASLPREP_ERROR)
		ERROR(GSASL_MECHANISM_PARSE_ERROR)
		ERROR(GSASL_AUTHENTICATION_ERROR)
		ERROR(GSASL_INTEGRITY_ERROR)
		ERROR(GSASL_NO_CLIENT_CODE)
		ERROR(GSASL_NO_SERVER_CODE)
		ERROR(GSASL_NO_CALLBACK)
		ERROR(GSASL_NO_ANONYMOUS_TOKEN)
		ERROR(GSASL_NO_AUTHID)
		ERROR(GSASL_NO_AUTHZID)
		ERROR(GSASL_NO_PASSWORD)
		ERROR(GSASL_NO_PASSCODE)
		ERROR(GSASL_NO_PIN)
		ERROR(GSASL_NO_SERVICE)
		ERROR(GSASL_NO_HOSTNAME)
		ERROR(GSASL_GSSAPI_RELEASE_BUFFER_ERROR)
		ERROR(GSASL_GSSAPI_IMPORT_NAME_ERROR)
		ERROR(GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR)
		ERROR(GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR)
		ERROR(GSASL_GSSAPI_UNWRAP_ERROR)
		ERROR(GSASL_GSSAPI_WRAP_ERROR)
		ERROR(GSASL_GSSAPI_ACQUIRE_CRED_ERROR)
		ERROR(GSASL_GSSAPI_DISPLAY_NAME_ERROR)
		ERROR(GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR)
		ERROR(GSASL_KERBEROS_V5_INIT_ERROR)
		ERROR(GSASL_KERBEROS_V5_INTERNAL_ERROR)
		ERROR(GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE)
		ERROR(GSASL_SECURID_SERVER_NEED_NEW_PIN)

	default:

		msg += "unknown error";
		break;
	}

#undef ERROR

	return msg;
}

#ifndef VMIME_DO_NOT_HAVE_NATIVE_BASE64_CODECS
// static
void GnuSASLImpl::decodeB64(const string &input, byte_t **output,
                            long *outputLen)
{
	size_t outlen = 0;
	gsasl_base64_from(input.c_str(), input.size(), (char **)output, &outlen);
	*outputLen = outlen;
}

// static
const string GnuSASLImpl::encodeB64(const byte_t *input, const long inputLen)
{
	size_t outlen;
	size_t inLen = inputLen;
	char *outbuf = NULL;
	gsasl_base64_to((const char *)input, inLen, &outbuf, &outlen);
	string encodedStr(outbuf);
	free(outbuf);
	return encodedStr;
}

#else
// static
void GnuSASLImpl::decodeB64(const string &input, byte_t **output,
                            long *outputLen)
{
	string res;

	utility::inputStreamStringAdapter is(input);
	utility::outputStreamStringAdapter os(res);

	ref<utility::encoder::encoder> dec =
	    utility::encoder::encoderFactory::getInstance()->create("base64");

	dec->decode(is, os);

	byte_t *out = new byte_t[res.length()];

	std::copy(res.begin(), res.end(), out);

	*output = out;
	*outputLen = res.length();
}

// static
const string GnuSASLImpl::encodeB64(const byte_t *input, const long inputLen)
{
	string res;

	utility::inputStreamByteBufferAdapter is(input, inputLen);
	utility::outputStreamStringAdapter os(res);

	ref<utility::encoder::encoder> enc =
	    utility::encoder::encoderFactory::getInstance()->create("base64");

	enc->encode(is, os);

	return res;
}

#endif

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&
       // VMIME_HAVE_GNU_SASL
