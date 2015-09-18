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

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&                \
    VMIME_USE_CYRUS_SASL

#include "CyrusSASLImpl.hpp"

#include <sstream>

#include <sasl/sasl.h>
#include <pthread.h>

#include "vmime/security/sasl/CyrusSASLImpl.hpp"
#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/security/sasl/SASLContext.hpp"
#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLMechanismFactory.hpp"

#include "vmime/base.hpp"

#include "vmime/utility/encoder/encoderFactory.hpp"

#include "vmime/utility/stream.hpp"
#include "vmime/utility/stringUtils.hpp"
#include "vmime/utility/outputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamByteBufferAdapter.hpp"

static unsigned int saslRefs = 0;
static pthread_mutex_t saslContextMutex = PTHREAD_MUTEX_INITIALIZER;
static int getsecret_func(sasl_conn_t *conn,
                          void *context __attribute__((unused)), int id,
                          sasl_secret_t **psecret)
{
	return SASL_OK;
}

static int getauthname_func(void *context, int id, const char **result,
                            unsigned *len)
{
	if (id != SASL_CB_AUTHNAME)
		return SASL_FAIL;

	return SASL_OK;
}

/* callbacks we support. This is a global variable at the
 top of the program */
static sasl_callback_t callbacks[] = {
    {
        SASL_CB_GETREALM, NULL,
        NULL /* we'll just use an interaction if this comes up */
    },
    {
        SASL_CB_USER, NULL,
        NULL /* we'll just use an interaction if this comes up */
    },
    {
        SASL_CB_AUTHNAME, (int (*)()) & getauthname_func,
        NULL /* A mechanism should call getauthname_func
              if it needs the authentication name */
    },
    {
        SASL_CB_PASS, (int (*)()) & getsecret_func,
        NULL /* Call getsecret_func if need secret */
    },
    {SASL_CB_LIST_END, NULL, NULL}};




namespace vmime {
namespace security {
namespace sasl {
namespace detail {

CyrusSASLImpl::CyrusSASLImpl()
{
	int saslResult = SASL_OK;
	pthread_mutex_lock(&saslContextMutex);
	if (saslRefs == 0)
	{
		saslResult = sasl_client_init(NULL);
	}
	saslRefs++;
	pthread_mutex_unlock(&saslContextMutex);
	if (saslResult != SASL_OK)
	{
		throw std::bad_alloc();
	}
}

void CyrusSASLImpl::teardownContext()
{
	pthread_mutex_lock(&saslContextMutex);
	if (--saslRefs == 0)
	{
		/* This should not be called, due to a bug in Cyrus SASL */

		// sasl_done();
	}
	pthread_mutex_unlock(&saslContextMutex);
}

shared_ptr<SASLSession<CyrusSASLImpl>>
CyrusSASLImpl::createSessionImpl(const string &serviceName,
                                 shared_ptr<authenticator> auth,
                                 shared_ptr<SASLMechanism<CyrusSASLImpl>> mech)
{
	return make_shared<SASLSession<CyrusSASLImpl>>(serviceName, auth, mech);
}


bool CyrusSASLImpl::isMechanismSupportedImpl(const string &name) const
{
	// TODO
}


shared_ptr<SASLMechanism<CyrusSASLImpl>> CyrusSASLImpl::suggestMechanismImpl(
    const std::vector<shared_ptr<SASLMechanism<CyrusSASLImpl>>> &mechs)
{
	if (mechs.empty())
		return 0;

	static const char *sPreferredMechNames[] = {"EXTERNAL", "ANONYMOUS", NULL};
	std::vector<std::string> mechNamesVec;
	for (unsigned int i = 0; i < mechs.size(); ++i)
	{
		mechNamesVec.push_back(mechs[i]->getName());
	}

	long mechIdx = -1;
	std::vector<std::string>::const_iterator it;

	for (unsigned int i = 0; sPreferredMechNames[i] != NULL; ++i)
	{
		if ((it = std::find(mechNamesVec.begin(), mechNamesVec.end(),
		                    sPreferredMechNames[i])) != mechNamesVec.end())
		{
			mechIdx = std::distance(mechNamesVec.cbegin(), it);
			break;
		}
	}
	return (mechIdx >= 0) ? mechs[mechIdx] : 0;
}

void CyrusSASLImpl::startSessionImpl()
{
	// TODO
}

void CyrusSASLImpl::stopSessionImpl()
{
	// TODO
}

std::vector<string>
CyrusSASLImpl::getNativeMechanisms(shared_ptr<SASLSession<CyrusSASLImpl>> sess) const
{
        const char *list = nullptr;
        unsigned num_chars = 0;
        int num_mechs = 0;
        
    int result = sasl_listmech(
              sess->getNativeSession()
              , nullptr /*user -- not used*/
              , "" /*prefix*/
              , ";" /*sep*/
              , "" /*suffix*/
              , &list /* *result*/
              , &num_chars /*plen*/
              , &num_mechs /*pcount*/);
        
        if (result == SASL_OK && num_mechs > 0) {
                std::vector<string> mechs = utility::stringUtils::splitString(string(list), ";");
                return mechs;
        }
        return {};
}

bool CyrusSASLImpl::stepImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
                             const byte_t *challenge, const size_t challengeLen,
                             byte_t **response, size_t* responseLen)
{
	// TODO
}

bool CyrusSASLImpl::isCompleteImpl() const
{
	// TODO
}

void CyrusSASLImpl::encodeImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
                               const byte_t *input, const size_t inputLen,
                               byte_t **output, size_t *outputLen)
{
	// TODO
}

void CyrusSASLImpl::decodeImpl(shared_ptr<SASLSession<CyrusSASLImpl>> sess,
                               const byte_t *input, const size_t inputLen,
                               byte_t **output, size_t *outputLen)
{
	// TODO
}

const string CyrusSASLImpl::getErrorMessageImpl(const string &fname,
                                                const int code)
{
	string msg = fname + "() returned ";

#define ERROR(x)                                                               \
	case x:                                                                    \
		msg += #x;                                                             \
		break;

	switch (code)
	{
		ERROR(SASL_CONTINUE)
		ERROR(SASL_OK)
		ERROR(SASL_FAIL)
		ERROR(SASL_NOMEM)
		ERROR(SASL_BUFOVER)
		ERROR(SASL_NOMECH)
		ERROR(SASL_BADPROT)
		ERROR(SASL_NOTDONE)
		ERROR(SASL_BADPARAM)
		ERROR(SASL_TRYAGAIN)
		ERROR(SASL_BADMAC)
		ERROR(SASL_NOTINIT)
		ERROR(SASL_INTERACT)
		ERROR(SASL_BADSERV)
		ERROR(SASL_WRONGMECH)
		ERROR(SASL_BADAUTH)
		ERROR(SASL_NOAUTHZ)
		ERROR(SASL_TOOWEAK)
		ERROR(SASL_ENCRYPT)
		ERROR(SASL_TRANS)
		ERROR(SASL_EXPIRED)
		ERROR(SASL_DISABLED)
		ERROR(SASL_NOUSER)
		ERROR(SASL_BADVERS)
		ERROR(SASL_UNAVAIL)
		ERROR(SASL_NOVERIFY)
		ERROR(SASL_PWLOCK)
		ERROR(SASL_NOCHANGE)
		ERROR(SASL_WEAKPASS)
		ERROR(SASL_NOUSERPASS)

	default:

		msg += "unknown error";
		break;
	}

#undef ERROR

	return msg;
}

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT &&
       // VMIME_HAVE_CYRUS_SASL
