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

#include "vmime/config.hpp"
#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "SASLContext.hpp"

#include "vmime/types.hpp"

#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLMechanismFactory.hpp"
#include <sstream>

#ifdef __APPLE__
#include <pthread.h>
#endif

#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/base.hpp"

#include "vmime/utility/encoder/encoderFactory.hpp"
#include "vmime/utility/stream.hpp"
#include "vmime/utility/outputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamStringAdapter.hpp"
#include "vmime/utility/inputStreamByteBufferAdapter.hpp"
#include <memory>

#define SHARED_THIS (dynamicCast<SASLContext<SASLImpl>>(shared_from_this()))
namespace vmime {
namespace security {
namespace sasl {
namespace detail {

template <typename SASLImpl>
SASLContext<SASLImpl>::~SASLContext() { this->teardownContext(); }

template <typename SASLImpl>
SASLContext<SASLImpl>::SASLContext() { ; }

template <typename SASLImpl>
shared_ptr<SASLSession<SASLImpl>>
SASLContext<SASLImpl>::createSession(const string &serviceName, shared_ptr<authenticator> auth,
              shared_ptr<SASLMechanism<SASLImpl>> mech)
{
	return this->createSessionImpl(serviceName, auth, mech);
}

template <typename SASLImpl>
shared_ptr<SASLMechanism<SASLImpl>> SASLContext<SASLImpl>::createMechanism(const string &name)
{
	SASLMechanismFactory<SASLImpl> *mechFactoryPtr(SASLMechanismFactory<SASLImpl>::getInstance());
	return mechFactoryPtr->create(SHARED_THIS, name);
}

template <typename SASLImpl>
shared_ptr<SASLMechanism<SASLImpl>>
SASLContext<SASLImpl>::suggestMechanism(const std::vector<shared_ptr<SASLMechanism<SASLImpl>>> &mechs)
{
	if (mechs.empty())
		return 0;

	std::ostringstream oss;

	for (unsigned int i = 0; i < mechs.size(); ++i)
		oss << mechs[i]->getName() << " ";

	const string mechList = oss.str();
	SASLImpl &impl = *this;
	const auto &suggested = impl.suggestMechanismImpl(mechs);

	if (suggested)
	{
		for (unsigned int i = 0; i < mechs.size(); ++i)
		{
			if (mechs[i]->getName() == suggested->getName())
				return mechs[i];
		}
	}

	return 0;
}

template <typename SASLImpl>
void SASLContext<SASLImpl>::decodeB64(const string& input, byte_t** output, size_t* outputLen)
{
	string res;

	utility::inputStreamStringAdapter is(input);
	utility::outputStreamStringAdapter os(res);

	shared_ptr <utility::encoder::encoder> dec =
		utility::encoder::encoderFactory::getInstance()->create("base64");

	dec->decode(is, os);

	byte_t* out = new byte_t[res.length()];

	copy(res.begin(), res.end(), out);

	*output = out;
	*outputLen = res.length();
}


template <typename SASLImpl>
const string SASLContext<SASLImpl>::encodeB64(const byte_t* input, const size_t inputLen)
{
	string res;

	utility::inputStreamByteBufferAdapter is(input, inputLen);
	utility::outputStreamStringAdapter os(res);

	shared_ptr <utility::encoder::encoder> enc =
		utility::encoder::encoderFactory::getInstance()->create("base64");

	enc->encode(is, os);

	return res;
}



template <typename SASLImpl>
const string SASLContext<SASLImpl>::getErrorMessage(const string &fname, const int code)
{
	return SASLImpl::getErrorMessageImpl(fname, code);
}

template class VMIME_EXPORT SASLContext<SASLImplementation>;

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT
