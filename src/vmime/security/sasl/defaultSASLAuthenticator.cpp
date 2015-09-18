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

#include "defaultSASLAuthenticator.hpp"
#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "SASLSession.hpp"
#include "SASLMechanism.hpp"

#include <memory>

namespace vmime {
namespace security {
namespace sasl {
namespace detail {

template <class SASLImpl>
const std::vector<std::shared_ptr<SASLMechanism<SASLImpl>>>
defaultSASLAuthenticator<SASLImpl>::getAcceptableMechanisms(
    const std::vector<std::shared_ptr<SASLMechanism<SASLImpl>>> &available,
    std::shared_ptr<SASLMechanism<SASLImpl>> suggested) const
{
	if (suggested)
	{
		std::vector<std::shared_ptr<SASLMechanism<SASLImpl>>> res;

		res.push_back(suggested);

		for (unsigned int i = 0; i < available.size(); ++i)
		{
			if (available.at(i)->getName() != suggested->getName())
				res.push_back(available[i]);
		}

		return res;
	}
	else
	{
		return available;
	}
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getUsername() const
{
	return m_default.getUsername();
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getPassword() const
{
	return m_default.getPassword();
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getHostname() const
{
	return m_default.getHostname();
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getAnonymousToken() const
{
	return m_default.getAnonymousToken();
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getAccessToken() const
{
	return m_default.getAccessToken();
}

template <class SASLImpl>
const string defaultSASLAuthenticator<SASLImpl>::getServiceName() const
{
	return m_session.lock()->getServiceName();
}

template <class SASLImpl>
void defaultSASLAuthenticator<SASLImpl>::setSASLSession(
    std::shared_ptr<SASLSession<SASLImpl>> sess)
{
	m_session = sess;
}

template <class SASLImpl>
void defaultSASLAuthenticator<SASLImpl>::setService(
    shared_ptr<net::service> serv)
{
	m_service = serv;
	m_default.setService(serv);
}

template <class SASLImpl>
void defaultSASLAuthenticator<SASLImpl>::setSASLMechanism(
    std::shared_ptr<SASLMechanism<SASLImpl>> mech)
{
	m_saslMech = mech;
}
template <class SASLImpl>
shared_ptr<SASLMechanism<SASLImpl>>
defaultSASLAuthenticator<SASLImpl>::getSASLMechanism() const
{
	return m_saslMech;
}

template class VMIME_EXPORT defaultSASLAuthenticator<SASLImplementation>;

} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT
