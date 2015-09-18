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

#ifndef VMIME_SECURITY_SASL_DEFAULTSASLAUTHENTICATOR_HPP_INCLUDED
#define VMIME_SECURITY_SASL_DEFAULTSASLAUTHENTICATOR_HPP_INCLUDED

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "vmime/security/sasl/SASLCommon.hpp"

#include "vmime/security/sasl/SASLAuthenticator.hpp"
#include "vmime/security/defaultAuthenticator.hpp"

#include <memory>

namespace vmime {
namespace security {
namespace sasl {
namespace detail {

/** An authenticator that is capable of providing information
 * for simple authentication mechanisms (username and password).
 */
template <class SASLImpl>
class VMIME_EXPORT defaultSASLAuthenticator : public SASLAuthenticator<SASLImpl>
{
  public:
	defaultSASLAuthenticator() { ; }
	~defaultSASLAuthenticator() { ; }

	virtual const std::vector<std::shared_ptr<SASLMechanism<SASLImpl>>>
	getAcceptableMechanisms(
	    const std::vector<std::shared_ptr<SASLMechanism<SASLImpl>>> &available,
	    std::shared_ptr<SASLMechanism<SASLImpl>> suggested) const;

	const string getUsername() const;
	const string getPassword() const;
	const string getHostname() const;
	const string getAnonymousToken() const;
	const string getServiceName() const;
	const string getAccessToken() const;

	void setSASLSession(std::shared_ptr<SASLSession<SASLImpl>> sess);

	void setService(shared_ptr<net::service> serv);

	void setSASLMechanism(std::shared_ptr<SASLMechanism<SASLImpl>> mech);
	shared_ptr<SASLMechanism<SASLImpl>> getSASLMechanism() const;

  private:
	defaultAuthenticator m_default;

	std::weak_ptr<net::service> m_service;
	std::shared_ptr<SASLMechanism<SASLImpl>> m_saslMech;
	std::weak_ptr<SASLSession<SASLImpl>> m_session;
};

extern template class VMIME_EXPORT defaultSASLAuthenticator<SASLImplementation>;

} // detail

using defaultSASLAuthenticator =
    detail::defaultSASLAuthenticator<SASLImplementation>;
    
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#endif // VMIME_SECURITY_SASL_DEFAULTSASLAUTHENTICATOR_HPP_INCLUDED
