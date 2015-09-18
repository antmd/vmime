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

#ifndef VMIME_SECURITY_SASL_SASLMECHANISMFACTORY_HPP_INCLUDED
#define VMIME_SECURITY_SASL_SASLMECHANISMFACTORY_HPP_INCLUDED

#include "vmime/config.hpp"

#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#include "vmime/security/sasl/builtinSASLMechanism.hpp"

#include "vmime/types.hpp"
#include "vmime/base.hpp"
#include "vmime/exception.hpp"

#include "vmime/security/sasl/SASLMechanism.hpp"
#include "vmime/utility/stringUtils.hpp"

#include <map>
#include <iostream>

namespace vmime {
namespace security {
namespace sasl {
namespace detail {

template <class SASLImpl> class SASLContext;

/** Constructs SASL mechanism objects.
 */
template <class SASLImpl>
class SASLMechanismFactory : public SASLImpl
{
  private:
	friend class SASL_POLICY;

  public:
	SASLMechanismFactory() { ; }
	~SASLMechanismFactory() { ; }

	using MechFactoryFn = std::function<shared_ptr<SASLMechanism<SASLImpl>>(
	    shared_ptr<SASLContext<SASLImpl>> ctx, const string &name)>;
	using MapType = std::map<string, MechFactoryFn>;

	static SASLMechanismFactory *getInstance();

	/** Register a mechanism into this factory, so that subsequent
	 * calls to create return a valid object for this mechanism.
	 *
	 * @param name mechanism name
	 */
	template <typename MECH_CLASS> void registerMechanism(const string &name);

	/** Create a mechanism object given its name.
	 *
	 * @param ctx SASL context
	 * @param name mechanism name
	 * @return a new mechanism object
	 * @throw exceptions::no_such_mechanism if no mechanism is
	 * registered for the specified name
	 */
	std::shared_ptr<SASLMechanism<SASLImpl>> create(shared_ptr<SASLContext<SASLImpl>> ctx, const string &name_);

	/** Return a list of supported mechanisms. This includes mechanisms
	 * registered using registerMechanism() as well as the ones that
	 * are built-in.
	 *
	 * @return list of supported mechanisms
	 */

	const std::vector<string> getSupportedMechanisms(shared_ptr<SASLSession<SASLImpl>> sess) const;

	/** Test whether an authentication mechanism is supported.
	 *
	 * @param name mechanism name
	 * @return true if the specified mechanism is supported,
	 * false otherwise
	 */
	bool isMechanismSupported(const string &name) const;

	bool isBuiltinMechanism(const string &name) const;

  private:
	MapType getMechanismMap();

  private:
	MapType m_mechs;
};

extern template class SASLMechanismFactory<SASLImplementation>;

} // detail

using SASLMechanismFactory = detail::SASLMechanismFactory<SASLImplementation>;

} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#endif // VMIME_SECURITY_SASL_SASLMECHANISMFACTORY_HPP_INCLUDED
