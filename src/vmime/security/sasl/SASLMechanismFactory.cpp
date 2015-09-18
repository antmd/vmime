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

#include "SASLMechanismFactory.hpp"
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

template <class SASLImpl>
SASLMechanismFactory<SASLImpl> *SASLMechanismFactory<SASLImpl>::getInstance()
{
	static SASLMechanismFactory<SASLImpl> s_mechFactory;
	return &s_mechFactory;
}

/** Register a mechanism into this factory, so that subsequent
 * calls to create return a valid object for this mechanism.
 *
 * @param name mechanism name
 */
template <class SASLImpl>
template <typename MECH_CLASS>
void SASLMechanismFactory<SASLImpl>::registerMechanism(const string &name)
{
	m_mechs.emplace(MapType::value_type(
	    name, [](shared_ptr<SASLContext<SASLImpl>> ctx, const string &name)
	    {
		    return new MECH_CLASS(ctx, name);
		}));
}

/** Create a mechanism object given its name.
 *
 * @param ctx SASL context
 * @param name mechanism name
 * @return a new mechanism object
 * @throw exceptions::no_such_mechanism if no mechanism is
 * registered for the specified name
 */
template <class SASLImpl>
std::shared_ptr<SASLMechanism<SASLImpl>>
SASLMechanismFactory<SASLImpl>::create(shared_ptr<SASLContext<SASLImpl>> ctx, const string &name_)
{
	const string name(utility::stringUtils::toUpper(name_));

	// Check for registered mechanisms
	typename MapType::const_iterator it = m_mechs.find(name);

	if (it != m_mechs.end())
	{
		return it->second(ctx, name);
	}

	// Check for built-in mechanisms
	if (isBuiltinMechanism(name))
		return make_shared<builtinSASLMechanism<SASLImpl>>(ctx, name);

	throw exceptions::no_such_mechanism(name);
	return 0;
}

/** Return a list of supported mechanisms. This includes mechanisms
 * registered using registerMechanism() as well as the ones that
 * are built-in.
 *
 * @return list of supported mechanisms
 */
template <class SASLImpl>
const std::vector<string>
SASLMechanismFactory<SASLImpl>::getSupportedMechanisms(shared_ptr<SASLSession<SASLImpl>> sess) const
{
	std::vector<string> list;

	// Registered mechanisms
	for (typename MapType::const_iterator it = m_mechs.begin();
	     it != m_mechs.end(); ++it)
	{
		list.push_back((*it).first);
	}

	const SASLImpl &impl(*this);
	std::vector<string> native_list = impl.getNativeMechanisms(sess);
	std::copy(native_list.begin(), native_list.end(), std::back_inserter(list));

	return list;
}

/** Test whether an authentication mechanism is supported.
 *
 * @param name mechanism name
 * @return true if the specified mechanism is supported,
 * false otherwise
 */
template <class SASLImpl>
bool SASLMechanismFactory<SASLImpl>::isMechanismSupported(
    const string &name) const
{
	const SASLImpl &impl(*this);
	return (isBuiltinMechanism(name) || m_mechs.find(name) != m_mechs.end());
}

template <class SASLImpl>
bool SASLMechanismFactory<SASLImpl>::isBuiltinMechanism(
    const string &name) const
{
	// TODO
	const SASLImpl &impl(*this);
	return impl.isMechanismSupportedImpl(name);
}

template <class SASLImpl>
typename SASLMechanismFactory<SASLImpl>::MapType
SASLMechanismFactory<SASLImpl>::getMechanismMap()
{
	return m_mechs;
}

template class SASLMechanismFactory<SASLImplementation>;
} // detail
} // sasl
} // security
} // vmime

#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT
