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

#ifndef VMIME_SECURITY_SASL_BUILTINSASLMECHANISM_HPP_INCLUDED
#define VMIME_SECURITY_SASL_BUILTINSASLMECHANISM_HPP_INCLUDED


#include "vmime/config.hpp"


#if VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT


#include "vmime/security/sasl/SASLMechanism.hpp"


namespace vmime {
namespace security {
namespace sasl {
namespace detail {
				
				
template <class SASLImpl> class SASLContext;
template <class SASLImpl> class SASLSession;


/** A built-in authentication mechanism that relies on
 * the GNU SASL library.
 */
template <class SASLImpl>
class VMIME_EXPORT builtinSASLMechanism : public SASLMechanism<SASLImpl>
{
public:
	
	builtinSASLMechanism(shared_ptr <SASLContext<SASLImpl>> ctx, const string& name);
	~builtinSASLMechanism(){;}
	
	
	const string getName() const override;
	
	bool step(shared_ptr <SASLSession<SASLImpl>> sess,
		  const byte_t* challenge, const size_t challengeLen,
		  byte_t** response, size_t* responseLen) override;
	
	bool isComplete(shared_ptr<SASLSession<SASLImpl>> sess) const override;
	
	bool hasInitialResponse() const override;
	
	void encode(shared_ptr <SASLSession<SASLImpl>> sess,
		    const byte_t* input, const size_t inputLen,
		    byte_t** output, size_t* outputLen) override;
	
	void decode(shared_ptr <SASLSession<SASLImpl>> sess,
		    const byte_t* input, const size_t inputLen,
		    byte_t** output, size_t* outputLen) override;
	
private:
	
	/** SASL context */
	shared_ptr <SASLContext<SASLImpl>> m_context;

	/** Mechanism name */
	const string m_name;
	
};
	
extern template class builtinSASLMechanism<SASLImplementation>;
	
} // detail

using builtinSASLMechanism = detail::builtinSASLMechanism<SASLImplementation>;

} // sasl
} // security
} // vmime


#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT

#endif // VMIME_SECURITY_SASL_BUILTINSASLMECHANISM_HPP_INCLUDED

