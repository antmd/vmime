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

#include "builtinSASLMechanism.hpp"
#include "SASLSession.hpp"


namespace vmime {
namespace security {
namespace sasl {
namespace detail {
        
template<typename SASLImpl>
builtinSASLMechanism<SASLImpl>::builtinSASLMechanism(shared_ptr<SASLContext<SASLImpl>> ctx, const string& name)
	: m_context(ctx), m_name(name)
{
}
                                
template<typename SASLImpl>
const string
builtinSASLMechanism<SASLImpl>::getName() const
{
        return m_name;
}

template<typename SASLImpl>
bool builtinSASLMechanism<SASLImpl>::step(shared_ptr<SASLSession<SASLImpl>> sess,
                                          const byte_t* challenge, const size_t challengeLen,
                                          byte_t** response, size_t* responseLen)
{
        return sess->stepImpl(sess,challenge,challengeLen,response,responseLen);
}

template<typename SASLImpl>
bool
builtinSASLMechanism<SASLImpl>::isComplete(shared_ptr<SASLSession<SASLImpl>> sess) const
{
        return sess->isCompleteImpl();
}

template<typename SASLImpl>
bool builtinSASLMechanism<SASLImpl>::hasInitialResponse() const
{
        return false;
}

template<typename SASLImpl>
void builtinSASLMechanism<SASLImpl>::encode(shared_ptr<SASLSession<SASLImpl>> sess,
            const byte_t* input, const size_t inputLen,
            byte_t** output, size_t* outputLen)
{
        sess->encodeImpl(sess,input, inputLen,output, outputLen);
}

template<typename SASLImpl>
void builtinSASLMechanism<SASLImpl>::decode(shared_ptr<SASLSession<SASLImpl>> sess,
            const byte_t* input, const size_t inputLen,
            byte_t** output, size_t* outputLen)
{
        sess->decodeImpl(sess, input, inputLen, output, outputLen );
}
        
template class builtinSASLMechanism<SASLImplementation>;
                        
} // detail
} // sasl
} // security
} // vmime

