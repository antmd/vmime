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

#include "vmime/security/sasl/SASLSocket.hpp"
#include "vmime/security/sasl/SASLSession.hpp"
#include "vmime/security/sasl/SASLMechanism.hpp"

#include "vmime/utility/stringUtils.hpp"

#include "vmime/exception.hpp"

#include <algorithm>
#include <cstring>


namespace vmime {
namespace security {
namespace sasl {
namespace detail {
				
				
	
template <class SASLImpl>
SASLSocket<SASLImpl>::SASLSocket( std::shared_ptr<SASLSession<SASLImpl> > sess, shared_ptr<net::socket> wrapped)
: m_session(sess)
, m_wrapped(wrapped)
, m_pendingBuffer(0)
, m_pendingPos(0)
, m_pendingLen(0)
{
}

template <class SASLImpl>
SASLSocket<SASLImpl>::~SASLSocket()
{
	if (m_pendingBuffer)
		delete [] m_pendingBuffer;
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::connect(const string& address, const port_t port)
{
	m_wrapped->connect(address, port);
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::disconnect()
{
	m_wrapped->disconnect();
}

template <class SASLImpl>
bool SASLSocket<SASLImpl>::isConnected() const
{
	return m_wrapped->isConnected();
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::receive(string& buffer)
{
	const size_t n = receiveRaw(m_recvBuffer, sizeof(m_recvBuffer));
	buffer = utility::stringUtils::makeStringFromBytes(m_recvBuffer, n);
}

template <class SASLImpl>
size_t SASLSocket<SASLImpl>::receiveRaw(byte_t* buffer, const size_t count)
{
	if (m_pendingLen != 0)
	{
		const size_t copyLen =
		(count >= m_pendingLen ? m_pendingLen : count);
		
		std::copy(m_pendingBuffer + m_pendingPos,
			  m_pendingBuffer + m_pendingPos + copyLen,
			  buffer);
		
		m_pendingLen -= copyLen;
		m_pendingPos += copyLen;
		
		if (m_pendingLen == 0)
		{
			delete [] m_pendingBuffer;
			
			m_pendingBuffer = 0;
			m_pendingPos = 0;
			m_pendingLen = 0;
		}
		
		return copyLen;
	}
	
	const size_t n = m_wrapped->receiveRaw(buffer, count);
	
	byte_t* output = 0;
	size_t outputLen = 0;
	
	m_session->getMechanism()->decode
	(m_session, buffer, n, &output, &outputLen);
	
	// If we can not copy all decoded data into the output buffer, put
	// remaining data into a pending buffer for next calls to receive()
	if (outputLen > count)
	{
		std::copy(output, output + count, buffer);
		
		m_pendingBuffer = output;
		m_pendingLen = outputLen;
		m_pendingPos = count;
		
		return count;
	}
	else
	{
		std::copy(output, output + outputLen, buffer);
		
		delete [] output;
		
		return outputLen;
	}
}


template <class SASLImpl>
void SASLSocket<SASLImpl>::send(const string& buffer)
{
	sendRaw(reinterpret_cast <const byte_t*>(buffer.data()), buffer.length());
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::send(const char* str)
{
	sendRaw(reinterpret_cast <const byte_t*>(str), strlen(str));
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::sendRaw(const byte_t* buffer, const size_t count)
{
	byte_t* output = 0;
	size_t outputLen = 0;
	
	m_session->getMechanism()->encode
	(m_session, buffer, count, &output, &outputLen);
	
	try
	{
		m_wrapped->sendRaw(output, outputLen);
	}
	catch (...)
	{
		delete [] output;
		throw;
	}
	
	delete [] output;
}


template <class SASLImpl>
size_t SASLSocket<SASLImpl>::sendRawNonBlocking(const byte_t* buffer, const size_t count)
{
	byte_t* output = 0;
	size_t outputLen = 0;
	
	m_session->getMechanism()->encode
	(m_session, buffer, count, &output, &outputLen);
	
	size_t bytesSent = 0;
	
	try
	{
		bytesSent = m_wrapped->sendRawNonBlocking(output, outputLen);
	}
	catch (...)
	{
		delete [] output;
		throw;
	}
	
	delete [] output;
	
	return bytesSent;
}

template <class SASLImpl>
size_t SASLSocket<SASLImpl>::getBlockSize() const
{
	return m_wrapped->getBlockSize();
}

template <class SASLImpl>
unsigned int SASLSocket<SASLImpl>::getStatus() const
{
	return m_wrapped->getStatus();
}

template <class SASLImpl>
const string SASLSocket<SASLImpl>::getPeerName() const
{
	return m_wrapped->getPeerName();
}
				
template <class SASLImpl>
const string SASLSocket<SASLImpl>::getPeerAddress() const
{
	return m_wrapped->getPeerAddress();
}

template <class SASLImpl>
shared_ptr<net::timeoutHandler> SASLSocket<SASLImpl>::getTimeoutHandler()
{
	return m_wrapped->getTimeoutHandler();
}

template <class SASLImpl>
void SASLSocket<SASLImpl>::setTracer(shared_ptr <net::tracer> tracer)
{
	m_wrapped->setTracer(tracer);
}


template <class SASLImpl>
shared_ptr <net::tracer> SASLSocket<SASLImpl>::getTracer()
{
	return m_wrapped->getTracer();
}

template <class SASLImpl>
bool SASLSocket<SASLImpl>::waitForRead(const int msecs)
{
	return m_wrapped->waitForRead(msecs);
}


template <class SASLImpl>
bool SASLSocket<SASLImpl>::waitForWrite(const int msecs)
{
	return m_wrapped->waitForWrite(msecs);
}

				
template class VMIME_EXPORT SASLSocket<SASLImplementation>;
    
} // detail
} // sasl
} // security
} // vmime



#endif // VMIME_HAVE_MESSAGING_FEATURES && VMIME_HAVE_SASL_SUPPORT


