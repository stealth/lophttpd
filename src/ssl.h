/*
 * Copyright (C) 2008-2018 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lophttpd_ssl_h
#define lophttpd_ssl_h

#include <map>
#include <string>

#ifdef USE_SSL
extern "C" {
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
}


#endif


// encapsulating the SSL_CTXs for use with SNI's, for easier handling
// with the callbacks and inside the main loop

class ssl_container {

private:

#ifdef USE_SSL

	friend int sni_handler(SSL *ssl, int *ad, void *arg);

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *ssl_method;
#else
	SSL_METHOD *ssl_method;
#endif

	std::map<std::string, SSL_CTX *> host2ctx;
#endif

	std::string err;

public:

	ssl_container()
		: err("")
	{
	}

	~ssl_container()
	{
	}

	const char *why()
	{
		return err.c_str();
	}

	int init(const std::map<std::string, std::string> &, const std::map<std::string, std::string> &);

#ifdef USE_SSL
	SSL_CTX *find_ctx(const std::string &);

	void clear();
#endif


};

#endif

