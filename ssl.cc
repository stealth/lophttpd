/*
 * Copyright (C) 2008-2014 Sebastian Krahmer.
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

#include <map>
#include <string>
#include "ssl.h"

#ifdef USE_SSL
extern "C" {
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
}

extern int enable_dh(SSL_CTX *);

#include <unistd.h>

#endif

using namespace std;

#ifdef USE_CIPHERS
string ciphers = USE_CIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!ADH:kDHE:RSA:AES256:SHA256:SHA384:IDEA:@STRENGTH";
#endif


using namespace std;


#ifdef USE_SSL
int sni_handler(SSL *ssl, int *ad, void *arg)
{
	const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

	// If no SNI, the default CTX is already set
	if (!sni)
		return SSL_TLSEXT_ERR_OK;
	string name = sni;
	ssl_container *sslc = reinterpret_cast<ssl_container *>(arg);
	if (!SSL_set_SSL_CTX(ssl, sslc->find_ctx(name)))
		return SSL_TLSEXT_ERR_NOACK;

	return SSL_TLSEXT_ERR_OK;
}

#endif


int ssl_container::init(const map<string, string> &certs, const map<string, string> &keys)
{

#ifdef USE_SSL
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	if ((ssl_method = TLSv1_server_method()) == NULL) {
		err = "ssl_container::init::TLSv1_server_method:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (certs.count("<default>") == 0) {
		err = "ssl_container::init: No default certificate given.";
		return -1;
	}

	string cpath = "", kpath = "", host = "";
	SSL_CTX *ssl_ctx = NULL;
	for (map<string, string>::const_iterator it = certs.begin(); it != certs.end(); ++it) {

		if (keys.count(it->first) == 0) {
			err = "ssl_container::init: Missing keyfile for host '";
			err += it->first;
			err += "'";
			return -1;
		}
		host = it->first;
		cpath = it->second;
		kpath = keys.find(host)->second;

		if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
			err = "ssl_container::init::SSL_CTX_new:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}

		if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cpath.c_str()) != 1) {
			err = "ssl_container::init::SSL_CTX_use_certificate_chain_file:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx, kpath.c_str(), SSL_FILETYPE_PEM) != 1) {
			err = "ssl_container::init::SSL_CTX_use_PrivateKey_file:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}
		if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
			err = "ssl_container::init::SSL_CTX_check_private_key:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}

		if (SSL_CTX_set_session_id_context(ssl_ctx, (const unsigned char *)"lophttpd", 8) != 1) {
			err = "ssl_container::init::SSL_CTX_set_session_id_context:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}

		SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

		// check for DHE and enable it if there are parameters
		string::size_type dhe = ciphers.find("kDHE");
		if (dhe != string::npos) {
			if (enable_dh(ssl_ctx) != 1)
				ciphers.erase(dhe, 4);
		}

		if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers.c_str()) != 1) {
			err = "ssl_container::init::SSL_CTX_set_cipher_list:";
			err += ERR_error_string(ERR_get_error(), NULL);
			err += "(Try default cipher list in Makefile)";
			return -1;
		}

		host2ctx[host] = ssl_ctx;
	}

	SSL_CTX_set_tlsext_servername_callback(host2ctx["<default>"], sni_handler);
	SSL_CTX_set_tlsext_servername_arg(host2ctx["<default>"], this);
#endif
	return 0;
}

#ifdef USE_SSL

SSL_CTX *ssl_container::find_ctx(const string &host)
{
	map<string, SSL_CTX *>::iterator it = host2ctx.find(host);
	if (it != host2ctx.end())
		return it->second;

	// must exist
	return host2ctx["<default>"];
}



void ssl_container::clear()
{
	for (map<string, SSL_CTX *>::iterator it = host2ctx.begin(); it != host2ctx.end(); ++it)
		SSL_CTX_free(it->second);
	host2ctx.clear();
}

#endif

