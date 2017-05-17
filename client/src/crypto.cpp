#include "crypto.hpp"

#include "../include/cryptopp/aes.h"
#include "../include/cryptopp/hex.h"
#include "../include/cryptopp/modes.h"
#include <stdexcept>

std::string hex_decode(const std::string& hex)
{
	std::string ascii;
	CryptoPP::StringSource ss(hex,true,new CryptoPP::HexDecoder(new CryptoPP::StringSink(ascii)));
	return ascii;
}

aes_t::aes_t(const std::string& key,const std::string& iv):key_m(key),iv_m(iv)
{
	if(key_m.size()!=16&&key_m.size()!=24&&key_m.size()!=32)
		throw std::runtime_error("Valid AES keysizes are 16, 24, and 32 bytes.");
	if(iv_m.size()!=CryptoPP::AES::BLOCKSIZE)
		throw std::runtime_error("AES blocksize is 16 bytes (invalid IV).");
}

std::string aes_t::encrypt(const std::string& plain)
{
	std::string cipher;
	CryptoPP::AES::Encryption encryptor((unsigned char*)key_m.c_str(),key_m.size());
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc(encryptor,(unsigned char*)iv_m.c_str());
	CryptoPP::StreamTransformationFilter filter(cbc,new CryptoPP::StringSink(cipher));
	filter.Put((unsigned char*)plain.c_str(),plain.size());
	filter.MessageEnd();
	return cipher;
}

std::string aes_t::decrypt(const std::string& cipher)
{
	std::string plain;
	CryptoPP::AES::Decryption decryptor((unsigned char*)key_m.c_str(),key_m.size());
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc(decryptor,(unsigned char*)iv_m.c_str());
	CryptoPP::StreamTransformationFilter filter(cbc,new CryptoPP::StringSink(plain));
	filter.Put((unsigned char*)cipher.c_str(),cipher.size());
	filter.MessageEnd();
	return plain;
}

rsa_t::rsa_t(const size_t bits):bits_m(bits)
{
	params_m.GenerateRandomWithKeySize(rng_m,bits);
	private_m=CryptoPP::RSA::PrivateKey(params_m);
	public_m=CryptoPP::RSA::PublicKey(params_m);
}

std::string rsa_t::encrypt(const std::string& plain)
{
	std::string cipher;
	CryptoPP::StringSource(plain,true,new CryptoPP::PK_EncryptorFilter(rng_m,
		CryptoPP::RSAES_OAEP_SHA_Encryptor(params_m),new CryptoPP::StringSink(cipher)));
	return cipher;
}

std::string rsa_t::decrypt(const std::string& cipher)
{
	std::string plain;
	CryptoPP::StringSource(cipher,true,new CryptoPP::PK_DecryptorFilter(rng_m,
		CryptoPP::RSAES_OAEP_SHA_Decryptor(private_m),new CryptoPP::StringSink(plain)));
	return plain;
}

std::string rsa_t::get_public() const
{
	std::string buffer;
	CryptoPP::HexEncoder encoder;
	encoder.Attach(new CryptoPP::StringSink(buffer));
	CryptoPP::RSAES_OAEP_SHA_Encryptor(params_m).GetPublicKey().Save(encoder);
	return buffer;
}

std::string rsa_t::get_private() const
{
	std::string buffer;
	CryptoPP::HexEncoder encoder;
	encoder.Attach(new CryptoPP::StringSink(buffer));
	CryptoPP::RSAES_OAEP_SHA_Decryptor(private_m).GetPrivateKey().Save(encoder);
	return buffer;
}