#include <bcrypt.hpp>
#include <iostream>
#include <assert.h>

namespace bcrypt
{
	std::string hash(std::string input, int salt)
	{
		std::string new_salt = gen_salt(salt);
		return _hash(input, new_salt);
	}

	std::string gen_salt(int rounds)
	{
		if (rounds < 4)
			rounds = 4;
		else if (rounds > 31)
			rounds = 31;

		std::vector<std::string> salt = {};
		std::string salt_str = "";

		salt.push_back("$2a$");
		if (rounds < 10)
			salt.push_back(0);
		salt.push_back(std::to_string(rounds));
		salt.push_back("$");
		salt.push_back(encode_base64(random(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN));

		for (int i = 0; i < (int)salt.size(); i++)
		{
			salt_str += salt[i];
		}

		return salt_str;
	}

	std::vector<uint32_t> random(int len)
	{
		std::vector<uint32_t> arr;

		for (int i = 0; i < len; i++)
		{
			uint32_t val = (uint32_t)rand();
			arr.push_back(val);
		}
		return arr;
	}

	std::string _hash(std::string s, std::string salt)
	{
		char minor;
		int offset;

		if (salt[0] != '$' || salt[1] != '2')
			throw "Invalid salt version :: " + salt.substr(0, 2);

		if (salt[2] == '$')
		{
			minor = (char)0; // character with ascii code 0 -> \x00
			offset = 3;
		}
		else
		{
			minor = salt[2];
			if ((minor != 'a' && minor != 'b' && minor != 'y') || salt[3] != '$')
				throw "Invalid salt revision :: " + salt.substr(2, 4);
			offset = 4;
		}

		// Extract number of rounds
		if (salt[offset + 2] > '$')
			throw "Missing salt round";

		int r1 = std::stoi(salt.substr(offset, offset + 1), 0, 10) * 10,
			r2 = std::stoi(salt.substr(offset + 1, offset + 2), 0, 10),
			rounds = r1 + r2;
		std::string real_salt = salt.substr(offset + 3, offset + 25);
		s += minor >= 'a' ? "\x00" : "";

		std::vector<int> passwordb = string_to_bytes(s);
		std::string saltb = decode_base64(real_salt, BCRYPT_SALT_LEN);

		std::vector<int> bytes = _crypt(passwordb, saltb, rounds);
		std::vector<std::string> res = {};
		res.push_back("$2");
		if (minor >= 'a')
			res.push_back(std::to_string(minor));
		res.push_back("$");
		if (rounds < 10)
			res.push_back("0");
		res.push_back(std::to_string(rounds));
		res.push_back("$");
		res.push_back(encode_base64(saltb, saltb.size()));
		res.push_back(encode_base64(bytes, C_ORIG.size() * 4 - 1));

		std::string retval = "";
		for (int i = 0; i < (int)res.size(); i++)
			retval += res[i];

		return retval;
	}

	std::vector<int> _crypt(std::vector<int> password, std::string salt, int rounds)
	{
		std::vector<int> cdata = C_ORIG;
		int clen = cdata.size();

		// Validate
		if (rounds < 4 || rounds > 31)
			throw "Illegal number of rounds (4-31) :: " + std::to_string(rounds);

		if (salt.size() != BCRYPT_SALT_LEN)
			throw "Illegal salt length :: " + std::to_string(salt.size()) + " != " + std::to_string(BCRYPT_SALT_LEN);

		rounds = (1 << rounds) >> 0;

		int i = 0, j;
		std::vector<uint32_t> P(P_ORIG);
		std::vector<uint32_t> S(S_ORIG);

		_ekskey(salt, password, P, S);

		if (i < rounds)
		{
			int start = date_now_ms();
			for (; i < rounds;)
			{
				i = i + 1;
				_key(password, P, S);
				_key(salt, P, S);
				if ((date_now_ms() - start) > MAX_EXECUTION_TIME)
					break;
			}
		}
		else
		{
			for (i = 0; i < 64; i++)
				for (j = 0; j < (clen >> 1); j++)
					_encipher(cdata, j << 1, P, S);
			std::vector<int> ret;
			for (i = 0; i < clen; i++)
			{
				ret.push_back(((cdata[i] >> 24) & 0xff) >> 0);
				ret.push_back(((cdata[i] >> 16) & 0xff) >> 0);
				ret.push_back(((cdata[i] >> 8) & 0xff) >> 0);
				ret.push_back((cdata[i] & 0xff) >> 0);
			}
			return ret;
		}
		return {};
	}

	void _key(std::vector<int> key, std::vector<uint32_t> P, std::vector<uint32_t> S)
	{
		int offset = 0;
		std::vector<int> lr = {0, 0};
		int plen = P.size();
		int slen = S.size();
		WordStr sw;
		for (int i = 0; i < plen; i++)
			sw = _streamtoword(key, offset),
			offset = sw.offp,
			P[i] = P[i] ^ sw.key;
		for (int i = 0; i < plen; i += 2)
			lr = _encipher(lr, 0, P, S),
			P[i] = lr[0],
			P[i + 1] = lr[1];
		for (int i = 0; i < slen; i += 2)
			lr = _encipher(lr, 0, P, S),
			S[i] = lr[0],
			S[i + 1] = lr[1];
	}

	void _key(std::string key, std::vector<uint32_t> P, std::vector<uint32_t> S)
	{
		int offset = 0;
		std::vector<int> lr = {0, 0};
		int plen = P.size();
		int slen = S.size();
		WordStr sw;
		for (int i = 0; i < plen; i++)
			sw = _streamtoword(key, offset),
			offset = sw.offp,
			P[i] = P[i] ^ sw.key;
		for (int i = 0; i < plen; i += 2)
			lr = _encipher(lr, 0, P, S),
			P[i] = lr[0],
			P[i + 1] = lr[1];
		for (int i = 0; i < slen; i += 2)
			lr = _encipher(lr, 0, P, S),
			S[i] = lr[0],
			S[i + 1] = lr[1];
	}

	void _ekskey(std::string data, std::vector<int> key, std::vector<uint32_t> P, std::vector<uint32_t> S)
	{
		int offp = 0;
		std::vector<int> lr = {0, 0};
		int plen = P.size();
		int slen = S.size();
		WordStr sw;

		for (int i = 0; i < plen; i++)
		{
			sw = _streamtoword(key, offp);
			offp = sw.offp;
			P[i] = P[i] ^ sw.key;
		}

		offp = 0;

		for (int i = 0; i < plen; i++)
		{
			sw = _streamtoword(data, offp);
			offp = sw.offp;
			lr[0] ^= sw.key;
			sw = _streamtoword(data, offp);
			offp = sw.offp;
			lr[1] ^= sw.key;
			lr = _encipher(lr, 0, P, S);
			P[i] = lr[0];
			P[i + 1] = lr[1];
		}

		for (int i = 0; i < slen; i += 2)
		{
			sw = _streamtoword(data, offp);
			offp = sw.offp;
			lr[0] ^= sw.key,
				sw = _streamtoword(data, offp),
				offp = sw.offp,
				lr[1] ^= sw.key,
				lr = _encipher(lr, 0, P, S),
				S[i] = lr[0],
				S[i + 1] = lr[1];
		}
	}

	std::vector<int> _encipher(std::vector<int> lr, int off, std::vector<uint32_t> P, std::vector<uint32_t> S)
	{
		int n;
		int l = lr[off];
		int r = lr[off + 1];

		l ^= P[0];

		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[1];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[2];
		// Iteration 1
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[3];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[4];
		// Iteration 2
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[5];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[6];
		// Iteration 3
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[7];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[8];
		// Iteration 4
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[9];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[10];
		// Iteration 5
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[11];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[12];
		// Iteration 6
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[13];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[14];
		// Iteration 7
		n = S[l >> 24];
		n += S[0x100 | ((l >> 16) & 0xff)];
		n ^= S[0x200 | ((l >> 8) & 0xff)];
		n += S[0x300 | (l & 0xff)];
		r ^= n ^ P[15];
		n = S[r >> 24];
		n += S[0x100 | ((r >> 16) & 0xff)];
		n ^= S[0x200 | ((r >> 8) & 0xff)];
		n += S[0x300 | (r & 0xff)];
		l ^= n ^ P[16];

		lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
		lr[off + 1] = l;
		return lr;
	}

	WordStr _streamtoword(std::string data, int offp)
	{
		WordStr word_str;
		int i = 0;
		int word = 0;
		for (; i < 4; ++i)
			word = (word << 8) | (data[offp] & 0xff),
			offp = (offp + 1) % data.size();
		word_str.key = word;
		word_str.offp = offp;
		return word_str;
	}

	WordStr _streamtoword(std::vector<int> data, int offp)
	{
		WordStr word_str;
		int i = 0;
		int word = 0;
		for (; i < 4; ++i)
			word = (word << 8) | (data[offp] & 0xff),
			offp = (offp + 1) % data.size();
		word_str.key = word;
		word_str.offp = offp;
		return word_str;
	}

	std::vector<int> string_to_bytes(std::string s)
	{
		int offset = 0;
		char c1, c2;

		std::vector<int> buffer(0, s.size());
		for (int i = 0, k = s.size(); i < k; ++i)
		{
			c1 = (char)i;
			if ((int)c1 < 128)
			{
				buffer[offset++] = c1;
			}
			else if ((int)c1 < 2048)
			{
				buffer[offset++] = (c1 >> 6) | 192;
				buffer[offset++] = (c1 & 63) | 128;
			}
			else if (
				(c1 & 0xFC00) == 0xD800 &&
				((c2 = (char)i + 1) & 0xFC00) == 0xDC00)
			{
				c1 = 0x10000 + ((c1 & 0x03FF) << 10) + (c2 & 0x03FF);
				++i;
				buffer[offset++] = (c1 >> 18) | 240;
				buffer[offset++] = (c1 >> 12 & 63) | 128;
				buffer[offset++] = (c1 >> 6 & 63) | 128;
				buffer[offset++] = (c1 & 63) | 128;
			}
			else
			{
				buffer[offset++] = (c1 >> 12) | 224;
				buffer[offset++] = (c1 >> 6 & 63) | 128;
				buffer[offset++] = (c1 & 63) | 128;
			}
		}
		return buffer;
	}

	std::string encode_base64(std::vector<uint32_t> b, int len)
	{
		std::string retval = "";
		std::vector<char> rs;
		int off = 0;
		int c1, c2;

		if (len <= 0 || len > (int)b.size())
			throw std::length_error("Illegal len :: " + std::to_string(len));

		while (off < len)
		{
			c1 = b[off++] & 0xff;
			rs.push_back(BASE64_CODE[(c1 >> 2) & 0x3f]);
			c1 = (c1 & 0x03) << 4;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 4) & 0x0f;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			c1 = (c2 & 0x0f) << 2;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 6) & 0x03;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			rs.push_back(BASE64_CODE[c2 & 0x3f]);
		}

		for (int i = 0; i < (int)rs.size(); i++)
			retval += std::to_string(rs.at(i));

		std::cout << "retval :: " << retval << "\n";

		return retval;
	}
	std::string encode_base64(std::string b, int len)
	{
		std::string retval = "";
		std::vector<char> rs;
		int off = 0;
		int c1, c2;

		if (len <= 0 || len > (int)b.size())
			throw std::length_error("Illegal len :: " + std::to_string(len));

		while (off < len)
		{
			c1 = b[off++] & 0xff;
			rs.push_back(BASE64_CODE[(c1 >> 2) & 0x3f]);
			c1 = (c1 & 0x03) << 4;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 4) & 0x0f;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			c1 = (c2 & 0x0f) << 2;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 6) & 0x03;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			rs.push_back(BASE64_CODE[c2 & 0x3f]);
		}

		for (int i = 0; i < (int)rs.size(); i++)
			retval += std::to_string(rs.at(i));

		std::cout << "retval :: " << retval << "\n";

		return retval;
	}

	std::string encode_base64(std::vector<int> b, int len)
	{
		std::string retval = "";
		std::vector<char> rs;
		int off = 0;
		int c1, c2;

		if (len <= 0 || len > (int)b.size())
			throw std::length_error("Illegal len :: " + std::to_string(len));

		while (off < len)
		{
			c1 = b[off++] & 0xff;
			rs.push_back(BASE64_CODE[(c1 >> 2) & 0x3f]);
			c1 = (c1 & 0x03) << 4;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 4) & 0x0f;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			c1 = (c2 & 0x0f) << 2;
			if (off >= len)
			{
				rs.push_back(BASE64_CODE[c1 & 0x3f]);
				break;
			}
			c2 = b[off++] & 0xff;
			c1 |= (c2 >> 6) & 0x03;
			rs.push_back(BASE64_CODE[c1 & 0x3f]);
			rs.push_back(BASE64_CODE[c2 & 0x3f]);
		}

		for (int i = 0; i < (int)rs.size(); i++)
			retval += std::to_string(rs.at(i));

		std::cout << "retval :: " << retval << "\n";

		return retval;
	}

	uint64_t date_now_ms()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}

	std::string decode_base64(std::string s, int len)
	{
		return "";
	}

	std::string get_salt(std::string hash)
	{
		return "";
	}

	bool compare(std::string input, std::string hash)
	{
		return true;
	}

}