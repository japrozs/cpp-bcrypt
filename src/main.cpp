#include <iostream>
#include <bcrypt.hpp>

int main()
{
	std::string hash = bcrypt::hash("japroz", 10);
	std::cout << hash << "\n";

	return 0;
}