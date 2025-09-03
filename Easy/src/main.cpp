#include <iostream>
#include <string>

int main()
{
    std::string key = "secret123";
    std::string input;
    
    std::cout << "Enter the password: ";
    std::cin >> input;
    
    if (input == key) {
        std::cout << "Correct! You cracked it!\n";
    }
    else {
        std::cout << "Wrong password! Try again.\n";
    }
    
    return 0;
}