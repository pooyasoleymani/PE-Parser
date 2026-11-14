#include "pe_parser.hpp"
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: peparser <file.exe|file.dll>\n";
        return 2;
    }
    pe::Parser parser(argv[1]);
    if (!parser.parse()) {
        std::cerr << "PE parse error: " << parser.error() << '\n';
        return 1;
    }
    parser.print(std::cout);
    return 0;
}
