#include <iostream>
#include <fstream>
#include <string>

#include <cstdlib>

#include "PEPreparator.hpp"

std::string getFilenameFromArgs(int argc, char **argv)
{
    if (argc < 2) {
        return std::string();
    }
    return std::string(argv[1]);
}

void printUsage(int argc, char **argv)
{
    std::cerr << "Usage: " << argv[0] << " pefile" << std::endl;
}

bool openFile(std::string const &filename, std::ifstream &file)
{
    file.open(filename.c_str(), std::ios_base::binary);
    if (file.is_open()) {
        return true;
    }
    std::cerr << "Couldn't open file " << filename << std::endl;
    return false;
}

int main(int argc, char **argv)
{
    std::string filename = getFilenameFromArgs(argc, argv);
    if (filename.empty()) {
        printUsage(argc, argv);
        return EXIT_FAILURE;
    }

    std::ifstream file;
    if (!openFile(filename, file)) {
        return EXIT_FAILURE;
    }

    PEPreparator pePreparator(file);
    if (!pePreparator.prepare()) {
        return EXIT_FAILURE;
    }
    if (!pePreparator.printExportTable()) {
        return EXIT_FAILURE;
    }
    std::cout << "ok" << std::endl;
}
