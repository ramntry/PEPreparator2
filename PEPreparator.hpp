#pragma once
#include <iostream>
#include <vector>

class PEPreparator
{
private:
    typedef unsigned char Byte;
    typedef unsigned short Word;
    typedef unsigned int Dword;

    bool loadDOSHeader();
    bool checkDOSHeader();
    int findPEOffset();
    bool loadDOSStub();

    std::ostream &error();
    std::ostream &note();
    std::ostream &warning();

#pragma pack (push, 1)
    class DOSHeader
    {
    public:
        static const int size = 64;

    private:
        Byte mMagicNumber[2];
        Byte mDummy[size - sizeof(mMagicNumber) - sizeof(Dword)];

    public:
        DOSHeader();
        bool magicNumberIsCorrect() const;

        Dword peOffset;
    };

    class DOSStub
    {
    public:
        std::vector<char> raw;
    };
#pragma pack (pop)

    class DOSStub;
    class PEHeader;
    class Image;

    std::istream &mFile;
    std::ostream &mLog;
    size_t mRawSize;

    DOSHeader mDOSHeader;
    DOSStub mDOSStub;

public:
    PEPreparator(std::istream &file, std::ostream &log = std::clog);
    bool prepare();
};

