#pragma once
#include <iostream>
#include <vector>

class PEPreparator
{
private:
    typedef unsigned char Byte;
    typedef unsigned short Word;
    typedef unsigned int Dword;
    typedef Dword Rva;

    bool loadFromFile(int pos, int size, char *dst, std::string const &name);
    bool loadDOSHeader();
    bool checkDOSHeader();
    int findPEOffset();
    bool loadDOSStub();
    bool loadPEHeader();
    bool checkPEHeader();
    bool loadImage();

    std::ostream &error();
    std::ostream &note();
    std::ostream &warning();

#pragma pack (push, 1)
    class DOSHeader
    {
    public:
        static const int size = 64;
    private:
        static const int mMagicNumberSize = 2;

    public:
        DOSHeader();
        bool magicNumberIsCorrect() const;

    private:
        Byte mMagicNumber[mMagicNumberSize];
        Byte mDummy[size - sizeof(mMagicNumber) - sizeof(Dword)];
    public:
        Dword peOffset;
    };
#pragma pack (pop)

    struct DOSStub
    {
        std::vector<char> raw;
    };

#pragma pack (push, 1)
    struct NTFileHeader
    {
        static const int size = 20;

        Word machine;
        Word numofSections;
        Dword timeDateStamp;
        Dword pointerToSymbolTable;
        Dword numofSymbols;
        Word sizeofOptionalHeader;
        Word characteristics;
    };

    struct DirectoryEntry
    {
        Rva rva;
        Dword size;
    };

    struct NTOptionalHeader
    {
        static const int size = 224;
        static const int numofDirectories = 16;

    private:
        Dword dummy[4];
    public:
        Rva entryPointRva;
        Rva baseOfCode;
        Rva baseOfData;
        Rva imageBase;
        Dword sectionAlignment;
        Dword fileAligment;
    private:
        Byte dummy1[size - numofDirectories * sizeof(DirectoryEntry) - 10 * sizeof(Dword)];
    public:
        DirectoryEntry directories[numofDirectories];
    };

    class PEHeader
    {
    public:
        PEHeader();
        bool magicNumberIsCorrect() const;
        int size() const;

    private:
        static const int mMagicNumberSize = 4;

    private:
        Byte mMagicNumber[mMagicNumberSize];
    public:
        NTFileHeader fst;
        NTOptionalHeader snd;
    };

    struct SectionHeader
    {
        static const int size = 40;
        static const int nameSize = 8;

        SectionHeader();

        char name[nameSize];
        Dword virtualSize;
        Rva rva;
        Dword sizeofRawData;
        Dword pointerToRawData;

        Dword pointerToRelocations;
        Dword pointerToLinenumbers;
        Word numofRelocations;
        Word numofLinenumbers;
        Dword characteristics;
    };
#pragma pack (pop)

    class Image
    {
    public:
        typedef std::vector<char> Section;

        void setNumofSections(int numofSections);
        int sectionHeadersSizeInBytes() const;
        char *rawSectionHeaders();
        void initSectionSizes();
        std::string nameOfSectionAt(int index) const;

        Section &sectionAt(int index);
        int rawOffsetOfSectionAt(int index) const;

    private:
        std::vector<SectionHeader> mSectionHeaders;
        std::vector<Section> mSections;
    };

    std::istream &mFile;
    std::ostream &mLog;
    size_t mRawSize;

    DOSHeader mDOSHeader;
    DOSStub mDOSStub;
    PEHeader mPEHeader;
    Image mImage;

public:
    PEPreparator(std::istream &file, std::ostream &log = std::clog);
    bool prepare();
};

