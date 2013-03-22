#pragma once
#include <iostream>
#include <iterator>
#include <vector>

class PEPreparator
{
public:
    PEPreparator(std::istream &file, std::ostream &log = std::clog);
    bool prepare();
    bool printExportTable();

private:
    typedef unsigned char Byte;
    typedef unsigned short Word;
    typedef unsigned int Dword;
    typedef Dword Rva;

    bool loadFromFile(int pos, int size, char *dst, std::string const &name);
    bool loadFromImage(Rva rva, int size, char *dst, std::string const &name);
    bool loadDirectory(int index, int size, char *dst, std::string const &name);
    bool loadDOSHeader();
    bool checkDOSHeader();
    int findPEOffset();
    bool loadDOSStub();
    bool loadPEHeader();
    bool checkPEHeader();
    bool loadImage();
    bool loadExportDirectory();
    std::string getString(Rva rva);

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
    public:
        static const int size = 224;
        static const int numofDirectories = 16;

        Rva directoryRva(int index) const;

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

    struct ExportDirectory
    {
        static const int size = 40;
        static const int index = 0;

        ExportDirectory();

        Dword characteristics;
        Dword timeDateStamp;
        Word majorVersion;
        Word minorVersion;
        Dword nName;

        Dword ordinalsBase;
        Dword numofFunctions;
        Dword numofNames;
        Rva functionsRva;
        Rva namesRva;
        Rva ordinalsRva;
    };
#pragma pack (pop)

    class Image
    {
    public:
        template <typename T>
        class Iterator : public std::iterator<std::input_iterator_tag, T>
        {
        public:
            Iterator(Image *image, Rva rva) : m(image), r(rva) {}
            T operator *() { m->read(reinterpret_cast<char *>(&buf), r, sizeof(T)); return buf; }
            T *operator ->() { return &(**this); }
            Iterator<T> operator ++() { r += sizeof(T); return *this; }
            Iterator<T> operator ++(int) { Iterator<T> tmp = *this; r += sizeof(T); return tmp; }
            bool operator !=(Iterator<T> const &rhs) const { return rhs.r != r; }
            bool operator ==(Iterator<T> const &rhs) const { return rhs.r == r; }
        private:
            Image *m;
            Rva r;
            T buf;
        };

        typedef std::vector<char> Section;

        void setNumofSections(int numofSections);
        int sectionHeadersSizeInBytes() const;
        char *rawSectionHeaders();
        void initSectionSizes();
        std::string nameOfSectionAt(int index) const;

        Section &sectionAt(int index);
        int rawOffsetOfSectionAt(int index) const;

        int read(char *buf, Rva from, size_t size);
        char at(Rva rva);

        template <typename T>
        Iterator<T> iterator(Rva rva) { return Iterator<T>(this, rva); }
        template <typename T>
        Iterator<T> iterator(Rva rva, int shift) { return Iterator<T>(this, rva + sizeof(T) * shift); }

        void clear() { mAccessError = false; }
        bool error() { return mAccessError; }

    private:
        std::vector<SectionHeader> mSectionHeaders;
        std::vector<Section> mSections;
        bool mAccessError;
    };

    std::istream &mFile;
    std::ostream &mLog;
    size_t mRawSize;

    DOSHeader mDOSHeader;
    DOSStub mDOSStub;
    PEHeader mPEHeader;
    Image mImage;

    ExportDirectory mExportDirectory;
};

