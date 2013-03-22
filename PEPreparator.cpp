#include <cassert>
#include <cstring>
#include <algorithm>

#include "PEPreparator.hpp"

PEPreparator::PEPreparator(std::istream &file, std::ostream &log)
    : mFile(file)
    , mLog(log)
{
    mFile.seekg(0, std::ios_base::end);
    mRawSize = mFile.tellg();
}

PEPreparator::DOSHeader::DOSHeader()
{
    assert(sizeof(*this) == size);
    std::memset(this, 0, size);
}

PEPreparator::PEHeader::PEHeader()
{
    assert(sizeof(*this) == size());
    std::memset(this, 0, size());
}

PEPreparator::SectionHeader::SectionHeader()
{
    assert(sizeof(*this) == size);
    std::memset(this, 0, size);
}

int PEPreparator::PEHeader::size() const
{
    return mMagicNumberSize + fst.size + snd.size;
}

bool PEPreparator::DOSHeader::magicNumberIsCorrect() const
{
    assert(mMagicNumberSize == sizeof(mMagicNumber));
    assert(mMagicNumberSize == 2);

    return mMagicNumber[0] == 'M'
        && mMagicNumber[1] == 'Z';
}

bool PEPreparator::PEHeader::magicNumberIsCorrect() const
{
    assert(mMagicNumberSize == sizeof(mMagicNumber));
    assert(mMagicNumberSize == 4);

    return mMagicNumber[0] == 'P'
        && mMagicNumber[1] == 'E'
        && mMagicNumber[2] == '\0'
        && mMagicNumber[3] == '\0';
}

bool PEPreparator::loadFromFile(int pos, int size, char *dst, std::string const &name)
{
    mFile.clear();
    mFile.seekg(pos);
    mFile.read(dst, size);
    if (mFile.gcount() != size) {
        error() << "Couldn't load " << name << ": only " << mFile.gcount() << " of " << size
            << " bytes was loaded" << std::endl;
        return false;
    }
    return true;
}

bool PEPreparator::loadDOSHeader()
{
    return loadFromFile(0, mDOSHeader.size, reinterpret_cast<char *>(&mDOSHeader), "the DOS header");
}

bool PEPreparator::loadPEHeader()
{
    if (static_cast<int>(mDOSHeader.peOffset) < mDOSHeader.size) {
        warning() << "Loading PE header with offset lower than standard DOS header size (" << mDOSHeader.size
            << ")" << std::endl;
    }
    return loadFromFile(mDOSHeader.peOffset, mPEHeader.size(), reinterpret_cast<char *>(&mPEHeader)
        , "the PE header");
}

void PEPreparator::Image::setNumofSections(int numofSections)
{
    mSectionHeaders.resize(numofSections);
    mSections.resize(numofSections);
}

int PEPreparator::Image::sectionHeadersSizeInBytes() const
{
    return mSectionHeaders.size() * SectionHeader::size;
}

char *PEPreparator::Image::rawSectionHeaders()
{
    return reinterpret_cast<char *>(&mSectionHeaders[0]);
}

PEPreparator::Image::Section &PEPreparator::Image::sectionAt(int index)
{
    return mSections.at(index);
}

int PEPreparator::Image::rawOffsetOfSectionAt(int index) const
{
    return mSectionHeaders.at(index).pointerToRawData;
}

void PEPreparator::Image::initSectionSizes()
{
    assert(mSections.size() == mSectionHeaders.size());
    assert(mSections.size() != 0);

    for (size_t i = 0; i < mSections.size(); ++i) {
        mSections[i].resize(mSectionHeaders[i].virtualSize, 0);
    }
}

std::string PEPreparator::Image::nameOfSectionAt(int index) const
{
    return std::string(&mSectionHeaders.at(index).name[0], SectionHeader::nameSize);
}

bool PEPreparator::loadImage()
{
    mImage.setNumofSections(mPEHeader.fst.numofSections);
    int sectionHeadersOffset = mDOSHeader.peOffset + mPEHeader.size();
    note() << "Section headers offset is " << sectionHeadersOffset << std::endl;

    if (!loadFromFile(sectionHeadersOffset, mImage.sectionHeadersSizeInBytes(), mImage.rawSectionHeaders()
            , "section headers")) {
        return false;
    }
    mImage.initSectionSizes();

    for (int i = 0; i < mPEHeader.fst.numofSections; ++i) {
        if (!loadFromFile(mImage.rawOffsetOfSectionAt(i), mImage.sectionAt(i).size(), &mImage.sectionAt(i)[0]
                , "a section")) {
            return false;
        }
        note() << "Section " << mImage.nameOfSectionAt(i) << " is loaded (" << mImage.sectionAt(i).size()
            << " bytes)" << std::endl;
    }
    return true;
}

bool PEPreparator::checkDOSHeader()
{
    if (!mDOSHeader.magicNumberIsCorrect()) {
        warning() << "MZ magic number isn't present" << std::endl;
    }
    if (mDOSHeader.peOffset >= mRawSize) {
        warning() << "PE offset presented in DOS header (" << mDOSHeader.peOffset
            << ") is greater (or equal) then file size" << std::endl;
    }
    return true;
}

bool PEPreparator::checkPEHeader()
{
    if (!mPEHeader.magicNumberIsCorrect()) {
        warning() << "PE magic number isn't present" << std::endl;
    }
    if (mPEHeader.fst.sizeofOptionalHeader != mPEHeader.snd.size) {
        warning() << "size of optional NT header presented in NT file header ("
            << mPEHeader.fst.sizeofOptionalHeader << ") is not match with the standard value ("
            << mPEHeader.snd.size << "). Still uses the standard value!" << std::endl;
    }

    size_t entryPointAddress = mPEHeader.snd.imageBase + mPEHeader.snd.entryPointRva;
    note() << "Image base address is 0x" << std::hex << mPEHeader.snd.imageBase << std::endl;
    note() << "Entry point RVA is 0x" << mPEHeader.snd.entryPointRva << " (0x" << entryPointAddress
        << ")" << std::dec << std::endl;

    if (entryPointAddress >= 0x80000000) {
        warning() << "Entry point have too high address" << std::endl;
    }
    note() << "Number of sections: " << mPEHeader.fst.numofSections << std::endl;
    return true;
}

int PEPreparator::findPEOffset()
{
    if (mDOSHeader.peOffset < mRawSize) {
        return mDOSHeader.peOffset;
    }
    warning() << "Try to restore PE offset" << std::endl;
    mFile.clear();
    mFile.seekg(0);
    Dword &result = mDOSHeader.peOffset;
    result = 0;
    while (mFile) {
        if (mFile.get() == 'P' && mFile.get() == 'E') {
            result = static_cast<Dword>(mFile.tellg()) - 2;
            if (result >= static_cast<Dword>(DOSHeader::size)) {
                return result;
            }
        }
    }
    return result;
}

bool PEPreparator::loadDOSStub()
{
    int peOffset = findPEOffset();
    int dosHeaderSize = DOSHeader::size;
    int dosStubOffset = std::min(dosHeaderSize, peOffset);
    int dosStubSize = peOffset - dosStubOffset;
    note() << "PE offset is " << peOffset << ", DOS stub size is " << dosStubSize << std::endl;

    mFile.clear();
    mFile.seekg(dosStubOffset);
    mDOSStub.raw.resize(dosStubSize);
    mFile.read(&mDOSStub.raw[0], dosStubSize);

    if (mFile.gcount() != dosStubSize) {
        error() << "File IO error while reading DOS stub" << std::endl;
        return false;
    }
    return true;
}

std::ostream &PEPreparator::error()
{
    return mLog << "error: ";
}

std::ostream &PEPreparator::warning()
{
    return mLog << "warning: ";
}

std::ostream &PEPreparator::note()
{
    return mLog << "note: ";
}

bool PEPreparator::prepare()
{
    note() << "Loaded file size is " << mRawSize << std::endl;

    return loadDOSHeader()
        && checkDOSHeader()
        && loadDOSStub()
        && loadPEHeader()
        && checkPEHeader()
        && loadImage()
        ;
}

