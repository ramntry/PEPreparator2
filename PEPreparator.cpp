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

bool PEPreparator::DOSHeader::magicNumberIsCorrect() const
{
    return mMagicNumber[0] == 'M'
        && mMagicNumber[1] == 'Z';
}

bool PEPreparator::loadDOSHeader()
{
    mFile.clear();
    mFile.seekg(0);
    mFile.read(reinterpret_cast<char *>(&mDOSHeader), DOSHeader::size);
    if (mFile.gcount() != DOSHeader::size) {
        error() << "Couldn't load the DOS header: only " << mFile.gcount() << " of " << DOSHeader::size
            << " bytes was loaded" << std::endl;
        return false;
    }
    return true;
}

bool PEPreparator::checkDOSHeader()
{
    if (!mDOSHeader.magicNumberIsCorrect()) {
        warning() << "MZ magic number isn't present" << std::endl;
    }
    if (mDOSHeader.peOffset >= mRawSize) {
        warning() << "PE offset presented in DOS header is greater (or equal) then file size" << std::endl;
    }
    return true;
}

int PEPreparator::findPEOffset()
{
    if (mDOSHeader.peOffset < mRawSize) {
        return mDOSHeader.peOffset;
    }
    warning() << "try to restore PE offset" << std::endl;
    mFile.clear();
    mFile.seekg(0);
    int result = 0;
    while (mFile) {
        if (mFile.get() == 'P' && mFile.get() == 'E') {
            result = static_cast<int>(mFile.tellg()) - 2;
            if (result >= DOSHeader::size) {
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
    return loadDOSHeader() && checkDOSHeader();
}

