#include "bucket.h"

namespace memdedup {

bool Bucket::isZero() const { return cnt == 0 && sumCipher == 0 && sumTag == 0; }

void Bucket::add(const Bucket &other) {
    cnt = Field::add(cnt, other.cnt);
    sumCipher = Field::add(sumCipher, other.sumCipher);
    sumTag = Field::add(sumTag, other.sumTag);
}

void Bucket::sub(const Bucket &other) {
    cnt = Field::sub(cnt, other.cnt);
    sumCipher = Field::sub(sumCipher, other.sumCipher);
    sumTag = Field::sub(sumTag, other.sumTag);
}

} // namespace memdedup
