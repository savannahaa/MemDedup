#pragma once

#include "field.h"

#include <cstdint>

namespace memdedup {

struct Bucket {
    FieldElement cnt = 0;
    FieldElement sumCipher = 0;
    FieldElement sumTag = 0;

    bool isZero() const;
    void add(const Bucket &other);
    void sub(const Bucket &other);
};

} // namespace memdedup
