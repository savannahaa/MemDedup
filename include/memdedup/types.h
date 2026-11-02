#pragma once
#include "field.h"
#include <unordered_set>

namespace memdedup {
using Item = FieldElement;
using RecordSet = std::unordered_set<Item>;
} // namespace memdedup
