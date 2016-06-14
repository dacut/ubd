#pragma once
#include <aws/core/Aws.h>
#include <aws/core/Region.h>

Aws::Region getRegionForName(Aws::String const &name);
