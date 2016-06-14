#include <exception>
#include <map>
#include <string>
#include "regionmap.hh"

using std::domain_error;
using std::map;
using std::string;

using Aws::Region;
using Aws::String;

namespace {
    class RegionMap {
    public:
        RegionMap();
        map<String, Region> regions;
    };

    RegionMap::RegionMap() {
        regions["us-east-1"] = Region::US_EAST_1;
        regions["us-west-1"] = Region::US_WEST_1;
        regions["us-west-2"] = Region::US_WEST_2;
        regions["eu-west-1"] = Region::EU_WEST_1;
        regions["eu-central-1"] = Region::EU_CENTRAL_1;
        regions["ap-southeast-1"] = Region::AP_SOUTHEAST_1;
        regions["ap-southeast-1"] = Region::AP_SOUTHEAST_2;
        regions["ap-northeast-1"] = Region::AP_NORTHEAST_1;
        regions["ap-northeast-2"] = Region::AP_NORTHEAST_2;
        regions["sa-east-1"] = Region::SA_EAST_1;
        return;
    }
}

Region getRegionForName(String const &name) {
    static RegionMap regionMap;
    auto pos = regionMap.regions.find(name);
    if (pos == regionMap.regions.end()) {
        throw domain_error("Unknown region " + string(name.c_str()));
    }

    return pos->second;
}

