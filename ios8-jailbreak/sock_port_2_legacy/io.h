#ifndef IO_H
#define IO_H

#include "../IOKit/IOKitLib.h"

extern uint32_t kslide32;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    
    kOSSerializeEndCollection   = 0x80000000U,
    
    kOSSerializeMagic           = 0x000000d3U,
};

void spray_OSUnserializeXML(uint8_t *data, size_t size);
int leak_anchor(addr_t* anchor);

#endif
