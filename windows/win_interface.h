#include <vr_interface.h>

struct vr_interface *GetVrInterfaceByGuid(GUID if_guid);
struct vr_interface *GetVrInterfaceByPortAndNic(NDIS_SWITCH_PORT_ID vifPort, NDIS_SWITCH_NIC_INDEX vifNic);
