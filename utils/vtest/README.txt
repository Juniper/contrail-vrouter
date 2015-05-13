The xml file specification
-------------------------

<?xml version="1.0"?>
<test>
    <test_name>Interface test</test_name>
    <message>
        <vif>
            <m_op>Add</m_op>
            <vif_type>Virtual</vif_type>
            <vif_index>4</vif_index>
            <vif_vrf>0</vif_vrf>
            <vif_mac>00:01:02:03:04:05</vif_mac>
            <vif_mtu>1514</vif_mtu>
        </vif>
        <message_return>0</message_return>
    </message>

    <test_result>
        <message>
            <vif>
                <m_op>Get</m_op>
                <vif_index>4</vif_index>
            </vif>
        </message>
        <message_return>0</message_return>
        <message_expect>
            <vif>
                <vif_type>Virtual</vif_type>
                <vif_index>4</vif_index>
                <vif_vrf>0</vif_vrf>
                <vif_mac>00:01:02:03:04:05</vif_mac>
                <vif_mtu>1514</vif_mtu>
            </vif>
        </message_expect>
    </test_result>

</test>

The generated code from sandesh file processing
-----------------------------------------------

....

void *
vr_nexthop_req_node(xmlNodePtr node, struct vtest *test)
{
    unsigned int list_size;
    vr_nexthop_req *req;

    req = calloc(sizeof(*req), 1);
    if (!req)
        return NULL;

    node = node->xmlChildrenNode;
    while (node) {
        if (!node->content || !strlen(node->content)) {
            return NULL;
        }

        if (!strncmp(node->name, "h_op", strlen(node->content))) {
            req->h_op = vt_gen_op(node->content);
        } else if (!strncmp(node->name, "nhr_type", strlen(node->content))) {
            req->nhr_type = strtoul(node->content, NULL, 0);
        } else if (!strncmp(node->name, "nhr_family", strlen(node->content))) {

....

        } else if (!strncmp(node->name, "nhr_label_list", strlen(node->content))) {
            req->nhr_label_list = vt_gen_list(node->content, GEN_TYPE_U32, &list_size);
            req->nhr_label_list_size = list_size;
        }
        node = node->next;
    }

    return (void *)req;
}

