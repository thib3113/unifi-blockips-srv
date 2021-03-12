export interface ISite {
    _id: string;
    anonymous_id: string;
    name: string;
    desc: string;
    attr_hidden_id: string;
    attr_no_delete: boolean;
    role: string;
    role_hotspot: boolean;
}

export interface IFWRule {
    _id: string;
    ruleset: string;
    rule_index: number;
    name: string;
    enabled: boolean;
    action: string;
    protocol_match_excepted: boolean;
    logging: boolean;
    state_new: boolean;
    state_established: boolean;
    state_invalid: boolean;
    state_related: boolean;
    ipsec: string;
    src_firewallgroup_ids: Array<string>;
    src_mac_address: string;
    dst_firewallgroup_ids: Array<string>;
    dst_address: string;
    src_address: string;
    protocol: string;
    icmp_typename: string;
    src_networkconf_id: string;
    src_networkconf_type: string;
    dst_networkconf_id: string;
    dst_networkconf_type: string;
    site_id: string;
}

export interface IGroup {
    _id: string;
    name: string;
    group_type: string;
    group_members: Array<string>;
    site_id: string;
}
