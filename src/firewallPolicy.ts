export interface FirewallPolicy {
    _id: string;
    action: 'ALLOW' | 'BLOCK' | 'REJECT';
    connection_state_type: ConnectionStateType;
    connection_states: ConnectionState[];
    create_allow_respond: boolean;
    destination: Destination;
    enabled: boolean;
    icmp_typename: ICMPTypename;
    icmp_v6_typename: ICMPTypename;
    index: number;
    ip_version: IPVersion;
    logging: boolean;
    match_ip_sec: boolean;
    match_opposite_protocol: boolean;
    name: string;
    predefined: boolean;
    protocol: Protocol;
    schedule: Schedule;
    source: Source;
    origin_id?: string;
    origin_type?: OriginType;
    match_ip_sec_type?: MatchIPSECType;
    description?: string;
}

export enum ConnectionStateType {
    All = 'ALL',
    Custom = 'CUSTOM',
    RespondOnly = 'RESPOND_ONLY'
}

export enum ConnectionState {
    Established = 'ESTABLISHED',
    Invalid = 'INVALID',
    New = 'NEW',
    Related = 'RELATED'
}

export interface Destination {
    match_opposite_ports: boolean;
    matching_target: ICMPTypename;
    port_matching_type: Type;
    zone_id: string;
    ips?: string[];
    match_opposite_ips?: boolean;
    matching_target_type?: Type;
    port?: string;
    app_ids?: number[];
    ip_group_id?: string;
    port_group_id?: string;
}

export enum ICMPTypename {
    Any = 'ANY',
    App = 'APP',
    IP = 'IP'
}

export enum Type {
    Any = 'ANY',
    Object = 'OBJECT',
    Specific = 'SPECIFIC'
}

export enum IPVersion {
    Both = 'BOTH',
    Ipv4 = 'IPV4',
    Ipv6 = 'IPV6'
}

export enum MatchIPSECType {
    MatchIPSEC = 'MATCH_IP_SEC'
}

export enum OriginType {
    CustomFirewallRule = 'custom_firewall_rule',
    NetworkConfig = 'network_config',
    PortForward = 'port_forward'
}

export enum Protocol {
    All = 'all',
    ICMP = 'icmp',
    Icmpv6 = 'icmpv6',
    TCP = 'tcp',
    TCPUDP = 'tcp_udp',
    UDP = 'udp'
}

export interface Schedule {
    mode: Mode;
    repeat_on_days: any[];
    time_all_day: boolean;
    date_end?: Date;
    date_start?: Date;
    time_range_end?: string;
    time_range_start?: string;
}

export enum Mode {
    Always = 'ALWAYS'
}

export interface Source {
    match_opposite_ports: boolean;
    matching_target: MatchingTarget;
    port_matching_type: Type;
    zone_id: string;
    ips?: string[];
    match_mac?: boolean;
    match_opposite_ips?: boolean;
    matching_target_type?: Type;
    port?: string;
    client_macs?: string[];
    ip_group_id?: string;
    match_opposite_networks?: boolean;
    network_ids?: string[];
}

export enum MatchingTarget {
    Any = 'ANY',
    Client = 'CLIENT',
    IP = 'IP',
    Network = 'NETWORK'
}
